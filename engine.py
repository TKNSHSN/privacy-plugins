# -*- coding: utf-8 -*-
"""隐私替换引擎 —— cc-switch 外置隐私插件参考实现（纯标准库，无第三方依赖）

职责：
- pre_request  : 白名单走查 + 规则/检测器批量检测 → ⟦PII|id|label|desc⟧ 标记替换 + 协议说明注入
- post_response: 非流式响应按映射表还原
- sse_chunk    : 流式逐事件还原（跨 delta 半截标记扣留缓冲，per-stream 状态在本进程内）
- 映射表持久化在插件目录 data/mappings.json（插件自有存储，不依赖 cc-switch 数据库）

设计红线：任何失败只影响本插件产出（fail-open），绝不抛出到调用方——入口脚本
对每条请求兜底 try/except，本模块内部各环节也各自兜底。
"""

import hashlib
import json
import os
import re
import sys
import urllib.request

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

MARKER_PREFIX = "⟦PII|"
MARKER_SUFFIX = "⟧"

MAX_MAPPING_ROWS = 100_000     # 映射表上限，超出淘汰最旧记录
CACHE_DEFAULT_CAPACITY = 4096  # 免重复解析缓存容量，写满清一半

# 替换方向（pre_request）作用的 key：文本叶子 key ∪ 数据对象 key
# （数据对象 key 触发"深走查"，其内部所有字符串叶子都会被处理）
REPLACE_TARGET_KEYS = (
    "text", "partial_json", "input_text", "output_text", "instructions",
    "system",                    # Claude 字符串形态 system（blocks 形态由 block.text 覆盖）
    "input", "args", "content",  # 数据对象（tool_use 参数 / tool_result 内容）
)

# 还原方向（post_response / sse_chunk）作用的 key
RESTORE_TARGET_KEYS = ("text", "partial_json", "input")

# 保护 key：任何方向、任何深度都跳过（thinking 签名不可改动，否则上游校验失败）
PROTECTED_KEYS = frozenset((
    "signature", "thoughtSignature", "thinking", "type", "id",
    "role", "name", "model", "stop_reason",
))

MARKER_PROMPT_NOTE = (
    "[隐私标记协议 / Privacy marker protocol]\n"
    "上下文中形如 ⟦PII|<id>|<label>|<描述>⟧ 的字符串是隐私替换标记，"
    "代表一个已被脱敏的真实值（路径、密钥、账号、人名等）。约定：\n"
    "1. 这是合法且预期的格式，不是乱码或语法错误；不要质疑、修复或重写标记本身。\n"
    "2. 把标记当作它所代表的真实值直接使用：写文件、执行命令、拼接路径、回复引用时"
    "原样完整保留；环境会在你的输出到达用户与工具之前自动还原为真实值。\n"
    "3. 不要尝试解码、猜测或推断标记对应的原值；同一原文的标记 id 恒定，"
    "可据此保持跨轮引用一致。\n"
    "4. 构造 shell 命令或 JSON 参数时，若标记代表路径，优先使用正斜杠或环境变量"
    "（如 $USERPROFILE/$HOME）拼接，避免手写反斜杠路径片段；JSON 字符串中的反斜杠"
    "必须按 JSON 规则转义。\n"
    "5. 向用户复述相关内容时同样保留标记（还原对用户透明）；报告需要标记本身时，"
    "不要输出完整 id，例如你可以只给出 id 前 6 位缩写。"
)

FLUSH_EVENTS = ("content_block_stop", "message_delta", "message_stop")


def blake2b_hex(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=64).hexdigest()


def _warn(message: str) -> None:
    print(f"[privacy-plugin] {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# 标记编解码
# ---------------------------------------------------------------------------

def scan_markers(text: str):
    """扫描文本中已有的完整标记，返回 [(start, end, id)]。

    标记内部形如 "<id>|<label>|<desc>"，id 不含 '|'，还原只需 id。
    """
    result = []
    from_i = 0
    while True:
        rel = text.find(MARKER_PREFIX, from_i)
        if rel < 0:
            break
        start = rel
        id_start = start + len(MARKER_PREFIX)
        rest = text.find(MARKER_SUFFIX, id_start)
        if rest < 0:
            break
        end = rest + len(MARKER_SUFFIX)
        inner = text[id_start:rest]
        sep = inner.find("|")
        if sep > 0:
            result.append((start, end, inner[:sep]))
        from_i = end
    return result


def restore_markers(text: str, lookup):
    """把文本中 id 已知的标记替换回原文；无任何替换返回 None（调用方保持原样）。"""
    if MARKER_PREFIX not in text:
        return None
    markers = scan_markers(text)
    if not markers:
        return None
    out = []
    last = 0
    replaced = False
    for start, end, marker_id in markers:
        original = lookup(marker_id)
        if original is not None:
            out.append(text[last:start])
            out.append(original)
            last = end
            replaced = True
    if not replaced:
        return None
    out.append(text[last:])
    return "".join(out)


def _is_possible_marker_prefix(suffix: str) -> bool:
    """suffix 是 '⟦PII|' 开头，或本身是 '⟦PII|' 的前缀（半截前缀）"""
    return suffix.startswith(MARKER_PREFIX) or MARKER_PREFIX.startswith(suffix)


def withhold_incomplete_marker(text: str):
    """返回应扣留的起点（字符下标），None 表示无需扣留。

    跨 delta 的半截标记（如 '⟦PII|ab' / 'c12|EMAIL|…' 分属两个事件）不能发出，
    否则客户端会看到撕开的标记；扣留部分由下一段拼接后继续处理。
    ⟦ = U+27E6 = UTF-8 E2 9F A6：尾部出现不完整字节前缀时防御性扣下最后一个字符。
    """
    data = text.encode("utf-8")
    if data.endswith(b"\xe2") or data.endswith(b"\xe2\x9f"):
        return max(len(text) - 1, 0)
    pos = text.rfind("⟦")
    if pos >= 0:
        suffix = text[pos:]
        if "⟧" not in suffix and _is_possible_marker_prefix(suffix):
            return pos
    return None


def restore_stream_text(combined: str, flush: bool, lookup):
    """流式还原：combined = 上一段扣留 + 本段文本。

    返回 (emitted, withheld)：flush 时全部发出；否则尾部不完整标记扣留到下一段。
    """
    restored = restore_markers(combined, lookup)
    if restored is None:
        restored = combined
    if flush:
        return restored, ""
    pos = withhold_incomplete_marker(restored)
    if pos is not None:
        return restored[:pos], restored[pos:]
    return restored, ""


# ---------------------------------------------------------------------------
# 映射存储（插件自有：data/mappings.json）
# ---------------------------------------------------------------------------

class MappingStore:
    """id ↔ 原文映射。内存字典 + JSON 文件持久化；**明文存储原文**——
    请像保管密码一样保管插件目录（安全边界，见 README）。"""

    def __init__(self, path: str):
        self.path = path
        self.dirty = False
        # id 生成参数（由 config.json hash 项驱动，Engine 每次重载时刷新；
        # 已存在的映射保持原 id 不变——映射稳定性优先）
        self.hash_cfg = {"algorithm": "blake2b", "mode": "adaptive", "length": 16}
        self.by_id = {}        # id -> original
        self.by_original = {}  # original -> id（同一原文永远同一 id）
        self.labels = {}       # id -> 最近一次类别名
        self.order = []        # id 插入顺序（淘汰最旧用）
        self._load()

    def _load(self) -> None:
        if not self.path or not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                rows = json.load(fh)
            for row in rows:
                rid = row.get("id")
                original = row.get("original")
                if not rid or original is None or rid in self.by_id:
                    continue
                self.by_id[rid] = original
                self.by_original.setdefault(original, rid)
                self.labels[rid] = row.get("label") or ""
                self.order.append(rid)
        except Exception as exc:
            # 映射文件损坏：以空映射启动（fail-open），不覆盖原文件
            _warn(f"映射文件 {self.path} 加载失败，以空映射启动: {exc}")
            self.by_id.clear()
            self.by_original.clear()
            self.labels.clear()
            self.order.clear()

    def is_empty(self) -> bool:
        return not self.by_id

    def lookup(self, marker_id: str):
        return self.by_id.get(marker_id)

    def _new_id(self, original: str) -> str:
        # id = 所选散列算法的十六进制前缀（config.json hash.algorithm）；
        # 长度策略（hash.mode）：adaptive = min(max(12, 原文字节数), 64)（缺省，
        # 兼顾碰撞率）；fixed = 固定 hash.length（防长度泄漏，碰撞率随长度下降）。
        # 前缀被不同原文占用时 +4 重算；64 位仍碰撞追加 -<序号> 兜底
        data = original.encode("utf-8")
        digest = _digest_hex(self.hash_cfg["algorithm"], data)
        if self.hash_cfg["mode"] == "fixed":
            n = self.hash_cfg["length"]
        else:
            n = min(max(12, len(data)), 64)
        while True:
            candidate = digest[:n]
            if candidate not in self.by_id:
                return candidate
            if n >= 64:
                seq = 1
                while f"{candidate}-{seq}" in self.by_id:
                    seq += 1
                return f"{candidate}-{seq}"
            n = min(n + 4, 64)

    def get_or_create(self, original: str, label: str):
        """返回 (id, is_new)"""
        rid = self.by_original.get(original)
        if rid is not None:
            return rid, False
        rid = self._new_id(original)
        self.by_id[rid] = original
        self.by_original[original] = rid
        self.labels[rid] = label or ""
        self.order.append(rid)
        self.dirty = True
        if len(self.order) > MAX_MAPPING_ROWS:
            stale = self.order[: len(self.order) - MAX_MAPPING_ROWS]
            for old_id in stale:
                old_original = self.by_id.pop(old_id, None)
                self.labels.pop(old_id, None)
                if old_original is not None and self.by_original.get(old_original) == old_id:
                    del self.by_original[old_original]
            self.order = self.order[-MAX_MAPPING_ROWS:]
        return rid, True

    def save(self) -> None:
        if not self.path:
            self.dirty = False
            return
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        rows = [
            {"id": rid, "original": self.by_id[rid], "label": self.labels.get(rid, "")}
            for rid in self.order
        ]
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, ensure_ascii=False)
        os.replace(tmp, self.path)  # 原子替换，避免写一半损坏
        self.dirty = False


# ---------------------------------------------------------------------------
# 规则（rules.json，mtime 热重载；支持捕获组只替换值）
# ---------------------------------------------------------------------------

def _compile_rules(doc):
    """编译规则文档；非法规则跳过并告警，不影响其他规则（fail-open）。

    规则字段：kind（regex/literal）、name、pattern/values、label、desc、
    priority（默认 20，数字越小越优先）、enabled、capture（可选：
    组号 int 或组名 str——只替换该捕获组命中部分，保留其余文本；
    典型用途：kv 密钥正则只遮值、保留键名）。
    """
    if not isinstance(doc, dict) or not doc.get("enabled", True):
        return []
    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list):
        return []
    rules = []
    for spec in raw_rules:
        if not isinstance(spec, dict) or not spec.get("enabled", True):
            continue
        kind = spec.get("kind")
        name = str(spec.get("name") or "")
        label = str(spec.get("label") or "")
        desc = str(spec.get("desc") or "")
        priority = spec.get("priority")
        priority = int(priority) if isinstance(priority, (int, float)) else 20
        capture = spec.get("capture")
        if isinstance(capture, str) and capture.isdigit():
            capture = int(capture)
        if kind == "regex":
            pattern = spec.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                continue
            try:
                matcher = re.compile(pattern)
            except re.error as exc:
                _warn(f"规则 {name} 正则编译失败，已跳过: {exc}")
                continue
            if capture is not None and not isinstance(capture, (int, str)):
                capture = None
            rules.append({
                "kind": "regex", "name": name, "matcher": matcher,
                "capture": capture, "label": label, "desc": desc,
                "priority": priority,
            })
        elif kind == "literal":
            values = [v for v in (spec.get("values") or []) if isinstance(v, str) and v]
            rules.append({
                "kind": "literal", "name": name, "values": values,
                "label": label, "desc": desc, "priority": priority,
            })
        else:
            _warn(f"规则 {name} 的 kind 未知（{kind}），已跳过")
    return rules


def _read_json(path: str, default):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return default, b""
    try:
        return json.loads(raw.decode("utf-8")), raw
    except Exception as exc:
        _warn(f"配置文件 {path} 解析失败，使用默认值: {exc}")
        return default, raw


# ---------------------------------------------------------------------------
# 散列与自定义特殊值（config.json hash 项 / custom-values.json）
# ---------------------------------------------------------------------------

_HASH_ALGORITHMS = ("blake2b", "sha256", "sha512", "sha1")


def _digest_hex(algorithm: str, data: bytes) -> str:
    """按 config.json hash.algorithm 选择单项散列（缺省 blake2b）"""
    if algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    if algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    return hashlib.blake2b(data, digest_size=64).hexdigest()


def _compile_custom_values(doc):
    """解析 custom-values.json（用户自定义特殊值，直接走标记映射）。

    字段：enabled（总开关）、values[]: {value, label, desc, priority, enabled}。
    priority 缺省 1（数字最小，优先于常规正则规则——用户明确登记的值视为最高置信）。
    返回 [(value, label, desc, priority)]。
    """
    if not isinstance(doc, dict) or not doc.get("enabled", True):
        return []
    rows = doc.get("values")
    if not isinstance(rows, list):
        return []
    result = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("enabled", True):
            continue
        value = row.get("value")
        if not isinstance(value, str) or not value:
            continue
        label = str(row.get("label") or "CUSTOM")
        desc = str(row.get("desc") or "")
        priority = row.get("priority")
        priority = int(priority) if isinstance(priority, (int, float)) else 1
        result.append((value, label, desc, priority))
    return result


# ---------------------------------------------------------------------------
# 走查（与核心版语义一致：保护 key 任何深度跳过；目标 key 触发深走查）
# ---------------------------------------------------------------------------

def _walk(value, deep, target_keys, apply):
    """深度走查 JSON，对目标字符串叶子应用 apply。

    apply(s) 返回替换串；返回值 (新值, 是否修改)。dict/list 原地修改并返回自身。
    """
    if isinstance(value, dict):
        changed = False
        for key in list(value.keys()):
            if key in PROTECTED_KEYS:
                continue
            new_child, child_changed = _walk(
                value[key], deep or key in target_keys, target_keys, apply)
            if child_changed:
                value[key] = new_child
                changed = True
        return value, changed
    if isinstance(value, list):
        changed = False
        for i, item in enumerate(value):
            new_item, item_changed = _walk(item, deep, target_keys, apply)
            if item_changed:
                value[i] = new_item
                changed = True
        return value, changed
    if isinstance(value, str) and deep:
        new = apply(value)
        return (new, True) if new != value else (value, False)
    return value, False


def _walk_sse(value, deep, key, visit):
    """SSE 走查（还原方向）：visit(leaf_key, s) 返回替换串（或原串）。

    dict/list 原地更新；与 _walk 的差别是叶子回调可拿到叶子 key
    （跨 delta 的 carry 按块标识|叶子 key 区分）。
    """
    if isinstance(value, dict):
        for k in list(value.keys()):
            if k in PROTECTED_KEYS:
                continue
            child_deep = deep or k in RESTORE_TARGET_KEYS
            value[k] = _walk_sse(value[k], child_deep, k, visit)
        return value
    if isinstance(value, list):
        for i, item in enumerate(value):
            value[i] = _walk_sse(item, deep, key, visit)
        return value
    if isinstance(value, str) and deep:
        return visit(key, value)
    return value


# ---------------------------------------------------------------------------
# 重叠消解 + 替换应用
# ---------------------------------------------------------------------------

def _resolve_overlaps(spans):
    """priority 小者胜、同级长 span 胜、再按出现顺序；返回按位置升序、互不重叠"""
    spans = sorted(spans, key=lambda s: (s[2], -(s[1] - s[0]), s[0], s[3]))
    selected = []
    for span in spans:
        if all(span[0] >= other[1] or span[1] <= other[0] for other in selected):
            selected.append(span)
    selected.sort(key=lambda s: (s[0], s[1]))
    return selected


# ---------------------------------------------------------------------------
# 检测器（config.json detectors，可选；http 批量协议）
# ---------------------------------------------------------------------------

def _http_post_default(url: str, payload: bytes, timeout_s: float) -> bytes:
    request = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout_s) as resp:
        return resp.read()


def _byte_to_char_map(text: str) -> dict:
    """UTF-8 字节偏移 → 字符（码点）下标对照（仅字符边界有映射）"""
    mapping = {}
    total = 0
    for i, ch in enumerate(text):
        mapping[total] = i
        total += len(ch.encode("utf-8"))
    mapping[total] = len(text)
    return mapping


def _normalize_span(text: str, span, defaults):
    """校验检测器 span 并把 UTF-8 字节偏移转为字符偏移；非法 span 返回 None（丢弃）。

    检测协议约定 start/end 为字节偏移且必须落在字符边界上——非边界字节偏移
    （如切进多字节字符中间）视为检测器错误，丢弃该 span（fail-open 防御）。
    """
    try:
        b_start = int(span["start"])
        b_end = int(span["end"])
    except Exception:
        return None
    mapping = _byte_to_char_map(text)
    if b_start not in mapping or b_end not in mapping:
        return None
    start, end = mapping[b_start], mapping[b_end]
    if start >= end:
        return None
    label = span.get("label") or defaults[1] or "PII"
    desc = span.get("desc") or defaults[2] or ""
    priority = span.get("priority")
    priority = int(priority) if isinstance(priority, (int, float)) else defaults[0]
    # 与规则 span 同一 canonical 形状：(start, end, priority, order, label, desc)
    # （order=0：同级并列时由 start 兜底排序）
    return (start, end, priority, 0, label, desc)


# ---------------------------------------------------------------------------
# SSE 块标识（跨 delta 的 carry 按块区分）
# ---------------------------------------------------------------------------

def _sse_block_key(value) -> str:
    """Claude: delta.type + index；Codex: type + content_index；缺形返回空串"""
    kind = ""
    if isinstance(value, dict):
        delta = value.get("delta")
        if isinstance(delta, dict):
            kind = delta.get("type") or ""
        if not kind:
            kind = value.get("type") or ""
    if not isinstance(kind, str) or not kind:
        return ""
    index = None
    if isinstance(value, dict):
        index = value.get("index")
        if index is None:
            index = value.get("content_index")
    if isinstance(index, int):
        return f"{kind}:{index}"
    return kind


# ---------------------------------------------------------------------------
# 标记协议说明注入（Claude / Codex / Gemini 三形状）
# ---------------------------------------------------------------------------

def inject_marker_prompt(body) -> bool:
    if not isinstance(body, dict):
        return False
    if "system" in body:
        system = body["system"]
        if isinstance(system, str):
            body["system"] = system + "\n\n" + MARKER_PROMPT_NOTE
            return True
        if isinstance(system, list):
            system.append({"type": "text", "text": MARKER_PROMPT_NOTE})
            return True
        return False
    if isinstance(body.get("instructions"), str):
        body["instructions"] = body["instructions"] + "\n\n" + MARKER_PROMPT_NOTE
        return True
    si = body.get("systemInstruction")
    if isinstance(si, dict) and isinstance(si.get("parts"), list):
        si["parts"].append({"text": MARKER_PROMPT_NOTE})
        return True
    # 三种字段都缺失：默认按 Claude 形状创建 system blocks
    body["system"] = [{"type": "text", "text": MARKER_PROMPT_NOTE}]
    return True


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------

class Engine:
    """插件引擎：持规则/配置（mtime 热重载）、映射存储、缓存、SSE 会话状态。

    transport: 可注入的 HTTP POST 函数 (url, payload_bytes, timeout_s) -> bytes，
    默认 urllib 实现；传入自定义实现可不依赖网络（配置界面预览即用此机制记录检测失败）。
    """

    def __init__(self, plugin_dir: str, transport=None):
        self.dir = os.path.abspath(plugin_dir)
        # 用户配置统一放 json/ 子目录（plugin.json 按契约仍须在插件根目录）
        self.json_dir = os.path.join(self.dir, "json")
        self.rules_path = os.path.join(self.json_dir, "rules.json")
        self.custom_values_path = os.path.join(self.json_dir, "custom-values.json")
        self.config_path = os.path.join(self.json_dir, "config.json")
        # 旧版根目录配置迁移提醒（进程启动时一次性）：配置静默失效是最坏故障，
        # 必须大声告警而不是悄悄读不到
        for _name in ("rules.json", "custom-values.json", "config.json"):
            if os.path.isfile(os.path.join(self.dir, _name)) \
                    and not os.path.isfile(os.path.join(self.json_dir, _name)):
                _warn(f"检测到旧版根目录 {_name}:新版配置目录为 json/,请把文件移入后重载")
        self.transport = transport or _http_post_default
        self._rules_mtime = None
        self._config_mtime = None
        self._custom_mtime = None
        self._fingerprint = ""
        self.rules = []
        self.custom_values = []  # [(value, label, desc, priority)]，用户自定义特殊值
        self.config = {}
        self.cache = {}
        self.cache_capacity = CACHE_DEFAULT_CAPACITY
        self.store = MappingStore("")
        self.sse_sessions = {}  # session_id -> {"carries": {key: str}, "seen_marker": bool}
        self._reload(force=True)

    # -- 配置/规则热重载 ----------------------------------------------------

    def _reload(self, force: bool = False) -> None:
        rules_mtime = os.path.getmtime(self.rules_path) if os.path.isfile(self.rules_path) else 0
        config_mtime = os.path.getmtime(self.config_path) if os.path.isfile(self.config_path) else 0
        custom_mtime = os.path.getmtime(self.custom_values_path) if os.path.isfile(self.custom_values_path) else 0
        if not force and (rules_mtime == self._rules_mtime and config_mtime == self._config_mtime
                          and custom_mtime == self._custom_mtime):
            return
        rules_doc, rules_raw = _read_json(
            self.rules_path, {"enabled": True, "rules": []})
        config_doc, config_raw = _read_json(self.config_path, {})
        custom_doc, custom_raw = _read_json(self.custom_values_path, {})
        self._rules_mtime, self._config_mtime, self._custom_mtime = \
            rules_mtime, config_mtime, custom_mtime
        # 指纹 = 规则 + 配置 + 自定义特殊值三个文件的内容哈希
        # （缓存键的一部分：任何配置变更自动失效）
        self._fingerprint = hashlib.sha256(
            rules_raw + b"\x00" + config_raw + b"\x00" + custom_raw).hexdigest()
        self.rules = _compile_rules(rules_doc if isinstance(rules_doc, dict) else {})
        self.config = config_doc if isinstance(config_doc, dict) else {}
        self.custom_values = _compile_custom_values(
            custom_doc if isinstance(custom_doc, dict) else {})
        capacity = self.config.get("cache_capacity")
        self.cache_capacity = int(capacity) if isinstance(capacity, (int, float)) and capacity > 0 \
            else CACHE_DEFAULT_CAPACITY
        mapping_rel = self.config.get("mapping_file") or os.path.join("data", "mappings.json")
        mapping_path = os.path.normpath(os.path.join(self.dir, str(mapping_rel)))
        # 映射文件必须落在插件目录内（配置笔误防御）
        if not mapping_path.startswith(self.dir + os.sep):
            _warn(f"mapping_file 指向插件目录之外（{mapping_path}），已回退默认路径")
            mapping_path = os.path.join(self.dir, "data", "mappings.json")
        if self.store.path != mapping_path:
            self.store = MappingStore(mapping_path)
        # 散列算法/方式（作用于新映射；已存在映射保持原 id 不变）
        hash_cfg = self.config.get("hash") if isinstance(self.config.get("hash"), dict) else {}
        algorithm = hash_cfg.get("algorithm", "blake2b")
        if algorithm not in _HASH_ALGORITHMS:
            _warn(f"散列算法 {algorithm!r} 不支持（可选 {', '.join(_HASH_ALGORITHMS)}），回退 blake2b")
            algorithm = "blake2b"
        mode = hash_cfg.get("mode", "adaptive")
        if mode not in ("adaptive", "fixed"):
            _warn(f"散列方式 {mode!r} 不支持（可选 adaptive / fixed），回退 adaptive")
            mode = "adaptive"
        length = hash_cfg.get("length", 16)
        length = int(length) if isinstance(length, (int, float)) else 16
        self.store.hash_cfg = {"algorithm": algorithm, "mode": mode,
                               "length": max(4, min(length, 64))}
        # 用户自定义特殊值：加载即预注册映射（用户"手动记录"的值立刻拥有稳定 id，
        # 即使尚未在任何请求里出现过，响应侧也已可还原）
        registered = False
        for value, label, _desc, _priority in self.custom_values:
            if value not in self.store.by_original:
                self.store.get_or_create(value, label)
                registered = True
        if registered and self.store.dirty:
            try:
                self.store.save()
            except Exception as exc:
                _warn(f"映射文件写入失败（内存映射仍生效）: {exc}")
                self.store.dirty = False

    def _has_backends(self) -> bool:
        # 三个可选来源：正则规则（enable_regex）、检测模型（enable_detectors）、
        # 用户自定义特殊值（custom-values.json）
        if self.config.get("enable_regex", True) and self.rules:
            return True
        if self.config.get("enable_detectors", True) and self.config.get("detectors"):
            return True
        return bool(self.custom_values)

    # -- 缓存 ---------------------------------------------------------------

    def _cache_key(self, text: str) -> str:
        return self._fingerprint + ":" + blake2b_hex(text.encode("utf-8"))

    def _cache_trim(self) -> None:
        if len(self.cache) > self.cache_capacity:
            for key in list(self.cache.keys())[: len(self.cache) // 2]:
                del self.cache[key]

    # -- 检测 ---------------------------------------------------------------

    def _collect_regex_spans(self, text: str):
        """正则/字面量规则收集 span；capture 指定时只取该捕获组的范围"""
        spans = []
        order = 0
        for rule in self.rules:
            if rule["kind"] == "regex":
                for match in rule["matcher"].finditer(text):
                    if rule["capture"] is None:
                        start, end = match.start(), match.end()
                    else:
                        try:
                            start, end = match.span(rule["capture"])
                        except (IndexError, re.error) as exc:
                            _warn(f"规则 {rule['name']} 的 capture 无效，已跳过规则: {exc}")
                            break
                        if start < 0:  # 该组未参与本次匹配
                            continue
                    if end <= start:
                        continue
                    spans.append((start, end, rule["priority"], order,
                                  rule["label"], rule["desc"]))
                    order += 1
            else:  # literal
                for value in rule["values"]:
                    from_i = 0
                    while True:
                        pos = text.find(value, from_i)
                        if pos < 0:
                            break
                        end = pos + len(value)
                        spans.append((pos, end, rule["priority"], order,
                                      rule["label"], rule["desc"]))
                        order += 1
                        from_i = end
        return spans

    def _collect_custom_spans(self, text: str):
        """用户自定义特殊值：与正则命中完全同路（走同一标记映射），
        直接替换为 ⟦PII|…⟧ 标记。priority 缺省 1，优先于常规规则。"""
        spans = []
        order = 0
        for value, label, desc, priority in self.custom_values:
            from_i = 0
            while True:
                pos = text.find(value, from_i)
                if pos < 0:
                    break
                end = pos + len(value)
                spans.append((pos, end, priority, order, label, desc))
                order += 1
                from_i = end
        return spans

    def _detect_batch(self, texts):
        """每个检测器各做一次批量调用（每请求每检测器至多一次）；
        失败/超限的检测器本批空产出（fail-open，不影响其他检测器）"""
        merged = [[] for _ in texts]
        if not self.config.get("enable_detectors", True):
            return merged  # 总开关：不启用检测模型
        detectors = self.config.get("detectors") or []
        for detector in detectors:
            if not isinstance(detector, dict) or detector.get("kind") != "http":
                continue
            if not detector.get("enabled", True):
                continue  # 选用哪些标记模型：detector 级开关
            url = detector.get("url")
            if not isinstance(url, str) or not url.strip():
                continue
            # 配置字段容错：timeout_ms/max_chars 类型错误只跳过本检测器（fail-open），
            # 不影响正则与其他检测器
            try:
                timeout_ms = detector.get("timeout_ms", 10000)
                timeout_s = max(1, int(timeout_ms)) / 1000.0
                max_chars = detector.get("max_chars")
                max_chars = int(max_chars) if max_chars is not None else None
            except (TypeError, ValueError) as exc:
                _warn(f"检测器 {url} 配置字段非法，本批按空产出处理: {exc}")
                continue
            defaults = (
                int(detector["priority"]) if isinstance(detector.get("priority"), (int, float)) else 100,
                detector.get("label") or None,
                detector.get("desc") or None,
            )
            indexes, batch = [], []
            for i, text in enumerate(texts):
                if max_chars is not None and len(text.encode("utf-8")) > max_chars:
                    continue  # 超限字符串跳过该检测器
                indexes.append(i)
                batch.append(text)
            if not batch:
                continue
            try:
                payload = json.dumps({"texts": batch}, ensure_ascii=False).encode("utf-8")
                raw = self.transport(url.strip(), payload, timeout_s)
                doc = json.loads(raw.decode("utf-8"))
                spans_lists = doc.get("spans")
                if not isinstance(spans_lists, list) or len(spans_lists) != len(batch):
                    raise ValueError("spans 长度与 texts 不一致")
                for slot, spans in enumerate(spans_lists):
                    for span in spans or []:
                        normalized = _normalize_span(batch[slot], span, defaults)
                        if normalized is not None:
                            merged[indexes[slot]].append(normalized)
            except Exception as exc:
                _warn(f"检测器 {url} 本批失败，按空产出处理: {exc}")
        return merged

    # -- 替换 ---------------------------------------------------------------

    def _compute_replacements(self, texts):
        """两段式：缓存命中直接取；未命中的字符串各检测器一次批量检测，
        合并 span（标记区守卫 + 重叠消解）后统一替换并写缓存"""
        result = {}
        if not texts:
            return result
        pending = []
        for text in texts:
            cached = self.cache.get(self._cache_key(text))
            if cached is not None:
                result[text] = cached
            else:
                pending.append(text)
        if not pending:
            return result
        detector_spans = self._detect_batch(pending)
        use_regex = self.config.get("enable_regex", True)  # 总开关：正则引擎
        for slot, text in enumerate(pending):
            # span 来源：自定义特殊值（用户登记，优先）+ 正则规则 + 检测模型
            spans = self._collect_custom_spans(text)
            if use_regex:
                spans = spans + self._collect_regex_spans(text)
            spans = spans + detector_spans[slot]
            replaced = self._apply_spans(text, spans)
            self.cache[self._cache_key(text)] = replaced
            result[text] = replaced
        self._cache_trim()
        return result

    def _apply_spans(self, text: str, spans) -> str:
        # 防御性过滤越界 span（外部检测器可能给出坏偏移）
        valid = [s for s in spans if 0 <= s[0] < s[1] <= len(text)]
        # 标记区守卫：已有 ⟦PII|…⟧ 区域不得再次入库/再遮罩（防标记套娃产生垃圾映射）
        zones = [(zs, ze) for (zs, ze, _mid) in scan_markers(text)]
        pruned = [s for s in valid
                  if not any(s[0] < ze and s[1] > zs for (zs, ze) in zones)]
        selected = _resolve_overlaps(pruned)
        if not selected:
            return text
        out = []
        last = 0
        for start, end, _priority, _order, label, desc in selected:
            original = text[start:end]
            marker_id, _is_new = self.store.get_or_create(original, label)
            out.append(text[last:start])
            out.append(f"{MARKER_PREFIX}{marker_id}|{label}|{desc}{MARKER_SUFFIX}")
            last = end
        out.append(text[last:])
        return "".join(out)

    # -- stage 处理 ----------------------------------------------------------

    def on_pre_request(self, req) -> dict:
        body = req.get("body")
        if not isinstance(body, (dict, list)) or not self._has_backends():
            return {}
        # 阶段 1：走查收集白名单字符串（去重，保持首次出现顺序）
        texts = []
        seen = set()

        def collect(s: str) -> str:
            if s not in seen:
                seen.add(s)
                texts.append(s)
            return s

        _walk(body, False, REPLACE_TARGET_KEYS, collect)
        # 阶段 2：批量检测（每检测器一次）→ 合并替换（守卫 + 消解）→ 写缓存
        replacements = self._compute_replacements(texts)
        # 阶段 3：统一应用替换
        changed = False

        def apply(s: str) -> str:
            nonlocal changed
            new = replacements.get(s)
            if new is None or new == s:
                return s
            changed = True
            return new

        _walk(body, False, REPLACE_TARGET_KEYS, apply)
        # 标记协议说明注入（走查之后，说明文本自身不参与替换；每轮恒定注入维持上游 prompt 缓存）
        if self.config.get("prompt_note", True) and inject_marker_prompt(body):
            changed = True
        if self.store.dirty:
            try:
                self.store.save()
            except Exception as exc:
                _warn(f"映射文件写入失败（内存映射仍生效）: {exc}")
                self.store.dirty = False
        return {"body": body} if changed else {}

    def on_post_response(self, req) -> dict:
        # 映射为空：零开销直通（无标记时代理行为与主线一致）
        if self.store.is_empty():
            return {}
        body = req.get("body")
        if not isinstance(body, (dict, list)):
            return {}

        def apply(s: str) -> str:
            restored = restore_markers(s, self.store.lookup)
            return s if restored is None else restored

        _walk(body, False, RESTORE_TARGET_KEYS, apply)
        return {"body": body}

    def on_sse_chunk(self, req) -> dict:
        session_id = str(req.get("session_id") or "")
        data = req.get("data")
        if not isinstance(data, str):
            return {}
        event_name = req.get("event")
        flush = event_name in FLUSH_EVENTS

        if self.store.is_empty():
            if event_name == "message_stop":
                # 流结束：无条件清空该会话全部状态
                self.sse_sessions.pop(session_id, None)
            return {}
        state = self.sse_sessions.setdefault(
            session_id, {"carries": {}, "seen_marker": False})
        # 短路：本事件不含 ⟦ 且流中无扣留痕迹 → 零开销透传
        if "⟦" not in data and not state["seen_marker"]:
            return {}
        try:
            value = json.loads(data)
        except Exception:
            return {}  # 非 JSON（如 [DONE]）原样透传
        if not isinstance(value, (dict, list)):
            return {}

        block_key = _sse_block_key(value)
        lookup = self.store.lookup
        changed = False

        def visit(leaf_key: str, s: str) -> str:
            nonlocal changed
            # 跨 delta 半截标记：new = carry + 本段文本，替换完整标记后按需扣留尾部
            carry_key = f"{block_key}|{leaf_key}"
            carry = state["carries"].pop(carry_key, "")
            emitted, withheld = restore_stream_text(carry + s, flush, lookup)
            if withheld:
                state["carries"][carry_key] = withheld
                state["seen_marker"] = True
            if emitted != s:
                changed = True
                return emitted
            return s

        _walk_sse(value, False, "", visit)

        if event_name == "content_block_stop":
            # 该块不再有 delta：剩余半截标记永远无法闭合，清除并记录（异常流才出现）
            stop_index = value.get("index") if isinstance(value, dict) else None
            if isinstance(stop_index, int):
                for key in list(state["carries"].keys()):
                    block = key.split("|", 1)[0]
                    if block.rsplit(":", 1)[-1] == str(stop_index):
                        withheld = state["carries"].pop(key)
                        if withheld:
                            _warn(f"content_block_stop 丢弃未闭合标记残留: {withheld}")
            else:
                state["carries"].clear()
        elif flush:
            for key, withheld in state["carries"].items():
                if withheld:
                    _warn(f"{event_name} 丢弃未闭合标记残留 ({key}): {withheld}")
            state["carries"].clear()

        if event_name == "message_stop":
            # 流结束：该会话全部状态出清后整体移除（防常驻进程缓慢累积）
            self.sse_sessions.pop(session_id, None)

        if not changed:
            return {}
        # 有修改：重新序列化写回（json.dumps 保序，键序不变）
        return {"body": {"data": json.dumps(value, ensure_ascii=False)}}

    # -- 入口 ----------------------------------------------------------------

    def handle(self, req) -> dict:
        """按 stage 分发；任何未知/异常由入口脚本兜底为 {}（透传）"""
        try:
            self._reload()
        except Exception as exc:
            _warn(f"配置重载失败，沿用旧配置: {exc}")
        stage = req.get("stage")
        if stage == "pre_request":
            return self.on_pre_request(req)
        if stage == "post_response":
            return self.on_post_response(req)
        if stage == "sse_chunk":
            return self.on_sse_chunk(req)
        return {}