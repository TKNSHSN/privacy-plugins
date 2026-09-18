# -*- coding: utf-8 -*-
"""隐私插件可视化配置服务：本地 Web GUI（仅监听 127.0.0.1，纯标准库）。

启动：python configure_server.py
浏览器自动打开 http://127.0.0.1:<port>/（端口占用自动顺延）。

职责：
- 提供 ui/index.html 与 /api/* 配置接口（读改 json/ 目录下的 rules.json / custom-values.json /
  config.json，原子写，正则服务端校验）；
- /api/preview：用引擎做**干跑预览**（临时目录里拷贝映射表，不污染真实映射）；
- /api/test-detector：对配置的检测模型发一次真实批量调用，验证模型服务连通与产出。

安全边界：只绑定 127.0.0.1、无外网监听；映射表只读不写（真实映射表仅由
cc-switch 内运行的插件进程写入，本服务预览时使用临时副本）。
"""

import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIR = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(DIR, "ui")
JSON_DIR = os.path.join(DIR, "json")
CONFIG_FILES = ("rules.json", "custom-values.json", "config.json")

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, DIR)
import engine  # noqa: E402


# ---------------------------------------------------------------------------
# 校验与原子写
# ---------------------------------------------------------------------------

class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _load_doc(name):
    """读 json/ 目录下的用户配置（name 为文件名，如 rules.json）"""
    path = os.path.join(JSON_DIR, name)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise ApiError(f"{name} 解析失败: {exc}", 500)


def _atomic_write(name, doc):
    path = os.path.join(JSON_DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _as_int(value, fallback):
    return int(value) if isinstance(value, (int, float)) else fallback


def validate_rules_doc(doc):
    if not isinstance(doc, dict):
        raise ApiError("rules.json 必须是 JSON 对象")
    doc["enabled"] = bool(doc.get("enabled", True))
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise ApiError("rules 必须是数组")
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ApiError(f"rules[{i}] 必须是对象")
        kind = rule.get("kind")
        if kind not in ("regex", "literal"):
            raise ApiError(f"rules[{i}].kind 只能是 regex 或 literal")
        if kind == "regex":
            pattern = rule.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                raise ApiError(f"rules[{i}].pattern 不能为空")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ApiError(f"rules[{i}].pattern 正则无效: {exc}")
            capture = rule.get("capture")
            if capture is not None and not isinstance(capture, (int, str)):
                raise ApiError(f"rules[{i}].capture 必须是组号(数字)或组名(字符串)")
        else:
            values = rule.get("values")
            if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
                raise ApiError(f"rules[{i}].values 必须是非空字符串数组")
        rule["priority"] = _as_int(rule.get("priority"), 20)


def validate_custom_doc(doc):
    if not isinstance(doc, dict):
        raise ApiError("custom-values.json 必须是 JSON 对象")
    doc["enabled"] = bool(doc.get("enabled", True))
    values = doc.get("values")
    if not isinstance(values, list):
        raise ApiError("values 必须是数组")
    for i, row in enumerate(values):
        if not isinstance(row, dict):
            raise ApiError(f"values[{i}] 必须是对象")
        if not isinstance(row.get("value"), str) or not row["value"].strip():
            raise ApiError(f"values[{i}].value 不能为空")
        row["priority"] = _as_int(row.get("priority"), 1)


def validate_config_doc(doc):
    if not isinstance(doc, dict):
        raise ApiError("config.json 必须是 JSON 对象")
    for key in ("enable_regex", "enable_detectors", "prompt_note", "enable_hexdump_guard"):
        if key in doc:
            doc[key] = bool(doc[key])
    doc["cache_capacity"] = max(16, _as_int(doc.get("cache_capacity"), 4096))
    hash_cfg = doc.get("hash")
    if isinstance(hash_cfg, dict):
        algorithm = hash_cfg.get("algorithm", "blake2b")
        if algorithm not in engine._HASH_ALGORITHMS:
            raise ApiError(f"hash.algorithm 只能是 {', '.join(engine._HASH_ALGORITHMS)}")
        mode = hash_cfg.get("mode", "adaptive")
        if mode not in ("adaptive", "fixed"):
            raise ApiError("hash.mode 只能是 adaptive 或 fixed")
        hash_cfg["length"] = max(4, min(_as_int(hash_cfg.get("length"), 16), 64))
    detectors = doc.get("detectors")
    if isinstance(detectors, list):
        for i, det in enumerate(detectors):
            if not isinstance(det, dict):
                raise ApiError(f"detectors[{i}] 必须是对象")
            if det.get("kind") != "http":
                raise ApiError(f"detectors[{i}].kind 目前只支持 http")
            if not isinstance(det.get("url"), str) or not det["url"].strip():
                raise ApiError(f"detectors[{i}].url 不能为空")


# ---------------------------------------------------------------------------
# 预览（干跑：临时目录拷贝映射表，绝不写真实映射）
# ---------------------------------------------------------------------------

class _RecordingTransport:
    """包装引擎默认 HTTP 传输，记录检测调用失败——预览结果里展示，避免 fail-open 静默吞掉。"""

    def __init__(self, inner):
        self._inner = inner
        self.errors = []

    def __call__(self, url, payload, timeout_s):
        try:
            return self._inner(url, payload, timeout_s)
        except Exception as exc:
            self.errors.append(f"{url} → {exc}")
            raise


def make_preview_engine(transport=None):
    tmp = tempfile.mkdtemp(prefix="privacy-preview-")
    os.makedirs(os.path.join(tmp, "json"), exist_ok=True)
    for name in CONFIG_FILES:
        src = os.path.join(JSON_DIR, name)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(tmp, "json", name))
    mappings = os.path.join(DIR, "data", "mappings.json")
    if os.path.isfile(mappings):
        os.makedirs(os.path.join(tmp, "data"), exist_ok=True)
        shutil.copy(mappings, os.path.join(tmp, "data", "mappings.json"))
    return tmp, engine.Engine(tmp, transport=transport)


# ---------------------------------------------------------------------------
# HTTP 处理
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "PrivacyPluginConfig/1.0"

    def log_message(self, fmt, *args):  # 静默默认访问日志
        pass

    # -- 工具 ---------------------------------------------------------------

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ApiError(f"请求体不是合法 JSON: {exc}")

    # -- GET ----------------------------------------------------------------

    def do_GET(self):
        try:
            if self.path in ("/", "/index.html"):
                self._serve_index()
            elif self.path == "/api/state":
                mappings_path = os.path.join(DIR, "data", "mappings.json")
                mappings = []
                if os.path.isfile(mappings_path):
                    try:
                        with open(mappings_path, "r", encoding="utf-8") as fh:
                            mappings = json.load(fh)
                    except Exception:
                        mappings = []  # 映射文件损坏时界面按空表展示，不阻塞配置面板
                rows = mappings if isinstance(mappings, list) else []
                self._send_json({
                    "plugin_dir": DIR,
                    "rules": _load_doc("rules.json"),
                    "custom_values": _load_doc("custom-values.json"),
                    "config": _load_doc("config.json"),
                    "mappings_count": len(rows),
                    "mappings": list(reversed(rows[-2000:])),
                })
            elif self.path == "/api/health":
                self._send_json({"ok": True})
            else:
                self._send_json({"error": "not found"}, 404)
        except ApiError as exc:
            self._send_json({"error": str(exc)}, exc.status)
        except Exception as exc:
            self._send_json({"error": f"服务器内部错误: {exc}"}, 500)

    def _serve_index(self):
        path = os.path.join(UI_DIR, "index.html")
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send_json({"error": "ui/index.html 缺失"}, 500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- POST ---------------------------------------------------------------

    def do_POST(self):
        try:
            if self.path == "/api/save":
                body = self._read_json_body()
                name = body.get("file")
                doc = body.get("doc")
                if name == "rules.json":
                    validate_rules_doc(doc)
                elif name == "custom-values.json":
                    validate_custom_doc(doc)
                elif name == "config.json":
                    validate_config_doc(doc)
                else:
                    raise ApiError(f"不支持的配置文件: {name}")
                _atomic_write(name, doc)
                self._send_json({"ok": True})
            elif self.path == "/api/validate-regex":
                pattern = (self._read_json_body() or {}).get("pattern", "")
                try:
                    re.compile(pattern)
                    self._send_json({"ok": True})
                except re.error as exc:
                    self._send_json({"ok": False, "error": str(exc)})
            elif self.path == "/api/preview":
                text = (self._read_json_body() or {}).get("text", "")
                if not isinstance(text, str) or not text:
                    raise ApiError("text 不能为空")
                rec = _RecordingTransport(engine._http_post_default)
                tmp, preview_engine = make_preview_engine(rec)
                try:
                    request = {"stage": "pre_request", "session_id": "preview",
                               "body": {"messages": [{"role": "user", "content": [
                                   {"type": "text", "text": text}]}]}}
                    response = preview_engine.handle(request)
                    out = response.get("body", {}).get(
                        "messages", [{}])[0].get("content", [{}])[0].get("text", "")
                    markers = [
                        {"id": mid,
                         "label": (out[s:e].split("|")[2] if "|" in out[s:e] else "")}
                        for (s, e, mid) in engine.scan_markers(out)
                    ]
                    cfg = preview_engine.config
                    self._send_json({
                        "output": out, "changed": bool(response),
                        "markers": markers,
                        "detector_errors": rec.errors,
                        "effective": {
                            "enable_regex": bool(cfg.get("enable_regex", True)),
                            "enable_detectors": bool(cfg.get("enable_detectors", True)),
                            "rules_count": len(preview_engine.rules),
                            "custom_values_count": len(preview_engine.custom_values),
                            "detectors": [
                                {"url": d.get("url"), "enabled": d.get("enabled", True),
                                 "timeout_ms": d.get("timeout_ms", 10000)}
                                for d in (cfg.get("detectors") or [])
                                if isinstance(d, dict)
                            ],
                        },
                    })
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
            elif self.path == "/api/test-detector":
                body = self._read_json_body()
                url = body.get("url", "")
                if not isinstance(url, str) or not url.strip():
                    raise ApiError("url 不能为空")
                timeout_s = max(1, _as_int(body.get("timeout_ms"), 8000)) / 1000.0
                payload = json.dumps({"texts": [
                    "测试：mail test@example.com 10.0.0.5 张三"
                ]}, ensure_ascii=False).encode("utf-8")
                request = urllib.request.Request(
                    url.strip(), data=payload,
                    headers={"Content-Type": "application/json"}, method="POST")
                try:
                    with urllib.request.urlopen(request, timeout=timeout_s) as resp:
                        raw = resp.read()
                except Exception as exc:
                    self._send_json({"ok": False, "error": f"调用失败: {exc}"})
                    return
                try:
                    doc = json.loads(raw.decode("utf-8"))
                    spans = doc.get("spans")
                    if not isinstance(spans, list):
                        raise ValueError("响应缺少 spans 数组")
                    self._send_json({"ok": True, "spans": spans})
                except Exception as exc:
                    self._send_json({"ok": False,
                                     "error": f"响应不符合协议（{{\"spans\":[[…]]}}): {exc}",
                                     "raw": raw.decode("utf-8", "replace")[:2000]})
            else:
                self._send_json({"error": "not found"}, 404)
        except ApiError as exc:
            self._send_json({"error": str(exc)}, exc.status)
        except Exception as exc:
            self._send_json({"error": f"服务器内部错误: {exc}"}, 500)


def pick_port(start=8766):
    port = start
    while port < start + 20:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("8766-8785 端口均被占用")


def main():
    port = pick_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"[privacy-config] 配置界面已启动: {url} （Ctrl+C 退出）")
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[privacy-config] 已退出")


if __name__ == "__main__":
    main()
