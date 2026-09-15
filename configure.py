# -*- coding: utf-8 -*-
"""隐私插件配置器（中文菜单）：免手写 JSON 的配置入口。

用法：在本插件目录执行  python configure.py
修改的就是插件同目录的 rules.json / custom-values.json / config.json，
保存即生效（引擎每次请求前检查文件修改时间，热重载，无需重启 cc-switch）。
"""

import json
import os
import re
import sys

DIR = os.path.dirname(os.path.abspath(__file__))

for _s in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass


def load(name, default):
    path = os.path.join(DIR, name)
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        print(f"!! {name} 解析失败（{exc}），将以其默认结构重建；原文件已备份为 {name}.bak")
        try:
            os.replace(path, path + ".bak")
        except OSError:
            pass
        return default


def save(name, doc):
    path = os.path.join(DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def ask(prompt, default=None):
    tip = f"（回车={default}）" if default is not None else ""
    raw = input(f"{prompt}{tip}: ").strip()
    return raw if raw else default


def ask_bool(prompt, default=True):
    raw = ask(f"{prompt} [y/n]", "y" if default else "n").lower()
    return raw in ("y", "yes", "1", "是", "true")


def ask_int(prompt, default):
    raw = ask(f"{prompt}", str(default))
    try:
        return int(raw)
    except ValueError:
        print("!! 不是数字，保持原值")
        return default


def pause():
    input("\n回车继续…")


# ---------------------------------------------------------------------------
# 正则规则
# ---------------------------------------------------------------------------

def menu_rules():
    doc = load("rules.json", {"enabled": True, "rules": []})
    rules = doc.setdefault("rules", [])
    while True:
        print("\n=== 正则规则（rules.json）===")
        if not rules:
            print("  （还没有规则）")
        for i, r in enumerate(rules):
            state = "开" if r.get("enabled", True) else "关"
            kind = r.get("kind", "?")
            extra = r.get("pattern") if kind == "regex" else ",".join(r.get("values", []))
            cap = f" capture={r['capture']}" if r.get("capture") is not None else ""
            print(f"  [{i}] [{state}] {r.get('name','?')} ({kind}{cap}) {str(extra)[:60]}")
        print("  1) 启用/停用某条   2) 新增正则规则   3) 修改某条   4) 删除某条"
              "   5) 规则引擎总开关   0) 返回")
        choice = ask("选择").lower()
        if choice == "0":
            save("rules.json", doc)
            print("已保存 rules.json")
            return
        if choice == "1":
            i = ask_int("序号", 0)
            if 0 <= i < len(rules):
                rules[i]["enabled"] = not rules[i].get("enabled", True)
        elif choice == "2":
            name = ask("规则名", "my-rule")
            pattern = ask("正则表达式（Python re 语法）", "")
            if not pattern:
                continue
            try:
                re.compile(pattern)
            except re.error as exc:
                print(f"!! 正则无效：{exc}")
                continue
            rule = {
                "kind": "regex", "name": name, "pattern": pattern,
                "label": ask("标记类别名（如 EMAIL/SECRET）", "CUSTOM"),
                "desc": ask("描述", ""),
                "priority": ask_int("优先级（越小越优先）", 20),
                "enabled": True,
            }
            if ask_bool("只替换某个捕获组（如 kv 密钥只遮值保键名）？", False):
                rule["capture"] = ask("组号或组名（如 4 或 v）", "1")
            rules.append(rule)
        elif choice == "3":
            i = ask_int("序号", 0)
            if not (0 <= i < len(rules)):
                continue
            r = rules[i]
            if r.get("kind") == "regex":
                new = ask("新正则表达式", r.get("pattern", ""))
                if new:
                    try:
                        re.compile(new)
                        r["pattern"] = new
                    except re.error as exc:
                        print(f"!! 正则无效：{exc}")
                        continue
            else:
                new = ask("新字面量（逗号分隔）", ",".join(r.get("values", [])))
                r["values"] = [v.strip() for v in new.split(",") if v.strip()]
            r["label"] = ask("标记类别名", r.get("label", "CUSTOM"))
            r["desc"] = ask("描述", r.get("desc", ""))
            r["priority"] = ask_int("优先级", r.get("priority", 20))
        elif choice == "4":
            i = ask_int("序号", -1)
            if 0 <= i < len(rules):
                rules.pop(i)
        elif choice == "5":
            doc["enabled"] = ask_bool("启用正则规则引擎？", doc.get("enabled", True))


# ---------------------------------------------------------------------------
# 自定义特殊值
# ---------------------------------------------------------------------------

def menu_custom_values():
    doc = load("custom-values.json", {"enabled": True, "values": []})
    values = doc.setdefault("values", [])
    while True:
        print("\n=== 自定义特殊值（custom-values.json，直接走标记映射）===")
        if not values:
            print("  （还没有登记——你预先知道不会被规则命中的账号/密码就登记在这里）")
        for i, v in enumerate(values):
            state = "开" if v.get("enabled", True) else "关"
            print(f"  [{i}] [{state}] {v.get('label','CUSTOM')} | {str(v.get('value',''))[:50]}")
        print("  1) 登记新值   2) 启用/停用   3) 修改   4) 删除   5) 总开关   0) 返回")
        choice = ask("选择").lower()
        if choice == "0":
            save("custom-values.json", doc)
            print("已保存 custom-values.json（登记的值已立即注册映射，id 稳定）")
            return
        if choice == "1":
            value = ask("特殊值原文（完整匹配，逐字出现才替换）", "")
            if not value:
                continue
            values.append({
                "value": value,
                "label": ask("标记类别名", "CUSTOM"),
                "desc": ask("描述", ""),
                "priority": ask_int("优先级（越小越优先，默认 1 压过正则）", 1),
                "enabled": True,
            })
        elif choice == "2":
            i = ask_int("序号", 0)
            if 0 <= i < len(values):
                values[i]["enabled"] = not values[i].get("enabled", True)
        elif choice == "3":
            i = ask_int("序号", 0)
            if 0 <= i < len(values):
                values[i]["value"] = ask("新原文", values[i].get("value", "")) or values[i]["value"]
                values[i]["label"] = ask("标记类别名", values[i].get("label", "CUSTOM"))
                values[i]["desc"] = ask("描述", values[i].get("desc", ""))
        elif choice == "4":
            i = ask_int("序号", -1)
            if 0 <= i < len(values):
                values.pop(i)
        elif choice == "5":
            doc["enabled"] = ask_bool("启用自定义特殊值？", doc.get("enabled", True))


# ---------------------------------------------------------------------------
# 检测模型
# ---------------------------------------------------------------------------

def menu_detectors():
    doc = load("config.json", {})
    detectors = doc.setdefault("detectors", [])
    while True:
        print("\n=== 检测模型（config.json detectors，HTTP 批量协议）===")
        if not detectors:
            print("  （未配置——如需本地隐私模型，见 README『接入隐私检测模型』）")
        for i, d in enumerate(detectors):
            state = "开" if d.get("enabled", True) else "关"
            print(f"  [{i}] [{state}] {d.get('url','?')}  label={d.get('label','MODEL')}")
        print("  1) 添加检测服务   2) 启用/停用   3) 删除   4) 检测总开关   0) 返回")
        choice = ask("选择").lower()
        if choice == "0":
            save("config.json", doc)
            print("已保存 config.json")
            return
        if choice == "1":
            url = ask("检测服务 URL（POST {\"texts\":[…]}）", "http://127.0.0.1:8765/detect")
            detectors.append({
                "kind": "http", "url": url, "enabled": True,
                "timeout_ms": ask_int("超时 ms", 8000),
                "max_chars": ask_int("单串最大字节数（0=不限）", 20000) or None,
                "priority": ask_int("兜底优先级", 100),
                "label": ask("兜底类别名", "MODEL"),
                "desc": ask("描述", "隐私模型"),
            })
        elif choice == "2":
            i = ask_int("序号", 0)
            if 0 <= i < len(detectors):
                detectors[i]["enabled"] = not detectors[i].get("enabled", True)
        elif choice == "3":
            i = ask_int("序号", -1)
            if 0 <= i < len(detectors):
                detectors.pop(i)
        elif choice == "4":
            doc["enable_detectors"] = ask_bool("启用检测模型总开关？",
                                               doc.get("enable_detectors", True))


# ---------------------------------------------------------------------------
# 散列
# ---------------------------------------------------------------------------

def menu_hash():
    doc = load("config.json", {})
    cfg = doc.setdefault("hash", {})
    print("\n=== 标记 id 散列（作用于新映射；已有映射 id 不变）===")
    print("  算法：blake2b（缺省）/ sha256 / sha512 / sha1")
    algo = ask("算法", cfg.get("algorithm", "blake2b")).lower()
    mode = ask("方式：adaptive=随原文长度（缺省）/ fixed=固定长度（防长度泄漏）",
               cfg.get("mode", "adaptive")).lower()
    length = ask_int("fixed 模式的基础长度（4-64，adaptive 忽略）", cfg.get("length", 16))
    if not ask_bool("保存？", True):
        return
    doc["hash"] = {"algorithm": algo, "mode": mode, "length": length}
    save("config.json", doc)
    print("已保存 config.json")


def main():
    while True:
        print("\n================ 隐私插件配置器 ================")
        print(" 1) 正则规则（启停/改表达式/新增）")
        print(" 2) 自定义特殊值（★预先登记账号密码等，直接走标记映射）")
        print(" 3) 检测模型（选用哪些隐私标记模型）")
        print(" 4) 标记 id 散列（算法与计算方式）")
        print(" 0) 退出（所有修改均已即时保存，热重载生效）")
        choice = ask("选择").lower()
        if choice == "1":
            menu_rules()
        elif choice == "2":
            menu_custom_values()
        elif choice == "3":
            menu_detectors()
        elif choice == "4":
            menu_hash()
        elif choice == "0":
            return


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n退出。")
