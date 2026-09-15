# -*- coding: utf-8 -*-
"""隐私替换插件入口：常驻进程，按行交换 JSON（协议见 docs/dev/plugin-system-contract.md 2.5）。

请求一行 JSON（cc-switch → stdin）：{"stage": "...", "session_id": "...", "body": {...}}
  sse_chunk 额外携带 "event" / "data"；
响应一行 JSON（stdout → cc-switch）：{"body": {…}} 或 {}；
  sse_chunk 为 {"body": {"data": "…"}}。
其余任何输出必须写到 stderr（cc-switch 只解析 stdout 的一行 JSON）。

运行要求：Python 3.7+（脚本目录内 config.json/rules.json 可随时编辑，保存即生效）。
Python 不在 PATH 时，请把 plugin.json 的 command 改为解释器完整路径，
如 ["C:\\\\Path\\\\To\\\\python.exe", "privacy_plugin.py"]。
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine  # noqa: E402


def main() -> None:
    # Windows 管道默认使用本地编码（如 GBK），⟦⟧ 等字符会写坏：强制 UTF-8
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    app = engine.Engine(plugin_dir)
    print(f"[privacy-plugin] 引擎已加载（插件目录: {plugin_dir}）", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = app.handle(request)
        except Exception as exc:  # 单条请求异常不影响进程存活（fail-open 透传）
            print(f"[privacy-plugin] 处理请求失败: {exc}", file=sys.stderr)
            response = {}
        sys.stdout.write(json.dumps(response, ensure_ascii=False))
        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
