# -*- coding: utf-8 -*-
"""参考检测模型服务：实现插件检测协议（POST {"texts":[…]} → {"spans":[[…]]}，
start/end 为 UTF-8 字节偏移），监听 http://127.0.0.1:8765/detect。

用途：
1. 不接真实模型时，用它验证插件"检测模型运行"链路是否打通（内置演示规则）；
2. 接真实模型：把 detect_one() 换成你的模型推理（如 pr_framework 的
   OPF/piiranha 管线），返回 [(start_char, end_char, label, desc, priority)] 即可，
   字节偏移换算本脚本已处理好。

启动：python detector_server.py [--port 8765]
"""

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

DEMO_RULES = [
    # （名称, 编译后的正则, label, desc, priority）——演示用，替换成你的模型推理
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
     "EMAIL", "邮箱", 100),
    ("cn-mobile", re.compile(r"1[3-9][0-9]{9}"), "PHONE", "手机号", 100),
    ("private-ipv4", re.compile(r"(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})"),
     "IPV4", "内网 IPv4", 100),
]


def char_spans(text):
    """演示检测：返回字符偏移 span 列表。★接真实模型改这里★"""
    out = []
    for name, compiled, label, desc, priority in DEMO_RULES:
        for m in compiled.finditer(text):
            out.append((m.start(), m.end(), label, desc, priority))
    return out


def to_byte_spans(text, char_spans_):
    """字符偏移 → 协议要求的 UTF-8 字节偏移"""
    prefix = []
    total = 0
    for ch in text:
        prefix.append(total)
        total += len(ch.encode("utf-8"))
    prefix.append(total)
    result = []
    for start, end, label, desc, priority in char_spans_:
        result.append({"start": prefix[start], "end": prefix[end],
                       "label": label, "desc": desc, "priority": priority})
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path not in ("/detect", "/"):
            self._json({"error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            doc = json.loads(self.rfile.read(length).decode("utf-8"))
            texts = doc["texts"]
            if not isinstance(texts, list):
                raise ValueError("texts 必须是数组")
            spans = [to_byte_spans(t, char_spans(t)) for t in texts]
            self._json({"spans": spans})
        except Exception as exc:
            self._json({"error": f"检测失败: {exc}"}, 400)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[detector] 检测模型服务: http://127.0.0.1:{args.port}/detect （Ctrl+C 退出）")
    print("[detector] 接真实模型：把 char_spans() 换成你的模型推理（见文件头注释）")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[detector] 已退出")


if __name__ == "__main__":
    main()