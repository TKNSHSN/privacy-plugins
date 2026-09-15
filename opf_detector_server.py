# -*- coding: utf-8 -*-
"""OPF 检测模型服务：openai/privacy-filter（本地 checkpoint）→ 插件 /detect 批量协议。

协议与 detector_server.py 完全一致：POST {"texts": ["…", …]} →
{"spans": [[{"start":…,"end":…,"label":…,"desc":…,"priority":…}, …], …]}，
start/end 为 UTF-8 字节偏移且落在字符边界（模型输出是字符偏移，这里统一换算）。

与参考实现 detector_server.py 的差别：它内置的是演示正则，本服务加载真实
OPF token-classification 模型（1.5B 参数 MoE，本地 CPU 推理，无 CUDA 依赖），
负责上下文型实体（人名/地址/组织等正则抓不住的东西）。

运行环境：需要 `opf` 包（torch + tiktoken），本仓库插件本体仍然零依赖——
本服务是可选外挂，装不上就继续用 detector_server.py 或正则。
本机现成环境（uv 建）：T:\\note\\agent_work\\privacy_replace\\opf_env，
安装方式：uv venv opf_env --python 3.12
          uv pip install --python opf_env torch tiktoken safetensors numpy packaging
          uv pip install --python opf_env -e <privacy-filter 仓库路径>

启动：
    <opf_env>/Scripts/python.exe opf_detector_server.py \
        [--checkpoint <模型目录>] [--port 8765] [--device cpu]
        [--priority 100] [--max-bytes 20000] [--decode viterbi]
模型目录缺省取环境变量 OPF_CHECKPOINT，再退到本机默认
T:\\note\\agent_work\\privacy_replace\\opf_ckpt（原生格式：config.json +
model.safetensors + viterbi_calibration.json；opf_model/ 是 HF 转换格式）。

首次调用触发 2.8GB 权重加载（本机 NVMe 数秒），之后每次前向约零点几秒——
CPU 上批量文本是串行推理，插件侧 detector 的 timeout_ms 建议 ≥30000。
"""

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

DEFAULT_CHECKPOINT = r"T:\note\agent_work\privacy_replace\opf_ckpt"

# 模型 8 类标签 → 插件标记的 (label, desc)。改这里即可换呈现，不影响协议。
LABEL_MAP = {
    "private_person": ("NAME", "人名"),
    "private_address": ("ADDRESS", "地址"),
    "private_email": ("EMAIL", "邮箱"),
    "private_phone": ("PHONE", "电话"),
    "private_date": ("DATE", "日期"),
    "private_url": ("URL", "网址"),
    "account_number": ("ACCOUNT", "账号"),
    "secret": ("SECRET", "密钥"),
}
FALLBACK_LABEL, FALLBACK_DESC = "PII", "隐私实体"


def char_spans_to_byte_spans(text, char_spans):
    """字符（码点）偏移 → 协议要求的 UTF-8 字节偏移。"""
    prefix = []
    total = 0
    for ch in text:
        prefix.append(total)
        total += len(ch.encode("utf-8"))
    prefix.append(total)
    out = []
    for start, end, label, desc, priority in char_spans:
        out.append({"start": prefix[start], "end": prefix[end],
                    "label": label, "desc": desc, "priority": priority})
    return out


class OpfDetector:
    """OPF 模型封装：批量文本 → [(start_char, end_char, label, desc, priority)]。

    detect_one 是唯一的模型接入点；换 checkpoint/解码方式都在这里。
    推理用 threading.Lock 串行化（batch=1 前向，进程内无并发收益）。
    """

    def __init__(self, checkpoint, device="cpu", priority=100,
                 max_bytes=20000, decode_mode="viterbi", n_ctx=None):
        self.priority = priority
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        from opf._api import OPF  # 缺 opf 包时把报错留到构造，HTTP 层仍可起
        self._opf = OPF(model=checkpoint, device=device,
                        output_mode="typed", decode_mode=decode_mode,
                        context_window_length=n_ctx)
        t0 = time.time()
        self._opf.get_runtime()  # 立即加载权重，把耗时留在启动期而非首个请求
        self.load_seconds = time.time() - t0

    def detect_one(self, text):
        if not text or not text.strip():
            return []
        if len(text.encode("utf-8")) > self.max_bytes:
            return []  # 超限跳过（插件侧 max_chars 同样会跳，双保险）
        result = self._opf.redact(text)
        spans = []
        for s in result.detected_spans:
            label, desc = LABEL_MAP.get(s.label, (FALLBACK_LABEL, FALLBACK_DESC))
            spans.append((s.start, s.end, label, desc, self.priority))
        return spans

    def detect_batch(self, texts):
        with self._lock:
            return [char_spans_to_byte_spans(t, self.detect_one(t)) for t in texts]


class Handler(BaseHTTPRequestHandler):
    detector: OpfDetector = None  # main() 注入
    log_message = lambda self, fmt, *args: None

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path in ("/health", "/"):
            self._json({"ok": True, "model": "opf",
                        "load_seconds": round(self.detector.load_seconds, 1),
                        "labels": sorted(LABEL_MAP)})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if urlparse(self.path).path not in ("/detect", "/"):
            self._json({"error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            doc = json.loads(self.rfile.read(length).decode("utf-8"))
            texts = doc["texts"]
            if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
                raise ValueError("texts 必须是字符串数组")
            self._json({"spans": self.detector.detect_batch(texts)})
        except Exception as exc:
            self._json({"error": f"检测失败: {exc}"}, 400)


def resolve_checkpoint(arg_value):
    if arg_value:
        return arg_value
    import os
    env_value = os.environ.get("OPF_CHECKPOINT")
    if env_value:
        return env_value
    if __import__("os").path.isdir(DEFAULT_CHECKPOINT):
        return DEFAULT_CHECKPOINT
    raise SystemExit("未指定模型目录：--checkpoint / OPF_CHECKPOINT 均为空，"
                     f"本机默认路径也不存在（{DEFAULT_CHECKPOINT}）")


def main():
    parser = argparse.ArgumentParser(description="OPF 隐私检测模型服务（/detect 协议）")
    parser.add_argument("--checkpoint", help="OPF checkpoint 目录")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--device", default="cpu", choices=("cpu", "cuda"))
    parser.add_argument("--priority", type=int, default=100)
    parser.add_argument("--max-bytes", type=int, default=20000)
    parser.add_argument("--decode", default="viterbi", choices=("viterbi", "argmax"))
    parser.add_argument("--n-ctx", type=int, default=None,
                        help="上下文窗口（缺省 CPU=4096）")
    args = parser.parse_args()

    try:
        detector = OpfDetector(resolve_checkpoint(args.checkpoint),
                               device=args.device, priority=args.priority,
                               max_bytes=args.max_bytes, decode_mode=args.decode,
                               n_ctx=args.n_ctx)
    except ImportError as exc:
        raise SystemExit(f"缺少 opf 包（torch/tiktoken）：{exc}\n"
                         "用 opf_env 环境启动，见本文件头注释。")
    Handler.detector = detector

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[opf-detector] 模型加载完成（{detector.load_seconds:.1f}s），"
          f"服务: http://127.0.0.1:{args.port}/detect （Ctrl+C 退出）")
    print("[opf-detector] 插件侧配置: "
          '{"kind":"http","url":"http://127.0.0.1:%d/detect","timeout_ms":30000}' % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[opf-detector] 已退出")


if __name__ == "__main__":
    main()
