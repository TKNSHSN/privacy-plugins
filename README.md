# 隐私替换插件（privacy-replace）

把请求中的敏感信息替换为 `⟦PII|<id>|<label>|<desc>⟧` 标记发给上游模型，
响应（流式/非流式）中自动还原为原文。**引擎全部在本目录内**（Python 脚本 + 配置），
不依赖 cc-switch 核心代码；以普通用户插件方式导入即可，任何语言按同一协议都可重写。

权威规范（存于 cc-switch 仓库）：`docs/dev/privacy-pack-contract.md`（隐私包协议）、
`docs/dev/plugin-system-contract.md` §2.5（插件协议）。

## 目录结构

```
privacy-replace/
├── plugin.json          # 插件清单（mode: persistent，含 sse_chunk 流式挂点）
├── privacy_plugin.py    # 入口：常驻进程，按行交换 JSON
├── engine.py            # 引擎：标记编解码/映射存储/规则/检测器/走查/SSE 还原
├── rules.json           # ★ 用户正则规则（编辑保存即生效，无需重启）
├── custom-values.json   # ★ 用户自定义特殊值（预先登记账号密码等，直接走标记映射）
├── config.json          # ★ 引擎选项（正则/检测模型开关、散列、协议说明注入、缓存）
├── configure.py         # ★ 中文菜单配置器（python configure.py，免手写 JSON）
├── configure_server.py  # ★ 可视化配置服务（本地 Web GUI 后端，仅 127.0.0.1）
├── ui/index.html        # ★ 可视化配置界面（单文件，无外部依赖）
├── detector_server.py   # ★ 参考检测模型服务（/detect 协议，接真实模型的接入点）
├── README.md
└── data/mappings.json   # 运行时生成的映射表（明文存原文，见下方安全边界）
```

## 安装

cc-switch → 设置 → 高级 → 插件 → **导入插件**，选择本目录即可（也可手动拷贝整个
文件夹到 `<配置目录>/plugins/` 后点"重新加载"）。

**运行要求**：Python 3.7+，且 `python` 在 PATH 中。否则把 `plugin.json` 的
`command` 改为解释器完整路径，如 `["C:\\Python312\\python.exe", "privacy_plugin.py"]`。

## 可视化配置界面（GUI，推荐）

```
cd 本插件目录
python configure_server.py
```

浏览器自动打开 `http://127.0.0.1:8766/`（端口占用自动顺延）。功能：

- **实时预览**：输入示例文本 → 干跑一次真实替换（临时副本，不污染映射表），显示标记列表；
- **正则规则**：表格化启停/改表达式/新增/删除，正则服务端校验，支持捕获组只替换值；
- **特殊值**：★预先登记账号密码等，直接走标记映射；
- **检测模型**：选用哪些模型、启停、**一键测试连通性**（发真实批量请求看 spans）；
- **散列与选项**：算法（blake2b/sha256/sha512/sha1）、方式（adaptive/fixed）、各总开关；
- **映射表**：只读查看（默认隐藏原文，可搜索）。

所有修改即时保存、热重载生效，无需重启 cc-switch。界面只监听 127.0.0.1。

## 配置入口：configure.py（中文菜单）

不想手写 JSON 就用它：

```
cd 本插件目录
python configure.py
```

菜单覆盖：正则规则的启停/修改表达式/新增（含捕获组只替换值）、**自定义特殊值登记**、
检测模型的启停与添加、标记 id 散列算法与计算方式。所有修改即时保存，引擎热重载，
无需重启 cc-switch。手改下面几个配置文件与它等效。

## 配置：rules.json（用户自定义规则）

保存即生效（每次请求前检查文件修改时间，热重载）。字段：

| 字段 | 说明 |
|---|---|
| `enabled` | 总开关；`false` 时规则引擎不参与（检测模型仍可用） |
| `rules[].kind` | `"regex"` 或 `"literal"` |
| `rules[].pattern` | 正则表达式（Python `re` 语法，支持 `(?i)` 等内联旗标） |
| `rules[].capture` | **可选**，捕获组号（int）或命名组名（str）：只替换该组命中的部分，其余文本原样保留 |
| `rules[].values` | `kind=literal` 的字面量数组，逐个包含替换 |
| `rules[].label` / `desc` | 标记中的类别名 / 描述 |
| `rules[].priority` | 数字越小越优先；重叠时小者胜、同级长匹配胜 |
| `rules[].enabled` | 单条规则开关 |

### 只替换值、保留键名（kv 密钥类规则）

内置的 `kv-secret` 规则演示了 `capture` 的用法：模式里第 4 个捕获组是引号内的密钥值，
`"capture": 4` 使替换只作用于值——

```
api_key = "abcd1234efgh5678"   →   api_key = "⟦PII|…|SECRET|kv密钥值⟧"
```

组号按左括号出现顺序从 1 计数；更推荐把值那组写成命名组 `(?P<v>...)`，
然后 `"capture": "v"`，数括号的活儿就免了。

### ★ 自定义特殊值（custom-values.json）

你**预先知道**某段内容（账号、密码、内网域名、姓名…）不会被正则规则命中，或想给它
专门的类别名——把它登记到这里，它就**与正则命中完全同路**：出现即被替换为
`⟦PII|<id>|<label>|<desc>⟧`，响应中自动还原；且**登记瞬间就注册标记映射**
（id 稳定，尚未在对话里出现前映射已就绪）。

```json
{
  "enabled": true,
  "values": [
    { "value": "my-secret-password-01", "label": "PASSWORD", "desc": "主密码", "priority": 1, "enabled": true },
    { "value": "内网服务器 srv-internal.corp", "label": "HOST", "desc": "运维跳板", "priority": 1, "enabled": true }
  ]
}
```

- `value` 是**逐字面完整匹配**（子串包含，非正则）；`priority` 缺省 1（数字最小，
  压过正则规则——用户明确登记的值视为最高置信）；`enabled` 可临时停用某条。
- 用 configure.py 的菜单登记最省事（菜单 2）。

## 从旧版迁移

早期版本核心内置的同名插件已移除；如果你有旧的 `~/.cc-switch/privacy-rules.json`
（20 条规则集），把内容整份粘进本目录 `rules.json` 即可继续使用，格式完全一致。

## 配置：config.json

| 字段 | 默认 | 说明 |
|---|---|---|
| `enable_regex` | `true` | **启用正则引擎**总开关；关闭后仅自定义特殊值与检测模型参与 |
| `enable_detectors` | `true` | **启用本地隐私标记模型**总开关；关闭后所有 detectors 不调用 |
| `prompt_note` | `true` | 是否向系统提示注入"隐私标记协议"说明（让模型理解并保留标记） |
| `hash.algorithm` | `blake2b` | 标记 id 的单项散列：`blake2b` / `sha256` / `sha512` / `sha1` |
| `hash.mode` | `adaptive` | 计算方式：`adaptive`=id 长度随原文（min(max(12,字节长),64)）；`fixed`=固定长度（防长度泄漏，碰撞率随长度降低） |
| `hash.length` | `16` | fixed 模式的基础长度（4–64；adaptive 忽略） |
| `mapping_file` | `data/mappings.json` | 映射表文件（相对插件目录；必须留在插件目录内） |
| `cache_capacity` | `4096` | 免重复解析缓存条数；规则/配置变更自动失效 |
| `detectors` | `[]` | 额外检测后端（见下）；每个 detector 也有 `enabled` 字段——**选用哪些标记模型**在这里挑 |

> 散列说明：id 由「散列(原文)前缀」构成，算法/方式只影响**新登记**的映射；已存在的映射
> 保持原 id 不变（跨请求跨会话稳定优先）。从 `blake2b` 换 `sha256` 等行为等价，只是摘要不同。

### 接入隐私检测模型（可选）

`detectors` 里加一个 HTTP 检测服务即可与正则规则并用（span 合并后统一消解，
priority 小者胜）。协议：POST `{"texts": ["…", …]}`，期望 200 返回
`{"spans": [[{"start":0,"end":5,"label":"NAME","desc":"人名","priority":100}, …], …]}`，
`start`/`end` 为 UTF-8 字节偏移，`spans` 长度必须与 `texts` 一致，
`label`/`desc`/`priority` 可省略。检测服务失败只损失该检测器的 span，不影响正则与主链路。

```json
{
  "prompt_note": true,
  "mapping_file": "data/mappings.json",
  "cache_capacity": 4096,
  "detectors": [
    { "kind": "http", "url": "http://127.0.0.1:8765/detect", "enabled": true,
      "timeout_ms": 8000, "max_chars": 20000,
      "priority": 100, "label": "MODEL", "desc": "隐私模型" }
  ]
}
```

`max_chars`：超过上限（UTF-8 字节数）的字符串跳过该检测器，防大文本拖垮模型服务。
自建检测服务可参考 pr_framework（OPF/piiranha 模型）暴露一个 `/detect` 端点。

## 映射表与安全边界

- 同一原文永远映射到同一 id（blake2b 摘要前缀，长度随原文 12–64，碰撞自动加长），
  跨请求、跨会话的替换与还原保持一致；
- 映射表持久化在 `data/mappings.json`，插件目录被导入/拷贝时随行（换机即迁移）；
- ⚠️ **明文存储原文**——拿到这个文件就能还原所有标记。不要把 `data/` 提交到仓库、
  不要随日志/截图外发；标记本身不含原文，泄露标记文本不会直接泄露敏感内容。

## 其他语言实现

本插件只是参考实现。协议完全是语言无关的：声明 `"mode": "persistent"` 后，
cc-switch 启动你的进程一次，每次调用写一行 JSON 请求（stdin），期望一行 JSON 响应
（stdout）；请求/响应形状与 oneshot 模式完全一致（见 plugin-system-contract.md 2.5），
`sse_chunk` 额外携带 `event`/`data`。流式还原所需的跨事件状态放在你自己的进程内存里。
