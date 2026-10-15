---
name: domain-egress-audit
description: 免费域名安全检查 Skill。首次使用主动引导配置威胁情报 API；随后自动查询注册、DNS、证书、IP 归属和公开威胁情报，交叉验证本地安全名单，输出普通人也能看懂的 HTML 报告。
---

# Domain Safety Check · 域名安全检查 Skill (v1.6)

## 目标

用户只需说「检查 example.com 是否安全」，即可完成：**首次 API 配置引导 → 自动校验 → HTML 安全报告**。不要索要与技术检测无关的表格，不要要求手工准备 `business_context.json`。

## 基本规则

- **零密钥也能运行**：DNS、RDAP、RIPEstat、crt.sh 和允许公开下载的安全名单不需要账号。缺失的可选情报明确显示“未配置/未检查”，不能等同于“未发现威胁”。
- **首次主动引导**：有交互终端且尚未完成首次配置时，执行 `audit` 会自动打开 CLI 配置向导；Agent 场景先主动告知 OTX/urlscan 等注册与 Key 获取方法。用户可跳过并先检测，之后随时通过 `setup` 补充。
- **真实许可**：不询问用户属于哪个行业，也不在正常查询中反复提示商业用途。对已配置并有权限的 API 默认查询；用户关闭来源则跳过。**VirusTotal Public API 特例**：仅在用户主动确认使用符合其官方免费条款后启用（或使用已获许可的订阅）。不得把免费 Key 当作不受限制的商用授权。
- **敏感信息保护**：API Key 必须由用户通过本机隐藏输入或本地环境变量设置；**不要要求用户把 Key 发给 Agent**。只查询公开 FQDN，不上传完整 URL、账号、Cookie、内部主机名或其他敏感内容。
- **只读、被动检测**：默认不访问目标站点、不主动扫描、不自动阻断或放行。仅在用户允许时执行 `--tls-probe` 做一次 TLS 连接检查；仅连接公网 IP。
- **谨慎解释**：缓存名单、历史网页跳转、共享 IP 关联及 OTX Pulse 仅是线索。不能声称“100% 安全”，不能把查询失败显示为绿色通过。

## 第一步：帮助用户配置 API（首次自动引导）

首次运行：

```bash
pip install -r requirements.txt
python scripts/domain_audit.py audit --domain example.com
```

交互环境会先展示服务地址和申请步骤，再用 `getpass` 在本机输入密钥，保存于 `.env`，不会在终端、报告或 GitHub 中出现。

| 来源 | 注册与获取方式 | 是否必须 |
|---|---|---|
| AlienVault OTX | https://otx.alienvault.com/ 注册并进入账户 API Key 设置 | 可选，建议配置 |
| urlscan.io | https://urlscan.io/user/signup/ 注册，Settings & API → New API Key | 可选，建议配置 |
| VirusTotal | https://www.virustotal.com/gui/join-us ，Key: https://www.virustotal.com/gui/my-apikey | 可选；须先确认使用条款 |
| 微步在线 | https://x.threatbook.com/ ，如账号有域名分析接口权限再配置 | 可选；接口不保证有免费额度 |

配置完成后自动检测；后来要修改 Key：

```bash
python scripts/domain_audit.py setup
python scripts/domain_audit.py doctor --online
```

如果处于 CI、Agent、非交互环境，不弹出输入提示；读取已存在的环境变量或 `.env`。未配置的数据源写入报告，继续运行。可通过 `audit --no-prompt` 强制不交互。

## 第二步：自动检查域名

```bash
python scripts/domain_audit.py audit --domain example.com
```

程序依次执行：域名格式与公网检查、RDAP 注册信息、DNS A/AAAA/CNAME/NS、RIPEstat IP 归属、crt.sh 公开证书、OTX/urlscan（已配置时）、VirusTotal（已确认权限时）、微步在线（已授权接口时）、本地 PhishShield / IPGuard 等 IOC 规则、既有报告历史变化比对。

本地 IOC 首次自动更新；缓存过期会尝试刷新，失败时保留旧数据并标注过期。不得通过多平台“票数”抵消一个明确的恶意命中。未经确认的来源只输出“可疑线索”，不能当作恶意实锤。

检测过程中不必主动向用户询问用途、供应商、IP 或访问端口。可选 `--business-file` 仅适用于用户愿意添加背景事实的高级场景，不影响普通检查流程。

## 第三步：给普通用户输出清晰的 HTML 结论

默认输出：

```text
reports/example.com_时间戳.html   # 首选：浏览器打开，重点一眼看懂
reports/example.com_时间戳.json   # 机器可读的完整原始结果
```

HTML 页面只需呈现：

1. **检查结论**：发现严重风险 / 发现可疑问题 / 信息不足 / 暂未发现明显风险。
2. **建议怎么做**：不用安全术语，一句话给出明确行动建议。
3. **发现的问题**：展示具体风险及简短原因；没有问题时说明“已完成检查中未触发明显风险”。
4. **哪些检查已完成、哪些未完成**：不要把没查到说成通过。
5. **可折叠技术详情**：保留来源链接、查询时间和原始证据，需要时再展开。

报告是单个独立 HTML，不能加载外部脚本、字体或跟踪器；动态字符串必须转义，避免 HTML 注入。JSON 继续保留证据来源与时间。可选 `--markdown` 额外生成旧版详细 Markdown。

## 对话式 Agent 响应

- 有执行环境：先运行脚本，再基于真实报告给用户 `结论 + 具体问题 + 建议`，附 HTML 路径。
- 缺少 API Key：主动提供注册和配置链接；不能要求将密钥发到对话。已有基础数据可照常评估。
- 无执行环境或联网权限：明确告知未做实际联网验证，给出 `setup` 和 `audit` 命令，不能虚构实时风险结果。
- 对已取得的风险情报保留误报可能性、检测时点及数据来源。无可用证据时明确输出“信息不足”。

进一步的原理和规则见 `references/RISK_RULES.md`、`references/SERVICE_SETUP.md` 和 `references/LOCAL_IOC.md`。
