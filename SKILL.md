---
name: domain-egress-audit
description: 通过公开数据源检查域名是否存在安全风险。首次主动引导配置可选免费 API，可由具备本地文件权限的 Agent 在会话接收 API Key 安全写入 .env；自动生成容易理解的 HTML 安全报告。
---

# Domain Safety Check Skill · v2.4

## 适用范围与原则

当用户说“检查 example.com 是否安全”，自动执行公开情报校验并交付**简明 HTML 报告**。不需要用户创建 `business_context.json`。支持首次使用时引导申请可选 API，之后只需域名。不可宣称绝对安全或擅自修改网络策略。

默认使用：无需密钥的 **DNS / RDAP / RIPEstat / crt.sh**、**PhishShield / IPGuard 开源静态安全名单**，以及可选的 **urlscan.io / VirusTotal**。**anti-AD** 默认作为广告追踪辅助线索（不得当作恶意 IOC 定性），使用者应核对聚合上游的许可，不参与恶意 IOC 定性。无须注册开源名单的 API；不使用其他第三方情报厂商 API，不要求人工提交情报文件。

- VirusTotal 必须**同时读取两个对象**：`GET /v3/domains/{host}`（域名对象）与 `GET /v3/urls/{sha256(scheme://host/)}`（URL 对象）。二者独立扫描、独立统计，只查域名对象会漏掉 URL 级 phishing/malware 判定的报毒。两对象结果分别输出 `domain_object` / `url_object`，并按对象分别给出风险线索（`vt_scope`）。均为纯 GET，404 表示无既有记录，不得因此提交新扫描。

- 默认读取第三方已有历史扫描详细结果，同时自动进行 TLS 握手检查（不发送 HTTP 请求）。urlscan 仅查询已有记录与详情，不提交新的网页扫描任务。
- 对外查询仅发送目标公开 FQDN；不要查询内部域名、包含密码或 Token 的 URL。
- API 缺失、接口超额、网络错误必须单独标明“未检查”，不能视为安全。
- VirusTotal 免费 Public API 有官方许可限制。仅用户确认具备适用授权时开启；否则不调用。
- 本地开源 IOC 默认自动更新，更新失败保留缓存并提示过期；精确域名命中只是需复核的证据，解析 IP 命中通常是共享基础设施弱关联。
- 仅得到历史跳转、域名较新等线索时，应说“需要进一步核实”，不是“确认恶意”。

## 第一步：引导配置 API

无 Key 也可执行基础检查。需要更全面检查时，提供官方注册步骤：

| 平台 | 官方入口 | 用途 |
|---|---|---|
| urlscan.io | https://urlscan.io/user/signup/ | 注册登录后在 Settings & API 创建 Key，读取公开历史扫描 |
| VirusTotal | https://www.virustotal.com/gui/join-us / https://www.virustotal.com/gui/my-apikey | 登录后获取 Key，读取已有域名检测结果；遵守许可 |

Agent 先执行 `python scripts/domain_audit.py doctor` 查看配置状态。用户主动在对话中给出 Key 时，如果 Agent 可访问项目本地文件，使用不记录秘密的标准输入或受控文件操作保存到 `.env`：

```bash
python scripts/domain_audit.py set-key --name URLSCAN_API_KEY --stdin
python scripts/domain_audit.py set-key --name VT_API_KEY --stdin --vt-tier noncommercial
```

对于 VirusTotal `--vt-tier noncommercial` / `--vt-tier premium` 仅在用户确认符合对应条款后选择。不可将 Key 写入 CLI 命令参数、公开代码、报告或日志，也不要回显密钥。若无法访问用户本机，不可假称已经完成配置，可请用户执行 `setup` 使用隐藏输入。

## 第二步：自动检查

```bash
pip install -r requirements.txt
python scripts/domain_audit.py audit --domain example.com
```

交互式终端首次执行会主动提示配置 API；无人值守加 `--no-prompt`。自动检查格式、当前 DNS、域名注册信息、IP 归属、证书透明度历史、PhishShield/IPGuard/anti-AD 本地 IOC、urlscan 历史扫描详情（默认最多 15 条）、已配置的 API、默认 TLS 握手，以及最近同域名的历史快照。无需额外 JSON 或人工输入。

## 第三步：HTML 结果

输出 `reports/example.com_时间戳.html` 和 `.json`。页面首先显示：**一句话风险结论、发现了什么问题、哪些检查完成或缺失、最终建议**；底部折叠显示详细证据、时间和来源。报告为完全离线可打开的单文件 HTML，所有外部数据都必须转义。

`未发现明显风险` 只指本次成功完成的检测；未配置域名信誉源时应报告信息不足，不能根据注册年限或证书存在便断言安全。不要将检测结论用作自动放行指令。

参见 [API 配置指南](references/SERVICE_SETUP.md)、[风险判断规则](references/RISK_RULES.md)、[本地开源 IOC 数据源](references/LOCAL_IOC.md)。

## 历史网站扫描和 TLS 检测的边界

- 默认：读取 urlscan 已有的历史 Search 结果，再逐条获取 Result JSON；提取历史截图链接、页面标题、最终域名、历史 IP、请求量、第三方资源域名、历史威胁标记。默认 15 条，`--history-limit 1..50` 可调整；精确 FQDN 无记录时补查子域名并标注弱关联；免费账户可能有 90 天历史范围限制，受额度限制；不要宣称已覆盖全网全部历史。
- 无 API Key、无历史记录、单条详情失败或 429 限额，必须明确标示“未检查 / 未找到 / 部分完成”，不得报告为安全。
- 实时网页扫描提交路径和相关 CLI 选项已移除；不得通过其他命令、脚本或 API 自动提交 urlscan 任务。配置 Key 或历史为空都不触发新扫描。
- `--no-tls-probe` 仅关闭默认 TLS 握手；它与 urlscan 远程实时网页扫描是两种不同功能。
