---
name: domain-egress-audit
description: 通过公开数据源检查域名是否存在安全风险。首次主动引导配置可选免费 API，可由具备本地文件权限的 Agent 在会话接收 API Key 安全写入 .env；自动生成容易理解的 HTML 安全报告。
---

# Domain Safety Check Skill · v1.8

## 适用范围与原则

当用户说“检查 example.com 是否安全”，自动执行公开情报校验并交付**简明 HTML 报告**。不需要用户创建 `business_context.json`。支持首次使用时引导申请可选 API，之后只需域名。不可宣称绝对安全或擅自修改网络策略。

默认只使用以下来源：无需密钥的 **DNS / RDAP / RIPEstat / crt.sh**，以及可选的 **urlscan.io / VirusTotal**。不使用其他威胁情报 API、静态名单、自动扫描或需要人工提交的情报文件。首次或报告中也不应列出未集成的平台。

- 默认仅被动查询第三方现有记录，**不主动访问目标站点**；仅用户明确同意 `--tls-probe` 才建立 TLS 连接，不发送 HTTP 请求。
- 仅提交目标公开 FQDN；不要查询内部域名、包含密码或 Token 的 URL。
- API 缺失、接口超额、网络错误必须单独标明“未检查”，不能视为安全。
- VirusTotal 免费 Public API 有官方许可限制。仅用户确认具备适用授权时开启；否则不调用。
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

交互式终端首次执行会主动提示配置 API；无人值守加 `--no-prompt`。自动检查格式、当前 DNS、域名注册信息、IP 归属、证书透明度历史、已配置的 API，以及最近同域名的历史快照。无需额外 JSON 或人工输入。

## 第三步：HTML 结果

输出 `reports/example.com_时间戳.html` 和 `.json`。页面首先显示：**一句话风险结论、发现了什么问题、哪些检查完成或缺失、最终建议**；底部折叠显示详细证据、时间和来源。报告为完全离线可打开的单文件 HTML，所有外部数据都必须转义。

`未发现明显风险` 只指本次成功完成的检测；未配置域名信誉源时应报告信息不足，不能根据注册年限或证书存在便断言安全。不要将检测结论用作自动放行指令。

参见 [API 配置指南](references/SERVICE_SETUP.md)、[风险判断规则](references/RISK_RULES.md)。
