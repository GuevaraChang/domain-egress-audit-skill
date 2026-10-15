# 可选 API 免费配置指南

## 无需 Key

- DNS：使用本机配置的 DNS 解析器查询 A、AAAA、CNAME、NS。
- IANA RDAP：自动根据公共引导信息查注册域。
- RIPEstat：查询 IP 的网络归属及 ASN，不是恶意信誉评分。
- crt.sh：查询公开证书透明度信息。
- PhishShield / IPGuard：自动下载公开静态名单并在本地做匹配（不提交待查域名）。

## 可选 Key：按向导一步步操作

运行 `python scripts/domain_audit.py setup`，程序会给出链接并在本机隐藏输入密钥。API Key 仅保存在 `.env`，不要粘贴到聊天、日志或公开仓库。

### AlienVault OTX

1. 打开 https://otx.alienvault.com/ ，注册并验证账号。
2. 登录账户，在 Settings 或 API Key 页面复制自己的 OTX API Key。
3. 在 CLI 向导中输入，之后自动查询域名 Pulse 关联。Pulse 可能过期或只是社区线索。

### urlscan.io

1. 打开 https://urlscan.io/user/signup/ 注册。
2. 登录，进入 Settings & API，创建 **New API Key**。
3. 将 Key 配置进 CLI。程序仅搜索已有扫描，不主动向 urlscan 提交新 URL。
4. API 有配额限制，遇 429 或访问失败会标明“未完成”，不会伪造数据。

官方：https://docs.urlscan.io/guides/quickstart

### VirusTotal（按官方使用范围）

1. 打开 https://www.virustotal.com/gui/join-us 注册。
2. 登录 https://www.virustotal.com/gui/my-apikey 获得 Key。
3. 配置前确认你有权在相应使用场景调用：免费 Public API 仅适用于官方允许的用途，不能用于商业产品/服务或部分业务工作流；订阅权限另有授权范围。
4. 在向导中确认适用条款并选择授权类型后才会保存启用标记。没有确认时直接跳过，不影响其他检查。

官方条款：https://docs.virustotal.com/reference/public-vs-premium-api

### 微步在线（可选）

1. 登录 https://x.threatbook.com/ ，查看当前账号是否具有**域名分析 API** 的可用权限与配额。
2. 若确实有权限，在向导中选择启用并在本机输入 Key；否则跳过。
3. 免费网页查询能力不代表 API 权限，工具不会尝试爬取登录态网页。

## 验证

```bash
python scripts/domain_audit.py doctor
python scripts/domain_audit.py doctor --online
```

如果有服务未配置或出错，仍可执行 `audit --domain example.com`，其报告会写出“未配置”或“查询失败”。
