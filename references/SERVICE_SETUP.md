# 免费 API 申请与接入指引（2026-10-15 核查）

> 必须先确认本单位允许把**公网 FQDN 和公网 IP**发送给这些境外/外部第三方服务，核实服务条款、数据出境、网络出口与查询频率要求。禁止把内部源 IP、服务器名、业务路径、客户资料、业务 Token 或账户信息提交给第三方。

## A. 完全不需要注册、不需要密钥的来源

| 数据源 | 目标 | 官方/公开入口 | 本工具接入 | 局限 |
| --- | --- | --- | --- | --- |
| IANA RDAP bootstrap + 注册局 RDAP | 创建日期、到期日期、注册商、域名状态 | https://data.iana.org/rdap/dns.json / https://lookup.icann.org/ | 自动 | 注册人个人信息可能隐藏；不等于供应商归属证明 |
| DNS | 当前 A、AAAA、CNAME、NS | 系统 DNS 解析器 | 自动 | 内外网视图不同；不是 Passive DNS 历史 |
| RIPEstat Data API | IP 前缀、ASNs | https://stat.ripe.net/docs/data-api/api-endpoints/network-info | 自动 | 网络归属不是威胁信誉；有服务条款/频率限制 |
| crt.sh | CT 证书历史 | https://crt.sh/ | 自动 | 社区查询服务可能超时；证书历史不等于实时 TLS 校验 |

操作：无需申请 Key，直接运行 `python scripts/domain_audit.py audit --domain example.com`。

## B. 可选免费账户：AlienVault / LevelBlue OTX

**申请指引**

1. 打开 https://otx.alienvault.com/ ，使用单位允许的邮箱自行注册并完成邮箱验证。
2. 登录后打开 https://otx.alienvault.com/api/ ，找到 DirectConnect / API Key。
3. **不要在聊天中发送 Key**。运行 `python scripts/domain_audit.py init`，在隐藏输入提示中粘贴；或把 Key 写入本地 `.env` 的 `OTX_API_KEY=`。
4. 运行 `python scripts/domain_audit.py doctor --online` 检查 API 可用性；失败时检查认证和出口网络权限。

**只读 API**：

`GET https://otx.alienvault.com/api/v1/indicators/domain/{FQDN}/general`

HTTP Header：`X-OTX-API-KEY: <您的密钥>`

脚本使用 `pulse_info.count` 和少量 Pulse 标题作为调查线索，不将社区 Pulse 数量直接解释成恶意判断；不会上传情报、创建/提交 Pulse。

**许可要求**：OTX 被宣传为免费威胁情报社区；银行和机构应用仍须确认当期条款、API 可用性及配额，不能因为“免费注册”就假定可以无限量用于商业批量审批。

参考：
- https://otx.alienvault.com/
- https://otx.alienvault.com/api/
- https://github.com/AlienVault-OTX/OTX-Node-SDK
- https://www.cisa.gov/resources-tools/services/alien-labs-open-threat-exchange-otx

## C. 可选免费账户：urlscan.io

**申请指引**

1. 打开 https://urlscan.io/ 自行注册、登录并验证邮箱。
2. 在用户设置页的 API Keys 管理区域申请/查看 Key。具体账户界面可能更新，以官方文档为准：https://urlscan.io/docs/api/ 。
3. 用 `python scripts/domain_audit.py init` 保存至 `URLSCAN_API_KEY=`；不要在聊天中粘贴 Key。
4. `python scripts/domain_audit.py doctor --online` 检查当前 Key 及配额接口。

**本工具只使用历史搜索接口**：

`GET https://urlscan.io/api/v1/search/?q=(task.domain.keyword%3A%22example.com%22%20OR%20page.domain.keyword%3A%22example.com%22)&size=15`

HTTP Header：`api-key: <您的密钥>`

**不使用 Submission API**，不会让 urlscan 自动访问目标网站；因为提交扫描可能公开 URL、页面内容或请求记录。免费账户可能仅能查询较近的扫描历史；无历史记录不等于安全。

**商业与机构用途**：官方 FAQ 说明，企业将服务用于日常 SOC 调查/报告一般允许；大量批量查询或作为商业产品集成需要先联系官方确认免费层限额及适用条件。账号使用规则与配额随时可能变化。

参考：
- https://urlscan.io/docs/api/
- https://docs.urlscan.io/apis/urlscan-openapi/search/searchdatasource
- https://docs.urlscan.io/pages/search-api-reference
- https://urlscan.io/docs/faq/

## D. 只能由人工查询/核验的辅助网站

- Cisco Talos: https://talosintelligence.com/reputation_center/ （网页信誉调查入口；如有变化以官网为准）
- 微步在线情报社区: https://x.threatbook.com/ （具体可见数据、免费额度/商用权限以当前账户条款为准）

上述来源**本工具没有自动 API**，不要把人工尚未操作的结果写成“已查、无风险”。

## D2. 国内免费/限额情报交叉验证（默认网页人工操作）

详见 `DOMESTIC_INTEL.md`。微步 X 免费版提供基础网页查询但完整域名 API 不保证免费；奇安信与腾讯以当前开放功能和账号条款为准。本工具**没有未授权网站爬取能力**，使用 `--domestic-evidence` 本地导入安全人员的真实审查记录。

微步 API 官方端点 `https://api.threatbook.cn/v3/domain/query`（POST/GET），但只有账号**实际授予域名分析接口免费额度**、**取得机构用途授权**，再本地设置 `THREATBOOK_API_AUTHORIZED=yes` 和 `THREATBOOK_API_KEY` 才开启。密钥仅 HTTPS POST 表单传输，不存入日志或报告；如授权或额度不明确，则保持 `no`。

## E. VirusTotal Public API：仅个人非商业用途可申请（商业自动跳过）

**第一问必须是：本次是不是商业用途？**

包括银行、企业内部安全审查、外联准入、客户项目、商业产品/服务和日常业务工作流。**如果是或者无法确认，直接跳过 VT 注册、申请和后续 API 调用**。原因：VirusTotal 官方政策规定 Public API 不能用于商业产品或服务，也不能用于不贡献新文件的业务工作流；银行外联域名审查属于后者。商业用户无需注册 VT、也无需向本工具提供 VT Key；报告会保留 `sources.virustotal.status=skipped` 与合规原因。此规则不会影响 RDAP、DNS、RIPEstat、crt.sh、OTX 和 urlscan 的合法查询。

**若用户明确为个人非商业/学术研究**，可按以下步骤免费接入：

1. 打开 https://www.virustotal.com/ ，注册 VirusTotal Community，完成邮箱验证和登录。
2. 登录后到 https://www.virustotal.com/gui/my-apikey 获取个人 Public API Key。
3. 在 Skill 目录执行 `python scripts/domain_audit.py init --usage noncommercial`，通过终端隐藏输入 `VT_API_KEY`；如非交互环境，执行 `init --non-interactive --usage noncommercial` 再**本地**编辑 `.env`。
4. 执行 `python scripts/domain_audit.py doctor --online` 测试权限，然后 `audit --domain example.com` 查询现有域名报告。
5. Public API 当前官方标明 4 次/分钟、500 次/天，不得使用多个账号规避；具体额度以官方当期规定为准。查询的域名等 IoC 可能进入其数据集，禁止将内部/机密/个人敏感指标提交给外部服务。

**代码调用（仅非商业模式）**：

`GET https://www.virustotal.com/api/v3/domains/{FQDN}`；Header：`x-apikey: <Key>`。

本工具只查询已有分析，不上传样本、不提交 URL 扫描、不将 VT 检测为 0 解释为安全。不提供付费版接入；若银行必须使用 VT，须由单位独立采购并按合同许可另行开发。

官方依据：
- https://docs.virustotal.com/reference/public-vs-premium-api
- https://docs.virustotal.com/reference/getting-started
- https://docs.virustotal.com/reference/domain-info

**AbuseIPDB Free/Individual**：目前官网 Free/Individual 的许可不适合作为本银行商用免费 API 直接集成；因此本工具仍不接入。

官方：https://www.abuseipdb.com/legal.html

## F. 校验步骤

```bash
python scripts/domain_audit.py init --usage business  # 商业用途自动跳过 VirusTotal
python scripts/domain_audit.py doctor
python scripts/domain_audit.py doctor --online
python scripts/domain_audit.py audit --domain ifuwuyun.com
```

**受管网络环境建议**：第三方查询最好由获批的运维管理/情报查询节点执行，并设置允许的访问域名、出口审计和调用限额；不要直接从生产内网业务服务器运行此脚本。报告本地留存，不要外传包含内部业务背景的文档。


## v1.2 报告复核与历史比对

新版本不增加需要申请的 API。可以用 `--baseline <previous_report.json>` 比较前后 DNS IP、CNAME 和注册商；相关历史证据超过 90 天会提示“可能过时”，不是行业法定阈值。报告每个数据源均带有采集时间，与历史观测日期分开。对于机构使用，应确认当前每个免费平台的使用条款、数据披露限制和调用频率，而不能把免费账号等同于可合法自动化用于银行日常业务。

概念来源与官方文档：`OPEN_SOURCE_INSPIRATION.md`。VirusTotal 条款：https://docs.virustotal.com/reference/public-vs-premium-api 。urlscan API 文档：https://urlscan.io/docs/api/ 。
