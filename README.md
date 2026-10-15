# Domain Safety Check · 域名安全检查 Skill

输入一个域名，自动查询 DNS、RDAP、IP/ASN、公开证书记录、网站完整历史扫描记录摘要（urlscan 逐条详情）、免费开源本地 IOC 黑名单，以及已配置的 VirusTotal 域名信誉，并生成**中文单文件 HTML 报告**。适合普通用户快速识别可疑线索。

## 开始使用

Python 3.10+：

```bash
pip install -r requirements.txt
python scripts/domain_audit.py audit --domain example.com
```

首次在交互式终端运行时会引导配置可选 API。可直接跳过注册步骤，基础检查仍然执行。再次配置运行 `python scripts/domain_audit.py setup`。

| 数据源 | API Key | 用途 |
|---|---|---|
| DNS | 不需要 | 当前 A、AAAA、CNAME、NS 记录 |
| RDAP | 不需要 | 注册时间、状态、注册商 |
| RIPEstat | 不需要 | IP / ASN 归属（不是安全信誉） |
| crt.sh | 不需要 | 历史证书透明度记录 |
| PhishShield | 不需要 | 自动更新的公开钓鱼域名候选名单 |
| IPGuard | 不需要 | 自动更新的公开攻击 IP 名单（共享 IP 弱关联） |
| anti-AD | 不需要，需关注上游许可 | 默认检查广告追踪名单，不能用于恶意定性 |
| urlscan.io | 可选 | 默认查询现有历史记录，并逐条读取详细扫描结果；实时扫描需明确开启 |
| VirusTotal | 可选，须符合官方条款 | 多引擎域名威胁检测结果 |

**API Key 可以在对话中提供给具有本地文件权限的 Agent**，由其通过标准输入写入项目根目录 `.env`，例如：

```bash
python scripts/domain_audit.py set-key --name URLSCAN_API_KEY --stdin
python scripts/domain_audit.py set-key --name VT_API_KEY --stdin --vt-tier noncommercial
```

仅在确认授权符合 VirusTotal 官方要求后使用对应 `--vt-tier`。不要把 Key 当成命令行参数、放进公开仓库或写入报告。本地终端使用 `setup` 的隐藏输入更安全。

## 输出

执行完成后生成 `reports/域名_时间戳.html` 与同名 `.json`。打开 HTML 即可查看：**结论、发现的问题、已完成检查、未检查项目、建议**。技术细节默认折叠。

[演示报告](assets/DEMO_REPORT.html) 为虚构示例，不代表任何网站的实际检测结果。因未配置 API 或网络失败而缺少结果时，显示“信息不足”，不会误报安全。

## 开源安全名单（无需注册或 API Key）

每次检查时自动查看规则库的更新时间；PhishShield、IPGuard 与 anti-AD 默认启用，过期 7 天时尝试自动更新。断网时使用现有缓存，并明确提示规则过期/缺失。anti-AD 默认参与匹配但只反映广告追踪，不等同于恶意风险；使用者应遵守上游及聚合数据许可。检查目标域名时不向开源名单服务器上传目标值。

```bash
python scripts/domain_audit.py ioc-status
python scripts/domain_audit.py ioc-update
python scripts/domain_audit.py ioc-update --include-adtracking --license-reviewed
```

详见 [IOC 本地规则说明](references/LOCAL_IOC.md)。

## 常用命令

```bash
python scripts/domain_audit.py setup
python scripts/domain_audit.py doctor
python scripts/domain_audit.py doctor --online
python scripts/domain_audit.py audit --domain example.com --no-prompt
python -m unittest discover -s tests -v
```

**网站历史扫描：** 默认查询 urlscan 上账号可见的最近最多 **15 条**历史扫描，并逐条读取完整 Result JSON，提取历史页面标题、跳转、页面 IP、请求数量、第三方资源域名与历史恶意标记。网页截图只提供历史结果链接，不会下载内容或重新扫描。可通过 `--history-limit 30` 修改上限（最多 50；限额取决于账号，不能保证覆盖全部历史）。查不到记录不代表安全。

**实时网页扫描：** 默认关闭；仅在用户明确传入 `--live-scan` 时才向 urlscan 提交 `https://域名/`。默认使用 `private` 可见性，若免费账户不支持则报告失败，**不会私自改成 public**；用户确需公开扫描时才自行选择 `--live-visibility public`。远程扫描可能访问页面并将页面元数据传送至服务商，不要提交私人 URL。

```bash
python scripts/domain_audit.py audit --domain example.com                         # 默认历史扫描详细分析，实时网页扫描关闭
python scripts/domain_audit.py audit --domain example.com --history-limit 30      # 扩大历史详情数量（消耗更多配额）
python scripts/domain_audit.py audit --domain example.com --live-scan             # 显式启动远程实时网页扫描，private 优先
python scripts/domain_audit.py audit --domain example.com --no-tls-probe          # 关闭默认 TLS 连接
```

**TLS 实时握手与网页实时扫描不同**：TLS 只建立 HTTPS 证书握手，不下载网页，默认对公网解析地址开启；可通过 `--no-tls-probe` 关闭。不会执行漏洞扫描，也不会更改 DNS、防火墙或浏览器权限。

参见 [SKILL.md](SKILL.md) · [API 配置](references/SERVICE_SETUP.md) · [判断规则](references/RISK_RULES.md) · [开源 IOC](references/LOCAL_IOC.md)。
