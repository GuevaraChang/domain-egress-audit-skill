# Domain Safety Check · 域名安全检查 Skill

输入一个域名，自动查询 DNS、RDAP、IP/ASN、公开证书记录、网站历史扫描、免费开源本地 IOC 黑名单，以及已配置的 VirusTotal 域名信誉，并生成**中文单文件 HTML 报告**。适合普通用户快速识别可疑线索。

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
| anti-AD | 不需要，需确认聚合许可 | 可选广告追踪名单，不能用于恶意定性 |
| urlscan.io | 可选 | 已有的公开网页扫描历史，不主动提交网址 |
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

每次检查时自动查看规则库的更新时间；PhishShield 与 IPGuard 默认启用，过期 7 天时尝试自动更新。断网时使用现有缓存，并明确提示规则过期/缺失。anti-AD 只反映广告追踪过滤，不等同于恶意风险，需用户核实上游许可后主动启用。检查目标域名时不向开源名单服务器上传目标值。

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

默认仅查公开情报，不访问目标网站、不进行漏洞扫描。只有用户主动选择 `--tls-probe` 才尝试 TLS 连接。不会更改 DNS、防火墙或浏览器访问权限。

参见 [SKILL.md](SKILL.md) · [API 配置](references/SERVICE_SETUP.md) · [判断规则](references/RISK_RULES.md) · [开源 IOC](references/LOCAL_IOC.md)。
