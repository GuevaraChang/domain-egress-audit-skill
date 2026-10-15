# Domain Egress Audit Skill · 免费域名安全检查

只需输入一个域名，就能自动收集公开安全信息，并生成一份**普通人也能看懂的 HTML 报告**。不用填写表格，不用购买商业威胁情报服务。

## 直接开始

需要 Python 3.10+：

```bash
pip install -r requirements.txt
python scripts/domain_audit.py audit --domain example.com
```

**首次在交互终端运行**时，程序会主动引导你配置可选的免费威胁情报账号和 API Key。你可以先跳过，照样获得基础检测结果；之后执行 `python scripts/domain_audit.py setup` 继续配置。密钥只保存在本地 `.env`，绝不要提交到 Git。

检查完成后生成：

```text
reports/example.com_时间戳.html  ← 双击即可看结论
reports/example.com_时间戳.json  ← 原始证据，供程序读取
```

## 报告怎么看？

结论一共有四种：**发现严重风险**（不建议访问）、**发现可疑问题**（建议先核实）、**信息不足**（关键检查未完成）、**暂未发现明显风险**（可以谨慎访问）。报告首页会展示具体问题和建议，不必阅读安全术语；技术详情默认折叠。

[查看 HTML 演示模板](assets/DEMO_REPORT.html)。演示数据是合成的，不是对真实域名的检测结果。

## 数据源

| 数据源 | 账号 | 自动能力 |
|---|---|---|
| DNS、RDAP、RIPEstat、crt.sh | 不需要 | 注册信息、解析、网络归属、证书历史 |
| PhishShield、IPGuard | 不需要 | 自动下载静态名单，建立本地 IOC 库，进行精确匹配 |
| OTX | 免费账号 | 社区威胁情报关联 |
| urlscan.io | 免费账号 | 已有历史扫描结果（不提交新扫描） |
| VirusTotal | API Key | 获得符合条款的权限后查询既有域名检测结果 |
| 微步在线 | 需有域名分析 API 额度 | 可选威胁情报检查 |

不是所有免费网页平台都提供可自动调用的免费 API。没有接口的来源不会通过爬虫规避登录或配额限制。VirusTotal Public API 的免费使用范围有限制，配置向导会提示官方条款，只有确认符合条件才启用。

## 其他命令

```bash
# 随时补充和修改密钥
python scripts/domain_audit.py setup
# 检查密钥是否配置，并在线验证
python scripts/domain_audit.py doctor --online
# 自动化/CI 中取消首次交互提示
python scripts/domain_audit.py audit --domain example.com --no-prompt
# 添加旧版 Markdown 技术报告（默认不生成）
python scripts/domain_audit.py audit --domain example.com --markdown
# 显式更新本地安全规则
python scripts/domain_audit.py ioc-update
# 查看本地规则状态
python scripts/domain_audit.py ioc-status
```

默认只做只读的被动查询，不主动访问目标网站、运行端口或漏洞扫描，也不会自动修改任何访问权限。检测结果基于成功获得的数据，未命中不等于安全，查询失败会标注为未完成。更多配置说明见 [服务指南](references/SERVICE_SETUP.md)。

## 安全与隐私

- 仅输入公开域名（FQDN），不要传带账号或参数的 URL。
- `.env`、本地规则数据库及 `reports/` 已列入 `.gitignore`。
- HTML 不含外链脚本、外部图片或追踪服务；所有域名与证据文本都执行 HTML 转义。
- 你可以使用任何符合所在环境安全规定的网络连接；无法连接某个数据源时会在报告标明。

## 开发测试

```bash
python -m unittest discover -s tests -v
```

此工具是辅助查询，非安全承诺。所有外部威胁数据具有时间滞后或误报可能；请结合访问内容谨慎判断。
