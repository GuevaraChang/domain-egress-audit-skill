## V2.4 — VirusTotal 同时读取域名对象与 URL 对象（修复漏报）

- **修复漏报**：原实现只查 `GET /v3/domains/{host}`（域名对象）。VT 的域名级与 URL 级判定是两个独立对象、独立扫描、独立统计，只查域名会**完全漏掉 URL 级报毒**。实测 `www.psbc.cn` 域名对象 malicious=0，而 URL 对象 `https://www.psbc.cn/` malicious=4（Netcraft、Webroot 报 Malicious，Emsisoft、Fortinet 报 Phishing），此前不可见。
- 新增 `GET /v3/urls/{sha256(scheme://host/)}` 读取 URL 对象既有判定；纯 GET，不提交任何新扫描。404 视为「无既有记录」并写入 `url_object_lookup`，不报错、不触发扫描。
- 结果结构新增 `domain_object` / `url_object`（各自含 `stats`、`flagged_engines`、`last_analysis_date`、`gui_url`），并保留 `combined_stats`（两对象逐项取较大值）兼容旧字段读取。
- 风险线索 `virustotal_detection` 按对象分别产出（带 `vt_scope: domain|url`），线索正文列出具体报毒引擎名与判定，便于区分类目型误报。
- 严重度分级：malicious≥5 记 high，1–4 记 medium；仅 suspicious 记 low。`report_html.summarize` 的 `intel_ok` 放宽为 `ok|partial`，避免 URL 对象查询失败时整份报告降级为“信息不足”。
- 新增 4 个测试：双对象分别命中、域名干净但 URL 报毒不被掩盖、URL 404 不算提交、评估阶段按对象分别出线索。全量 71 项测试通过。

## V2.3 — 取消实时网页扫描提交

- 移除 urlscan 实时提交实现及相关 CLI 选项；已有 Key 和历史空结果均不会触发新扫描。
- 保留历史查询、逐条详情分析、关联子域名补查、默认 TLS 检测及其余检测和配置。
- HTML/JSON/证据列表取消实时扫描来源；历史为空继续显示信息缺失，不视为安全。

## V2.2 — 默认 Private 实时扫描 + 历史扫描空结果诊断

- 已配置 urlscan Key 且目标解析为公网 IP 时，`audit --domain` 默认提交 Private 实时扫描；可使用 `--no-live-scan` 关闭，不会自动降级到 Public。
- 把本次实时扫描与历史扫描分别显示；实时结果处理中显示等待状态，失败则显示原因。
- 精确主机名无历史记录时，追加一次关联子域名搜索；有关联历史时明确区分“同一主机”和“关联子域名”，关联恶意记录不会直接定性当前主机。
- 报告显示免费账户历史范围限制（如 `search_date_limit_days: 90`）；零结果不等于安全。
- 真实 urlscan API 连通性、各账号实际额度需在有 Key 的环境联调。

## V2.1 — 网站历史扫描深度分析 + 实时扫描手动开关

- urlscan 历史扫描默认逐条读取完整 Result JSON 并提取页面标题、历史 IP、跨域跳转、外部资源、请求数、历史判恶标记和截图链接。
- 仅解析并保存安全相关的摘要，避免把历史页面的 Cookies / 请求头 / 访问 Token 等原始数据嵌入公开报告。
- 默认最近 15 条，最多 50 条（`--history-limit`）；配额受限、详情失败返回部分完成，不误报绿色安全。
- 新增 `--live-scan` / `--live-visibility`，默认不提交网站实时扫描；显式提交默认 Private，权限不足时禁止自动降级公开。
- HTML 报告增加易读的网站历史行为面板与证据链接。
- 保留上一个未发布开发阶段对 anti-AD 默认启用和 TLS 默认握手的改动；IOC 快照自动构建流程需在可联网环境完成实际数据更新。

## v1.9.0 — 恢复本地开源 IOC（2026-10-15）

- 修正 v1.8 删除范围过大的问题：重新接入 PhishShield、IPGuard 和可选 anti-AD 静态名单。
- 默认自动刷新可用名单（7 天）并保留离线 SQLite 缓存，新增本地命中与过期提示。
- HTML 重新显示本地名单检查，钓鱼域名精确命中和攻击 IP 弱关联分开判断。
- 保留已取消的 OTX、微步在线、奇安信及腾讯情报平台，不再申请其 API。
- 继续保留域名一键检查、API Key 对话配置与单文件 HTML 报告。

# Changelog

## v1.8.0 — 2026-10-15

- 精简为 DNS、RDAP、RIPEstat、crt.sh、urlscan.io、VirusTotal 六类公开数据源。
- 删除已废弃的所有地区专用情报集成、下载器、离线数据库与相关人工记录功能；对应 CLI 参数、测试、说明文件与报告字段一并清理。
- 保留首次可选 API 引导、对话式 Key 本地保存、一键检查、历史基线对比和单文件 HTML/JSON 报告。
- 缺少域名信誉查询不会被判定为“安全通过”。

## v1.6 — 2026-10-15

- 新增可读性更好的独立 HTML 报告、首次 API 配置引导与安全转义。

## Earlier releases

- 引入证据时间、历史比较、公开注册/解析/证书查询及 Python 自动化引擎。
