# V1.4 · 中国开源 IOC 本地情报引擎（2026-10-15）

- 新增 `scripts/local_ioc.py`，接入中文社区 PhishShield（钓鱼候选域名）、IPGuard（攻击 IP，弱关联），可选 anti-AD（广告/追踪，仅背景信息）。
- 引入本地 SQLite 精确匹配、来源元数据、规则 SHA256、下载时间与 7 天过期控制；更新失败保留原有规则。
- 新增 `ioc-update` / `ioc-status` / `ioc-check` / `ioc-import` 子命令；`audit` 只查本地数据库，不会查询域名到 feed 网站。
- 情报交叉验证区分原始来源组、子域精确匹配及共享 IP 弱关联；绝不做命中数投票放通。
- 许可证约束：anti-AD 默认关闭，须确认上游数据再利用许可；IPGuard 保留必要署名和原始注释。
- 更新标准化报告与 Agent 使用文档；离线回归测试覆盖格式异常、拒绝更新保留缓存、误报与时效判别。
- 未用真实公网 API/Feed 完成端到端联网测试；不对实时覆盖率和误报率作保证。

# 更新记录

## v1.3 · 2026-10-15

- 增加国内**微步 X、奇安信、腾讯安全**人工网页威胁情报交叉验证，及机器可读 `--domestic-evidence` JSON 输入和完整来源矩阵；查询仅限精确目标 FQDN。
- 微步 `v3/domain/query` 官方 API 为**可选且默认跳过**：只有用户实际获得域名接口免费额度与组织使用授权、显式设置 `THREATBOOK_API_AUTHORIZED=yes`、配置 Key 时才调用；使用 HTTPS POST 以免 Key 写入 URL/日志。
- 区分微步原生/奖励计划/转载情报，转载不得与 OTX 重复算独立证据；国内网页人工结果不可冒充 API 自动采集。
- 报告增加国内来源状态、判断、检查时间、截图/工单编号、命中复核待办；任何零命中不能自动放通。
- 提供 `references/DOMESTIC_INTEL.md` 和国内人工复核 JSON 示例；保留 VirusTotal 商业用途强制跳过机制。所有测试使用离线模拟，无真实 API Key 端到端验证。

## v1.2 · 2026-10-15

此次更新在保留“API 引导 → 校验 → 标准化报告”及商业场景跳过 VirusTotal Public API 的前提下，参考公开的 IOC Enrichment / Passive Recon / VirusTotal API Skill 做了原创增量实现。

- 新增 `asset_inventory`：申请 FQDN + 被动 CNAME/历史跳转依赖，带明确范围标记与归属未验证标签；不自动扩大查询范围。
- 新增 `evidence_ledger` 和 `evidence_coverage`：各来源的查询状态、检查时间、历史观察时间、来源链接与解释限制；历史情报超过 90 天提示时效性。
- 主要威胁发现补充 `evidence_ids` 与 `confidence` 字段以利报告回溯。
- 新增 `audit --baseline 上一次.json`：本地基线对比当前 IP 集合、CNAME 和注册商；变更触发人工复核，不能直接判恶意；两次数据均有效才对比。
- URLScan 历史跳转新增目标 hostname 差异识别；在线 doctor 修正 urlscan 配额检查路径；无时区原始时间按 UTC 解释。
- 更新 `SKILL.md`、`README.md`、审查规则、离线合成报告和开源设计来源说明。
- 自动化单元测试从 22 项增至 28 项，全部离线通过（不代表真实 API 联网验证）。

## v1.1 · 既有能力

- 免费数据源注册/配置、域名校验、MD/JSON 报告。
- VirusTotal Public API 仅在明确非商业用途下使用；银行/商业业务流程自动跳过。
