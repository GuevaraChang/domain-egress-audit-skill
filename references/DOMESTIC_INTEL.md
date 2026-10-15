# 中国国内免费域名威胁情报交叉验证 · 来源、权限与留痕

核查日期：2026-10-15。遵守**完全免费优先**：不要求订购套餐，不自动创建付费资源，不绕开平台授权抓取页面或非公开 API。网页的查询功能、数量限制、可用性及单位商用权限以登录页面和协议为准。

| 国内平台 | 官方入口 | 零付费可用范围 | Skill 接入状态 | 重要限制 |
|---|---|---|---|---|
| 微步在线 X 情报社区 | https://x.threatbook.com/ | 官网公布免费版提供基础安全情报网页查询，额度按当前套餐 | 人工核验 + 本地导入；域名分析 API 需许可与可用额度的额外确认 | 免费网页不保证 `v3/domain/query` 免费，个人 API 常见只给 IP 信誉等有限接口 |
| 奇安信威胁情报中心 | https://ti.qianxin.com/portal/ | 平台可申请账号，公开查询的可见字段/免费配额依账号开放情况 | 人工核验 + 本地导入 | 没有核实到稳定、公开可用于银行商业自动化的免费域名 API，不抓网站后台接口 |
| 腾讯安全威胁情报中心（TIX） | https://tix.qq.com/ | 提供威胁情报平台入口，实际网页检索功能和免费额度需账户确认 | 人工核验 + 本地导入 | 未核实可供银行自动化使用的免费域名 API，不冒称现成 API |

对 360：公开 `https://apt.360.net/` 是 APT 研究与报告资源，**不等于能对任意 FQDN 免费返回实时域名信誉的 API**；因此本版本不把 360 APT 查询算作自动域名信誉数据库。研究报告中明确列出的 IOC 可作为附加人工证据，但需证据原文与时间。阿里云 URL 风险检测目前官方明示为按量付费，故不集成。

## 1. 先询问用途与授权

- 只对**业务已申请的公网 FQDN**查询，禁止将内网主机名、服务器 IP、账户、Token、URL 路径、客户数据放入外部情报平台。
- 由单位判断是否允许第三方获得目标公网域名（可体现业务关系），境外平台还需按照本单位数据分类及跨境披露制度审查。
- 不是所有“免费注册”都给“免费 API 许可”。机构身份是否允许用个人免费额度，需要从用户协议/服务商处确认，不能自行假设。

## 2. 国内平台注册与查询操作（首次引导）

- **微步 X**：打开 https://x.threatbook.com/ → 页面提示注册/登录时使用本单位允许的账号 → 完成验证 → 搜索精确 FQDN → 查看当前账户的可用安全情报范围及免费配额 → 保存截图和查询时间。免费套餐介绍见 https://x.threatbook.com/v5/pricing?s=t 。如果希望申请域名 API，转到 https://x.threatbook.com/apiDocs/start/confirm_api_permissions 检查有无域名接口权限；默认个人有限免费额度可能只有 IP 信誉等，不要因注册成功就自动启用域名 API。
- **奇安信威胁情报中心**：打开 https://ti.qianxin.com/portal/ → 按页面指引注册/登录（可能跳转到 https://user.ti.qianxin.com/login/ ）→ 检查当前免费账户是否能查询指定域名的威胁标签和证据 → 记录原始证据。若当前账号不能免费查询，直接记录 `not_configured`，不购买、不尝试抓取非公开接口。
- **腾讯安全 TIX**：打开 https://tix.qq.com/ → 按页面实际开放方式登录或申请查询权限 → 判断是否能以零付费对 FQDN 进行威胁情报查询 → 如可查询则记录截图；若没有免费查询或要求企业采购，则跳过该平台，不虚构结果。

这三家只要求查询既有情报，不要求提交 URL 动态沙箱任务。各平台的注册步骤、登录验证及免费功能可能变化，**以实时官方页面为准**，不得声称已完成注册。

## 3. 人工复核标准化导入

1. 用已获单位授权的账号分别打开上述入口，查询精确申请 FQDN，留存页面截图到内部安全工单。
2. 每家记录 `verdict`：`malicious`（恶意标签命中、待复核）、`suspicious`（可疑）、`no_known_threat`（当时无已知恶意）或 `inconclusive`（无法确认）。无法登录或没有查询**不要伪造 no_known_threat**，删除该平台条目。
3. `checked_at` 要填写实际查询时间（ISO8601）、`reviewer` 为内部核查人、`evidence_ref` 是内部工单/截图编号、`notes` 写明情报源/原始观察日期/IOC 强关联情况。脚本不直接抓取网页，因此这些人工结论**未经程序独立核真**。
4. 复制 `assets/domestic_evidence.example.json` 至本地 `domestic_evidence.json` 并填入真实记录，在 `audit` 命令中传入 `--domestic-evidence domestic_evidence.json`。`target_fqdn` 以及所有 `queried_fqdn` 必须与申请中的 FQDN 完全一致。
5. 查询“无命中”并不自动转为低风险；多个平台可能转载同一 OTX/开源 IOC。**至少两家不同厂商供人工交叉验证**是工作建议，不是安全证明。

## 4. 微步域名 API（可选，默认不调用）

- 官方文档：https://x.threatbook.com/apiDocs/domain/query
- 权限/额度：https://x.threatbook.com/apiDocs/start/confirm_api_permissions
- 免费版网页权益：https://x.threatbook.com/v5/pricing?s=t
- 账号应先确认实际具备 `v3/domain/query` 接口权限、当前周期有免费调用额度，并获得适用于银行内部安全审查的机构授权。个人账号默认开通的有限免费 API 不能推定为域名分析接口。
- 在 Skill 本地 `.env` 设置 `THREATBOOK_API_AUTHORIZED=yes`、`THREATBOOK_API_KEY=<本地保管>`；默认为 `no`，**任何未授权或无配额情况自动跳过**。不为测试接口而强制扣费，不集成收费服务。
- 接口使用 HTTPS POST，不把 Key 放入 URL、Markdown、JSON 或控制台日志；只保存必要威胁标签、原始来源和观察时间，避免回传联系人或注册人个人信息。
- `intelligences.threatbook_lab` 与 `x_reward` 是供应商情报；`open_source` 为可能转载 OTX 等上游来源，不能把一家供应商聚合的三种来源视为“三家独立证据”。

## 5. 交叉验证推荐操作

1. 精确 FQDN 一致性验证；同时确认 URL/子域是否独立申请。
2. 确认标签是否来自**当前有效的恶意证据**，还是历史过期关联、共享 CDN IP、单次用户举报。
3. 多方命中：查是否同一个原始样本/事件/IOC 上游，记录来源独立性。不做简单加票。
4. 一方命中一方无命中：保留冲突，升级人工复核，不“少数服从多数”。
5. 实时数据/历史证据区分 checked_at 和原始观察时间；待查、错误、权限不符、查无记录不能标成安全。
6. 风险报告是**建议**，网络放通要另经业务必要性、供应商归属、数据安全与网络出口控制审批。

## 信息来源（官方）

- 微步 X 平台：https://x.threatbook.com/
- 微步 API 额度：https://x.threatbook.com/apiDocs/start/confirm_api_permissions
- 微步域名分析：https://x.threatbook.com/apiDocs/domain/query
- 微步免费套餐：https://x.threatbook.com/v5/pricing?s=t
- 奇安信公开平台：https://ti.qianxin.com/portal/
- 奇安信威胁情报平台介绍：https://www.qianxin.com/product/detail/pid/390
- 腾讯 TIX：https://tix.qq.com/
- 360 APT 报告中心：https://apt.360.net/Aboutus
- 阿里云 URL 风险接口按量收费：https://help.aliyun.com/zh/document_detail/2693366.html
