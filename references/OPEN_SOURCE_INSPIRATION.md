# 开源 Skill 借鉴清单与边界（2026-10-15）

本项目采用**功能和工作流启发，自己实现代码**的方式更新，无需运行或依赖下面的外部 Skill。下载与使用外部源码时另行遵守各仓库许可证和安全审查程序。

| 参考来源 | 已吸收的设计 | 本项目明确没有照搬的部分 |
| --- | --- | --- |
| [Performing IOC Enrichment Automation](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/skills/performing-ioc-enrichment-automation/SKILL.md) | 多源独立 enrichment；每个 IOC 结果附来源状态；多信号人工复核 | 没有其付费 Key 要求、简单 0–100 自动定性 / 自动阻断模型 |
| [Recon a Domain Passively](https://github.com/UseOSINT/Skills/blob/main/skills/recon-a-domain-passively/SKILL.md) | 先界定外联申请 FQDN 范围，最安静的证据先行；主机存在与主体归属分开；保留来源日期；限制被动 pivot 扩张 | 不进行全网子域枚举、代码搜索、扩大到关联公司、主动服务探测 |
| [VirusTotal API Skill](https://github.com/w33ts/virustotal-api-skill) | 有条件的 API Key 引导、用量意识、区分免费与企业 | 保留对商业/银行流程**彻底跳过免费 VT API**的门禁；不引入需要付费的 Premium API |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl) | 情报聚合接口与统一 JSON Schema 的潜在后续演进方向 | 没有把重量级服务、外部数据源的许可、管理平台要求带入当前轻量包 |

## 选择逻辑

1. **可审计优先于假精度**：不要给缺少数据的目标打“0 分安全”。提供 `evidence_ledger`, `evidence_coverage`, `finding.evidence_ids` 及源时间。
2. **关联 ≠ 归属 ≠ 恶意**：CNAME 指向和共享云 IP 可能属于 CDN/SaaS，历史 urlscan 页面可能早已失效。任何被动关联仅供人工复核，默认不扩大 FQDN 的准入审批范围。
3. **采集 ≠ 授权**：注册身份、网络技术和外联业务数据风险必须独立判断。**最终准入只由单位审批流程决定**。
4. **免费 ≠ 适用于商业**：VirusTotal Public API 明文限制商业产品/服务及部分业务工作流：<https://docs.virustotal.com/reference/public-vs-premium-api>；默认商业状态下所有 VT 请求直接禁止。OTX/urlscan 等服务应核实最新条款及配额，不能由“免费账号”推断银行业务使用权。
5. **最小披露**：仅在合规且获许可时，把外部公开 FQDN/IP 送往第三方 API；业务数据、内部主机名与认证凭据仅留在银行本地报告。
6. **限额与失败**：第三方服务可能发生限流、断网或字段变化；任何不完整结果一律记异常或 `empty`，不能伪造“正常”。上线前由银行依据服务条款决定是否启用、以及重试/缓存/排队策略。

## 未来可选增强（**本版尚未实现**）

- 统一 REST API 或 MCP / ITSM 封装、独立权限与审计身份。
- 自建被动 DNS 历史或合规商业情报（不属于“完全免费”范围）。
- 批量审查的速率队列/缓存与对账、经批准的网络出口代理集成。
- 企业证书指纹、业务数据出境规则的自动匹配。
