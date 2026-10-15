---
name: domain-egress-audit
description: 当用户想确认一个互联网外部域名是否适合企业/银行内网服务器访问、想申请配置免费威胁情报 API、检查域名注册信息/DNS/ASN/历史扫描，或需要生成外联域名准入评估报告时，按三阶段操作。严格区分威胁情报和访问授权，不得自动放通。
---

# Domain Egress Audit Skill · 互联网外联域名安全评估（v1.5）

## 职责与原则

这个 Skill 帮助网络/DNS/安全运维人员完成 **直接输入域名 → 自动选择免费且获许可的数据源 → 自动更新 IOC → 自动出具机器可读及 Markdown 报告**。面向企业及银行网络外联审批，以**人工复核和最小权限准入**为最终控制点。

- **不需要付费 API**。无账号可执行 RDAP、DNS、RIPEstat、crt.sh；可选接入 OTX、urlscan.io 免费额度内的 API。保留国内微步 X、奇安信、腾讯安全人工情报交叉核验及有权才接入的微步 API；新增中国开源社区 IOC 本地 SQLite 规则库（先下载，后纯离线匹配）。商业/机构使用应事先核实各平台条款、查询合规和跨境披露要求。
- **VirusTotal 条件接入**：先核实用途，`business`（银行/企业/商用/客户项目）下**自动跳过注册、Key 配置及全部 VT 网络请求**，说明官方条款限制；仅明确为合规个人非商业用途时允许使用 VirusTotal Public API。仍不集成 AbuseIPDB 免费个人版。
- 即使用户已经配置 `VT_API_KEY`，当 `VT_USAGE=business` 或业务背景 `usage_type=business` 时，**不可通过 doctor/audit 绕过限制**。无法确认用途时默认 `business`，自动跳过 VT。
- 不要声称 DomainTools 官方评分、VirusTotal 实时评分或完整 Passive DNS 已得到，除非用户确实提供相应证据。
- **所有外部查询只包含公网域名或公网 IP**；不要向第三方提交内部 IP、服务器名、账号密码、客户数据、Token、带业务参数的 URL。业务上下文文件只保存在本地。
- **默认只读、限定范围**。只评估申请中的一个 FQDN；CNAME、历史跳转域名只作为依赖线索，不自动追加查询对象或白名单。禁止自动提交 urlscan 扫描、访问目标网站、执行漏洞扫描、绕过策略或修改防火墙。TLS 检查只有得到用户明确授权时才追加 `--tls-probe`，并且仅连接解析出的公网 IP。
- 不得将 `not_configured`、`error`、`empty` 或情报零命中转换为“安全”。关联恶意 IP/OTX Pulse 仅是调查线索，不构成独立恶意定性。
- 不论得分/标签如何，**本 Skill 永远不自动批准域名访问**。最终需要业务、安全、数据合规与网络审批。

## 识别触发意图

当用户说「审核域名」「外联域名安全验证」「外网白名单准入」「帮我判断 ifuwuyun.com 能否放通」「引导注册威胁情报 API」「输出标准化评估报告」等，采用以下阶段。用户已经完成上一步时直接进入下一阶段，不重复询问。


## 优先路径：无人值守全流程（默认，无需人工填写任何 JSON）

用户只需要提供一个具体公网 FQDN。**立刻执行**（若执行环境支持），不用等待注册、人工创建 `business_context.json`、填国内网页证据或人工完成 `ioc-update`：

```bash
pip install -r requirements.txt
python scripts/domain_audit.py audit --domain ifuwuyun.com
```

`audit` 默认执行：检查本地开源 IOC 缓存是否缺失或超过 7 天，自动更新允许的两项静态 feed（不上传目标域名）；调用无需 Key 的 RDAP/DNS/RIPEstat/crt.sh，以及已经配置并有许可的可选 API；读取已有 IOC 缓存；自动查找同一域名最近一份报告作为历史基线；生成 `reports/*.json` 和 `*.md` 并返回**自动技术结论**。无任何交互 `input()`，运行异常或缺失的可选源必须进入报告，不能声称检查成功。`init` 和 Key 申请只在用户需要更多情报覆盖时主动引导，非运行前置条件。默认模式 `business`，商业用途 VT 免费 API 永远跳过。

`business_context.json` 原本是源服务器、数据类型、访问目的、供应商等内部业务审批证据。**现在完全可选**，不需要新建。未提供时 `data_classification=unknown`，内部数据/业务归属明确为 `not_assessed`，不能凭公网域名技术结果生成准入许可。用户要求无人值守意味着**自动生成报告**，并不意味着安全地自动开启银行防火墙、代理或 DNS 白名单。

对未授权主动网络连接的目标默认不使用 `--tls-probe`；可执行本地只读和第三方历史情报调查。所有可选来源因许可不明会安全跳过，而不是绕过网站的人工验证或服务条款。仅当用户**明确要求申请 API**时执行下面的配置引导阶段。

## 第一步（可选）：引导用户注册和申请免费 API

**Agent 对话行为（用户明确希望申请 API 时）**：首先询问「本次是否属于银行、企业、商业产品/服务、客户项目或日常业务审批/安全运营？」**默认答案为“是（business）”**。无交互输入时同样认定 `business`。解释 VT 免费 Public API 不允许用于商业产品/服务及不贡献新文件的业务工作流：若为商业用途，**自动跳过 VirusTotal 注册申请与 Key 获取，不要向用户索取 VT Key，并且在后续校验中不调用 VT**。不影响其他免费数据源。只有用户明确选择合规的个人非商业用途，才提供 VT 的免费申请页面；然后告知无密钥工具与 OTX、urlscan 两个可选 Key，明确“注册与邮箱验证由用户本人操作”。随后给出 `init` 的本地配置命令。用户没有取得密钥时直接按默认无人值守路径审查，绝不因此停留或等待人工。绝不索取用户把真实 Key 粘贴到聊天中。

1. 先告知用户：**零密钥也可开始**，基础数据来源是 IANA RDAP、DNS、RIPEstat、crt.sh。说明这只是基础技术检查，不足以自动证明域名安全。
2. **VirusTotal 用途分流（优先执行）**：
   - 商业/银行：解释条款后立即跳过 VT 账号及 API 申请，`VT_USAGE=business`，`VT_API_KEY` 留空；不得调用其 Public API。银行评估中这是一项**合规跳过**，不是“未发现恶意”。
   - 个人明确非商业：告知 VirusTotal Public API 免费但有限额（4 次/分钟、500 次/天）；指导用户打开 https://www.virustotal.com/ 注册、验证邮箱，并到 https://www.virustotal.com/gui/my-apikey 获取 Key。仅通过本地隐藏输入保存，不应发送到聊天。非商业模式使用现有分析 `GET /api/v3/domains/{domain}`，绝不提交扫描或文件。
   - 条款：https://docs.virustotal.com/reference/public-vs-premium-api ，详见 `references/SERVICE_SETUP.md`；如果对商业定义有疑问，**先跳过 VT**。
3. 引导用户注册 **OTX**（https://otx.alienvault.com/）并取得 DirectConnect API Key（登录后 https://otx.alienvault.com/api/）；引导注册 **urlscan.io**（https://urlscan.io/），验证邮箱并在账户界面创建 API Key（https://urlscan.io/docs/api/）。注册/验证必须由用户自行完成；不要代替用户声称已开通。
4. **国内威胁情报平台（网页及官方 API）**：
   - 微步在线 X 情报社区 https://x.threatbook.com/ ：平台提供免费基础网页查询；按当前账号显示额度操作。登录后检索**精确 FQDN**，保存显示的情报标签、截图/工单引用和查询日期；免费网页 ≠ 免费域名分析 API。
   - 奇安信威胁情报中心 https://ti.qianxin.com/portal/ ：根据公开网页和账号实际可用能力人工查询；未知免费次数及企业授权，不应自动化抓取网站或谎称免费 API。
   - 腾讯安全威胁情报中心 https://tix.qq.com/ ：依据当前站点及账号权限人工核查；免费查询内容/次数需当场确认，不预设全部开放。
   - 建议至少在**两家不同厂商**做交叉检查；不同厂商可能引用同一上游原始 IOC，不能视为两次独立确认。未查询平台标记为 `not_configured`。
   - 微步正式文档提供 `https://api.threatbook.cn/v3/domain/query`：申请免费账号不等于拥有免费域名分析调用权限；需要核实账号该接口免费配额及机构商用许可。**默认不调用**；只有真实授权且本地手工设置 `THREATBOOK_API_AUTHORIZED=yes` 并配置 Key 后才会调用，不能用试用名义突破商业许可。详见 `references/DOMESTIC_INTEL.md`。
5. **中国免费本地 IOC 规则库（v1.4）**：引导用户在本机、获批准的联网环境执行 `python scripts/domain_audit.py ioc-update`，只下载审核过的**静态公开规则文件**到 `data/ioc_rules.sqlite3`。不需要注册 Key，也不会上传待审查域名、IP 或业务上下文。默认尝试两个来源：
   - `cn_phishshield`：中文社区 PhishShield 仓库的本地钓鱼候选域名名单（项目 MIT）；精确 FQDN 命中才算待核查钓鱼线索。上游是 JavaScript，程序只静态读取名单常量，不执行 JS；若文件格式不匹配，更新报错并保留旧缓存，不能声称更新成功。
   - `cn_ipguard`：中国社区 IPGuard 的攻击来源 IP 名单（项目声明 CC BY 4.0，须署名保留注释）；仅与当前解析公网 IP **精确**匹配。共享云 IP、CDN 命中是弱关联，不证明域名恶意。
   - `cn_antiad`：中文 anti-AD 广告/追踪/隐私域名表。**不是恶意域名黑名单，不应计入恶意证据**；其代码仓库 MIT，但列表来自多个上游，机构需再确认这些数据的许可。故默认不下载，仅在机构确认条件后使用 `ioc-update --include-adtracking --license-reviewed`；命中只能作为广告/跟踪上下文。
   - 下载地址固定在 `scripts/local_ioc.py` 的 `FEEDS` allowlist 中，不允许用户任意填 URL 让脚本抓取；只接受 HTTPS，限制单源大小，超时/格式异常/条数异常后保留之前有效缓存。
   - 先 `ioc-status` 查看来源/数量/下载时间/SHA256/许可证。离线 `ioc-check --domain ifuwuyun.com` 可单独校验 FQDN；也可附 `--ip` 校验已获授权的公网 IP。未知或超过 7 天的缓存不构成“零风险”。
   - 无直接 GitHub 出口时：由获批准机器下载清单，经机构既定安全传递流程导入 `ioc-import --feed cn_ipguard --file ...`；**不得绕过机构网络控制**。基础审查仍可进行，但报告必须标明“本地 IOC 未配置/已过期”。
   - 具体来源、许可证、交叉验证限定、维护方法：`references/LOCAL_IOC.md`。
6. 对 urlscan 说明：本 Skill **仅 Search API 检索既有公开扫描记录，永不提交网站扫描任务**；免费层有频率、查询范围和使用条款限制。对 OTX 说明：Pulse 是社区线索，非官方恶意结论；银行商业使用仍须核验许可。
7. 用户不必在聊天中发送密钥。指导用户在 Skill 文件夹执行：

   ```bash
   python scripts/domain_audit.py init --usage business      # 银行/企业/商业用途，默认自动跳过 VT
   # 个人确属非商业用途时可改为 init --usage noncommercial
   ```

   CLI 会隐藏输入并将密钥写入本地 `.env`（可跳过、稍后填写；`.gitignore` 已忽略此文件）。容器/非交互环境可执行 `init --non-interactive` 后本地编辑 `.env`。
8. 使用 `python scripts/domain_audit.py doctor` 验证本地配置；获准联外后执行 `python scripts/domain_audit.py doctor --online` 验证访问权限和 Key 是否可用。无法连通时先排查访问代理/网络权限，**不要**要求粘贴密钥。
9. 查阅 `references/SERVICE_SETUP.md` 中明确的服务路径、收费/授权注意事项。**账号申请未完成、无互联网权限时允许跳过**，报告应如实体现证据缺口。

## 第二步：直接对域名自动执行校验（不需先配置）

**Agent 对话行为（配置后）**：从用户输入中取得准确的目标 FQDN（如果用户说的是“`ifuwuyun.com`”，以该值审查，不擅自扩展到所有子域）；确认 API 检查 `doctor` 正常或注明限制；收集本地业务上下文。具备可用的执行环境时运行命令；不能运行代码/没有互联网权限时，说明未实际验证并给出用户可复制的本地运行命令。禁止编造实时 DNS、WHOIS、风险评分。

1. 取得**确切 FQDN**，例如 `api.vendor.example`；不要只以二级注册域推断所有子域安全。域名与端口、CNAME、实际访问目标均需审查。
2. 对常见后缀脚本离线估算注册域；如是特殊多级后缀，先核实注册域并传入 `--registered-domain`，避免误判。询问或使用用户提供的业务上下文：源系统、外部服务商及域名归属证明、访问用途、协议和端口、是否上传数据、数据分类、代理/白名单/日志控制、业务及数据安全审批。业务上下文是可选资料，不需要自动创建或填写 `business_context.json`。缺少的信息报告标为 `unknown/not_assessed`；不得向威胁情报接口发送内部资料。
3. 执行：

   ```bash
   python scripts/domain_audit.py audit --domain ifuwuyun.com
   ```

   默认无需 `--business-file`，能得到自动技术评估结果；业务与准入授权维度必须明确 **not_assessed/not_granted**，不假装已获授权。
4. 默认执行的免费检查：
   - 通过 IANA RDAP bootstrap 取得注册局 RDAP（创建日期、注册商、到期时间、域名状态）。
   - 当前主机本地 DNS 解析（A、AAAA、CNAME、NS；注意 split-horizon 和递归解析器视角）。
   - 针对最多 4 个解析 IP 查询 RIPEstat 网络前缀/ASN（该结果不是安全信誉评分）。
   - 查询 crt.sh 公开 CT 证书历史（不代表当前服务证书有效）。
   - 如已配置 Key，查询 OTX 域名 Pulse 关联、urlscan 已有历史扫描；只采集摘要和证据 URL。
   - **本地 IOC 精确匹配（v1.4，自动）**：脚本先在需要时自动下载/刷新默认允许的静态规则，再读取本地 SQLite 快照；区分钓鱼候选、解析 IP 弱关联、广告/跟踪上下文，输出 `sources.local_ioc`。默认报告有更新时间、哈希、数据类别、匹配强弱、是否过期和授权说明；没有缓存/更新失败不能判定未命中。
   - **国内交叉核验**：`--domestic-evidence assets/domestic_evidence.example.json` 加载业务方/安全人员**人工查询结果**；CLI 只验证结构、精确 FQDN、核查时间和证据引用，并合并成跨平台风险矩阵，不会抓取网页。示例 JSON 是合成模板，**不能用作真实审批凭据**。银行使用时编辑为真实证据放在受控路径。
   - **微步域名 API（可选）**：默认不调用；当用户明确核实接口可用免费额度及机构使用许可并本地配置 Key + 授权开关时，才会将精确公网 FQDN 发往官方接口。微步实验室/奖励情报与转载开源情报分开，不能把转载 OTX 再算作一条独立来源。
   - **仅 `VT_USAGE=noncommercial` 且业务上下文未声明商业用途，且 VT Key 已配置**时，调用 VirusTotal v3 域名现有检测报告，获取恶意/可疑统计；其他情况明确记录 `skipped` / `not_configured` 而不请求 VT。用户选择银行或商业用途时无论有没有 VT Key 都必须跳过。
5. 对**已获得明确授权**的目标，可执行 `--tls-probe`（主动 TCP/TLS 连接）；不得对私网/非全局地址开展主动访问。默认不开启。
6. 按 **由便宜、安静到昂贵** 的固定次序组织证据：注册与 DNS → 当前 IP/ASN → 证书历史 → 可选第三方威胁情报/历史扫描 → 业务准入；不主动递归扩展其他站点。将 CNAME、历史外站跳转加入被动关联资产清单，不视为本申请自动批准的目标。
7. 严格区分 **检查时间 `checked_at`** 与原始记录的 **观察时间 `observed_at`**，并对超过 90 天的历史网站扫描、证书或 VT 记录提示“可能过时”。证据可信度与恶意风险级别分开；共享 IP/CDN 关联不等于所有权或恶意证据。
8. 已有上一次本地 JSON 报告时，使用 `--baseline` 对比 IP、CNAME 与注册商变化。变更仅表示需要核查，**不能自动定性为攻击**；查询失败不应被误判为基础设施变化。
9. 若 DNS 与业务方声明的访问主机不一致、实际跳转涉及其他域名、缺少供应商确认或数据分类不明，记录为需复核，不自动放通。详细规则参见 `references/RISK_RULES.md`。

## 第三步：根据结果生成标准化验证报告

**Agent 对话行为（完成采集后）**：只使用 CLI 真实返回的 JSON 证据填报，严格列出每个数据源的成功/失败/未配置、查询时间、原始证据链接；依据规则输出“风险信号判断”与“准入审批建议”两项独立结论。不可因无恶意命中而认定安全。最后交付机器技术结论、真实缺口及报告文件，不额外要求用户填报人工网页情报；不自动执行防火墙策略。

1. CLI 自动在 `reports/` 生成同名 **Markdown 审查报告 + JSON 原始结构化证据**（schema v1.5）。输出增加 `evidence_ledger`（来源编号、状态、检查/观察时间、解释限制）、`evidence_coverage`（完整性和过时警示）、`asset_inventory`（被动发现的依赖主机及归属置信度）和可选 `baseline_comparison`（历史差异），并保留审批意见与人工签字栏。
2. 对国内情报使用 `domestic_cross_validation.matrix[]` 展示**微步 X、奇安信、腾讯及已缓存的开源 IOC feed**来源状态、原始判断、复核时间和证据引用；一方命中另一方未命中、网页无结果或来源疑似共享时，提示安全人员调查，绝不自动“投票放通”。
3. 审查本地 IOC 的 `feed_updated_at`、`stale`、`origin_group` 和精确 FQDN/共享 IP 匹配类型，区分本地规则**是否加载成功**与**是否命中**。不能把 PhishShield + anti-AD + IPGuard 直接当作三家独立恶意厂商。
4. 审查每个数据源的 `status`：`ok` / `empty` / `error` / `not_configured` / `skipped`。不得把查询失败当作零命中；证据来源与时间必须保留。
5. 明确披露 VirusTotal 的查询状态：商业使用报告里需写「根据 VirusTotal Public API 使用许可限制，已自动跳过，未执行查询」，不得将其计为零风险；非商业查询的恶意/可疑计数需要人工核对检测引擎、记录时间和误报风险。
6. 遵照 `references/RISK_RULES.md` 输出 **风险信号级别（高/中/低/未触发）** 与 **可否进入审批** 两个独立结论。每条发现尽量附带 `evidence_ids`、`confidence`，确保调查人员能从风险信号回溯原始数据；不得输出「百分百安全」「已自动准入」。
7. 如果业务方提供的资料不充分，报告中的“待补充证据”保持未完成；提醒用户在 Talos/微步等可被单位授权的平台手工核查、核验域名归属证明。
8. 用户需要对领导/安全审批提交报告时，优先交付 Markdown/JSON 文件或依据模板粘贴的摘要；如需 PDF、Word，再明确另行转换。

## 实操命令

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/domain_audit.py ioc-update  # 首次下载国内 IOC；只读公开列表，不上传待查域名
python scripts/domain_audit.py ioc-status
python scripts/domain_audit.py init
python scripts/domain_audit.py doctor --online
python scripts/domain_audit.py audit --domain ifuwuyun.com --domestic-evidence domestic_evidence.json
# 复核：与上一次本地 JSON 结果进行非恶意定性的差异对比
# python scripts/domain_audit.py audit --domain ifuwuyun.com --baseline reports/上次的报告.json
# 主动探测必须获授权（否则不要加）：
# python scripts/domain_audit.py audit --domain ifuwuyun.com --tls-probe
```

运行前请阅读 `README.md`、`references/SERVICE_SETUP.md`。本项目是审核辅助工具，不替代银行网络准入、安全、数据保护和第三方供应商管理制度。

## 已借鉴的开源 Skill 设计要点（原创实现）

- **Performing IOC Enrichment Automation**：借鉴多源 IOC 标准化与证据复核，而非照搬以打分自动封禁的策略；每个来源独立记录状态，不能把 `skipped` 计成零风险。
- **Recon a Domain Passively**：借鉴“先界定边界、按依赖次序调查、主体归属和主机存在分别评价、每条记录保留时间来源”的方法；默认绝不进入主动探测与子域扩张。
- **VirusTotal API Skill**：借鉴 Key 引导、配额意识和免费/企业用途差别；银行场景始终保留自动跳过 VT 免费 API 的强制门禁。
- **IntelOwl**：仅借鉴未来可以接入统一情报适配器的架构思想；当前项目仍是纯轻量 Python、本地只读、无需部署 IntelOwl。

详见 `references/OPEN_SOURCE_INSPIRATION.md`。这些外部 Skill 只是设计参考，当前包不是它们的 fork，未复制第三方源码。
