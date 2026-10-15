# Domain Egress Audit Skill · 外联域名安全评估（v1.4，国内开源 IOC 本地库）

一个可直接用于兼容 `SKILL.md` 的 Agent Skills / Codex / Claude 类 Agent 的 `SKILL.md`，以及可独立运行的 Python CLI。工作流：**引导免费 API 申请 → 域名只读核查 → 自动出标准化 Markdown + JSON 证据报告**。

## 快速开始

要求 Python 3.10+，执行主机需要允许访问相应公开 HTTPS API（受单位网络管理制度约束）。

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/domain_audit.py ioc-update         # 首次拉取中国开源 IOC 到 SQLite（无需 Key）
python scripts/domain_audit.py ioc-status         # 验证规则库来源、许可、版本和完整性
python scripts/domain_audit.py init                # 先判断用途，商业默认自动跳过 VirusTotal
python scripts/domain_audit.py doctor
python scripts/domain_audit.py doctor --online
cp assets/business_context.example.json business_context.json
# Windows 可用：copy assets\business_context.example.json business_context.json
# 编辑 business_context.json：填写业务责任人、供应商、访问目标、数据风险、控制措施
python scripts/domain_audit.py audit --domain ifuwuyun.com --business-file business_context.json
```

重复审查时可以做基线对比：

```bash
python scripts/domain_audit.py audit --domain ifuwuyun.com \
  --business-file business_context.json \
  --baseline reports/ifuwuyun.com_上次报告时间.json
```

输出位置：`reports/ifuwuyun.com_<UTC时间>.md` 与 `.json`。`assets/DEMO_REPORT.md` 是**完全模拟、未联网**的格式样张，不能作为准入依据。没有任何 API Key 时依然可以生成报告；缺少的情报会明确标为 `not_configured`，不会被解释为安全。

**注意**：示例文件是未完成的上下文，不能直接作为银行外联审批证据。

## 新增：中国开源 IOC 本地规则库（v1.4）

评估前**单独**更新本地静态规则；`audit` **不会自动更新，也不会发送域名给 IOC 项目**。静态文件来自中国社区 GitHub 项目，并非微步/奇安信/腾讯的官方接口，也不是 DomainTools。

| 源 | 数据类型 | 免费/许可依据 | 自动规则 |
|---|---|---|---|
| **PhishShield** | 已整理的钓鱼候选域名 | 项目声明 MIT；需核实机构部署政策 | 默认尝试下载；JS 静态名单解析，格式变化则失败保留旧缓存 |
| **IPGuard** | 攻击来源 IP | 项目声明 CC BY 4.0；署名及保存注释 | 默认尝试下载；与申请域名当前解析 IP 比对，**弱关联** |
| **anti-AD** | 广告、追踪和隐私过滤域名，**不是恶意 IOC** | 项目声明 MIT，但聚合上游许可需进一步核实 | **默认关闭**；完成许可审核后可选加入 |

```bash
python scripts/domain_audit.py ioc-update
python scripts/domain_audit.py ioc-status
python scripts/domain_audit.py ioc-check --domain ifuwuyun.com  # 纯离线，不解析 DNS
python scripts/domain_audit.py ioc-check --domain ifuwuyun.com --ip 8.8.8.8 # 明确给出的公网 IP
# 机构核实聚合上游规则许可证后可选择添加非恶意类别：
python scripts/domain_audit.py ioc-update --include-adtracking --license-reviewed
# 隔离环境：由机构批准的渠道取得源文件并从本地导入（见 LOCAL_IOC.md）
python scripts/domain_audit.py ioc-import --feed cn_ipguard --file /safe/approved/blacklist.txt
```

规则缓存路径：`data/ioc_rules.sqlite3`，被 `.gitignore` 排除，不打包实际情报。数据源下载失败、格式错误或条数不足均保留旧缓存；超过 7 天视为过期，不当作实时安全证据。每次报告记录来源、 SHA256、许可、更新时间、命中类别、证据限制与待复核项。命中**永远不自动拦截/批准**。

**已完成离线单元测试；未从当前环境实测拉取全部三个真实上游。** 受网络出口、GitHub 可用性和上游格式变化影响，以第一次 `ioc-update` 的实际输出判断每个 feed 是否成功，不能把测试模拟数据当作真实情报。详细说明见 [`references/LOCAL_IOC.md`](references/LOCAL_IOC.md)。

## 免费服务/注册

- 不需要注册：IANA RDAP、系统 DNS、RIPEstat、crt.sh。
- 可选账号 Key：AlienVault OTX、urlscan.io（仅查询已有扫描；严格遵守使用限额）。
- 国内免费网页交叉验证：微步 X、奇安信、腾讯（功能/次数/商用权限以当前账户条款为准）；微步域名 API 额外授权确认，不保证免费。
- **VirusTotal Public API：新增“先判用途、再申请”的条件流程。** `init` 会先询问是否为银行/企业/商业业务：选“是”（默认）立即跳过 VT 注册和 Key 输入，`doctor --online` 和 `audit` 也**绝不请求 VT**，并把原因写入报告。只有明确选择个人/学术**非商业用途**，才提示免费注册并调用已有域名报告 API。
- 不包含：DomainTools 付费 Iris 数据、AbuseIPDB 免费个人版；不提供 VirusTotal 商用免费授权。
- 免费 ≠ 无限请求；**对机构/商业用途须先核实服务许可**。详细步骤见 `references/SERVICE_SETUP.md`。

## VirusTotal 用途开关（银行环境务必使用 business）

```bash
# 企业 / 银行 / 商业用途：默认模式，免费 VirusTotal API 直接跳过
python scripts/domain_audit.py init --usage business

# 无交互/Agent/CI：默认为 business，不会偷偷调用 VirusTotal
python scripts/domain_audit.py init --non-interactive

# 仅适用于明确合规的个人非商业/学术研究；首次注册见 references/SERVICE_SETUP.md
python scripts/domain_audit.py init --usage noncommercial
```

VirusTotal 官方禁止 Public API 用于商业产品或服务，以及不贡献新文件的业务工作流。银行外联准入属于此类场景，所以**即使填了 VT_API_KEY，程序也不会执行调用**。仅非商业场景才可按官网规则使用免费 API（目前官方文档列出 4 次/分钟、500 次/天；以官方最新规则为准）。报告内 `sources.virustotal.status=skipped`、`data.skip_reason=commercial_use_restriction`，以便审计。不要把用户业务 FQDN/URL/Token 提交给外部情报平台；公共 API 的域名查询指标可能加入 VT 数据集。

官方条款：https://docs.virustotal.com/reference/public-vs-premium-api

## 典型使用

```bash
# 首次初始化：用 getpass 隐藏 Key 输入，避免出现在终端回显中
python scripts/domain_audit.py init

# 不访问网络即可检查配置
python scripts/domain_audit.py doctor

# 获得单位网络许可后验证 API 连通性/Key
python scripts/domain_audit.py doctor --online

# 基础调查（不会访问目标域名对应的网站，不会执行端口扫描）
python scripts/domain_audit.py audit --domain ifuwuyun.com

# 业务资料补充后重新调查
python scripts/domain_audit.py audit --domain ifuwuyun.com --business-file business_context.json

# 严格需要审批同意后才能启用的 TLS 证书实时校验
python scripts/domain_audit.py audit --domain ifuwuyun.com --business-file business_context.json --tls-probe
```

## v1.3 新增：中国国内威胁情报交叉验证

新增三个**网页人工复核**来源：微步在线 X 情报社区、奇安信威胁情报中心、腾讯安全威胁情报中心。默认不抓取网页、不调用未授权 API；网页功能/限额视账户而定。

1. 登录各平台，核查**申请中的精确 FQDN**（不是注册域或共享 IP），保留截图或受控 ITSM 工单编号、日期、核查人；推荐至少两家。
2. 复制 `assets/domestic_evidence.example.json` 为 `domestic_evidence.json`，**将所有合成演示记录替换为真实记录**；没查的平台删除对应条目，不能勾选“无已知威胁”。记录 `verdict` 只能为 `malicious / suspicious / no_known_threat / inconclusive`。
3. 执行：

```bash
python scripts/domain_audit.py audit --domain ifuwuyun.com \
  --business-file business_context.json \
  --domestic-evidence domestic_evidence.json
```

输出报告新增国内交叉验证矩阵与证据编号，原始结果明确标注“人工填报、未由程序验证网页真伪”；不存在“多家都零命中就安全”的推导。微步域名分析 API **只有账户具有该接口的免费额度且允许本单位使用时**，本地设置 `THREATBOOK_API_AUTHORIZED=yes` 及 `THREATBOOK_API_KEY` 才会调用。`init` 不会诱导申请收费套餐；默认 `no`，永不调用该接口。详见 `references/DOMESTIC_INTEL.md`。

**报告遵守银行保密要求**：建议在批准的情报查询节点实施，检查是否允许将目标 FQDN 提交第三方；业务源/客户/传输参数留在内部。

## 既有 v1.2 更新（借鉴开源 Skill 的可审计设计）

1. **被动依赖资产清单**：从当前 DNS CNAME 和 urlscan 的历史终点抽取关联主机，仅做证据记录；只有请求中指定的 FQDN 在准入申请范围，其余条目不得自动查询、自动扩域或放通。`asset_inventory[*].in_approved_scope=false`。
2. **证据可追溯性**：`evidence_ledger` 为每个数据源赋予 `EV-01` 等证据编号，记录 `checked_at`、有则记录 `observed_at`、来源和解释限制；风险发现可引用 `evidence_ids` 并说明 `confidence`，避免“一段结论却没有证据”。
3. **时效与覆盖率**：`evidence_coverage` 显示 `ok / empty / error / not_configured / skipped` 分布，并提醒超过 90 天的第三方历史记录；这不是安全评分。
4. **历史快照对比**：可选 `--baseline` 对比历史 DNS IP 集合、CNAME、注册商；发现差异时阻止“直接进入审批”，需人工复核。查询失败不会自动生成变更告警。
5. **报告可直接关联 ITSM**：Markdown 适合审批阅读、JSON 适合下一步系统集成；本工具依旧不做自动授权、不访问目标网站、不提供恶意 0–100 分数。

参考设计来源与许可边界参见 `references/OPEN_SOURCE_INSPIRATION.md`。

## 范围与边界

- **绝无必须购买的 API**。但免费层并非无限量，也不保证机构商业使用获得授权；本单位审批前必须核实当期服务条款。

- 只允许输入 FQDN，不接受 URL/端口；避免暴露内部业务接口路径、Token 和客户参数。
- `business_context.json` 在本地读取并写入本地报告，不向第三方传输；报告本身可能含敏感业务信息，按内部制度保管。
- 当前 DNS 查询取决于**运行该程序的本地解析器视角**，不能当作公网多地解析结果。
- 注册域默认按常见域名后缀离线估算（例如 `.com`、`.com.cn`、`.co.uk`）；遇到特殊多级公共后缀时，务必核实并使用 `--registered-domain your.registered.domain` 指定，以防误查 RDAP/NS。
- RIPEstat 返回 IP 前缀和 ASN，并不是恶意信誉；证书透明度记录也不能证明当前 TLS 服务安全。
- 共享 CDN/云 IP 的恶意域名关联不能直接定性本域名恶意。
- 任何外部 API 断开或被限流，均记作异常/不完整，不会生成虚假的“安全”结论；VT 商业限制导致的 `skipped` 也不代表无风险。
- 如果 `business_context.json` 指定 `usage_type: "business"`，则即使本地误配置为 `VT_USAGE=noncommercial` 仍强制跳过 VT。
- 工具不做自动开通网络策略，不做渗透/漏洞扫描，不覆盖供应商身份认证、数据分级分类、银行内部审批。

## Skill 安装

把整个 `domain-egress-audit-skill` 文件夹放到 Agent 的 skills 目录，并按照所使用 Agent 的 Skills 发现方式启用（常见约定是读取目录中的 `SKILL.md`）。如果平台不支持 Skills，也可以直接使用 CLI。

## 开发自测

```bash
python -m unittest discover -s tests -v
```

仅包含本项目开发所需 Python 依赖；所有第三方数据端点均有各自的服务条款和可用性限制，无稳定性 SLA 承诺。
