# 中国开源 IOC 静态情报源接入与许可说明（v1.4）

## 设计边界

- 所有规则由使用方在批准的网络出口**按需**下载到本地 SQLite；审查域名时不访问规则发布者的网站，不上传 FQDN、源系统等内部业务信息。
- 本地 IOC 来源限 `scripts/local_ioc.py:FEEDS` 事先确认的 HTTPS GitHub Raw 地址，下载不跟随重定向，有体积和最小条目校验；网络、许可或格式失败保留旧缓存，报告标记不足或过期。
- 检测不是漏洞扫描，也不对被评估外部站点发起连接；不做 DNS 自动封禁、RPZ 或防火墙下发。
- 规则库按下载时间计算“缓存新鲜度”，不掌握每个 IOC 的原始初次/最后观测时间；刚下载到旧 IOC 不代表其近日活跃。

## 三个中国社区公开源

| 源编号 | 官方公开仓库 | 数据 | 许可/注意 |
|---|---|---|---|
| `cn_phishshield` | https://github.com/Lu-yanmo/phishshield | `common/blacklist.js` 内钓鱼/欺诈域名表，精确 FQDN 作为候选 IOC。 | 仓库声明 MIT；脚本**不执行 JavaScript**，只静态解析受支持数组，格式变化会停止导入。不是威胁情报厂商的鉴证结论。 |
| `cn_ipguard` | https://github.com/chxovo/IPguard | `blacklist.txt` 中社区攻击来源 IP，包括注释。 | 仓库声明 CC BY 4.0；商业用途可按许可使用，需署名并保留攻击类型等注释。共享 CDN/云 IP 关联非常弱，不能推断目标域恶意。 |
| `cn_antiad` | https://github.com/privacy-protection-tools/anti-AD | `anti-ad-domains.txt` 中广告、追踪、隐私域名。 | 仓库声明 MIT，但清单系多来源聚合，**不自动推定所有上游允许商业再利用**。默认关闭，只有完成许可核查才允许启用。此类命中不是恶意域名 IOC。 |

不要使用路由分流名单、GFW 代理名单、广告黑名单命中来证明站点正在传播恶意软件；它们的标签语义不相同。

注意：三份名单的**代码/仓库许可与数据许可**要分别看待。新增来源、重新分发或对外发布合并列表之前，应由法务/采购/安全部门核实上游授权。此工具不提供法律意见，也不内置商业情报平台未授权抓取。

## 操作

```bash
# 只下载白名单登记的开源规则文件，无需 API Key
python scripts/domain_audit.py ioc-update
# 核对本地版本、数量、 SHA256 和许可
python scripts/domain_audit.py ioc-status
# 用本地库离线检查精确 FQDN
python scripts/domain_audit.py ioc-check --domain ifuwuyun.com
# 结合当前已知公网解析 IP，增加共享 IP 弱关联
python scripts/domain_audit.py ioc-check --domain ifuwuyun.com --ip 203.0.113.11
# 审核上游许可后再选择加入广告/追踪清单
python scripts/domain_audit.py ioc-update --include-adtracking --license-reviewed
# 银行合规环境可采用经过安全传递的本地文件导入
python scripts/domain_audit.py ioc-import --feed cn_ipguard --file /approved/blacklist.txt
# 整体报告会自动合并 local_ioc 到证据链与交叉矩阵
python scripts/domain_audit.py audit --domain ifuwuyun.com --business-file business_context.json
```

指定的 `--ip` 必须是实际核实过的公网 IP；不要手工填写上述示意用的文档保留地址作为真实结论。

## 风险判读

1. **PhishShield 精确 FQDN 候选 IOC**：中级待核查信号，必须检查原始归属、误报、情报时效；没有自动定罪。
2. **IPGuard 当前解析 IP 命中**：中级人工核查事项，低可信、共享 IP/CDN 不能归因给该域名。
3. **anti-AD 精确命中**：低级广告/跟踪上下文，不能作为恶意风险升级依据；可能是合理业务统计服务。
4. **未命中**：只表示这些时点与名单中无精确对应，不是安全/无风险。
5. **下载失败、未配置或超过 7 天**：报告列出证据缺口，不可当作阴性证据。
6. **多个来源同一 IOC**：可存在共用原始情报或重复转发；追溯原始事件，不按“2/3 多数表决”放行。开源清单不算奇安信/腾讯/微步等不同商业厂商。

## 错误处理和离线测试

首次执行 `ioc-update` 必须检查输出各源是否 `ok`、有效条数是否正常。系统当前开发环境无公网 DNS 出口，单元测试使用虚构的离线样本和模拟下载，不代表已经用这三家真实源成功联网。可以用 `python -m unittest discover -s tests -v` 检查代码逻辑。

下一步如要做正式银行审批，建议由单位安全部门增加有明确商用授权、带事件与观测时间的恶意域名/钓鱼 URL 来源，提高误报解释能力；**不能把公开源码平台与商业高级风险评分等同**。
