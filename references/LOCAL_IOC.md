# 免费本地安全名单

`audit` 会自动检查是否需要更新本地 SQLite 缓存，**不需要手工运行更新命令**。静态规则文件下载不会上传待检测域名。

| 来源 | 主要用途 | 默认 |
|---|---|---|
| PhishShield | 钓鱼与仿冒域名候选名单 | 开启 |
| IPGuard | 攻击来源 IP（用于查询当前解析 IP 的弱关联） | 开启 |
| anti-AD | 广告、追踪过滤域名；不是恶意情报证明 | 关闭 |

公开规则可能有误报、滞后、格式变化或来源转载。缓存超过 7 天，报告会提示可能过期。更新失败时保留既有缓存，不把不存在的数据计为“没有问题”。共享主机/IP 命中不能证明该域名恶意。

```bash
python scripts/domain_audit.py ioc-status
python scripts/domain_audit.py ioc-update
python scripts/domain_audit.py ioc-check --domain example.com
```

可选广告/追踪规则需要先核实聚合名单的上游许可，才能使用 `ioc-update --include-adtracking --license-reviewed`。隔离环境允许 `ioc-import --feed cn_ipguard --file 已合法取得的本地名单`。所有下载源都来自代码内固定 allowlist；导入前要留意数据格式与许可证。
