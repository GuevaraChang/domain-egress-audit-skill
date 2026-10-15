# API 配置与注册

基础查询（DNS、RDAP、RIPEstat、crt.sh）无需注册。可选的两个 API：

## urlscan.io

1. 进入 https://urlscan.io/user/signup/ 注册账号。
2. 登录后进入 **Settings & API** 页面创建 API Key。
3. 在终端运行 `python scripts/domain_audit.py setup`，或将 Key 主动提供给有本地权限的 Agent，由其使用 `set-key --name URLSCAN_API_KEY --stdin` 保存。
4. 程序默认读取已有历史扫描，并在具备 Key、目标公网可达时默认提交一次 `https://域名/` 的 Private 远程扫描；若不希望第三方访问目标，执行 `audit --domain example.com --no-live-scan`。失败或额度不足在报告中标为未完成。

官方文档：https://docs.urlscan.io/guides/quickstart

## VirusTotal

1. 进入 https://www.virustotal.com/gui/join-us 注册账号。
2. 登录后打开 https://www.virustotal.com/gui/my-apikey 获取 API Key。
3. 确认 API 使用条款：免费 Public API 并不允许全部用途，已获得订阅授权时可选择 premium。
4. 使用 `setup` 或 Agent 的 `set-key --name VT_API_KEY --stdin --vt-tier noncommercial` / `--vt-tier premium` 保存，仅在用户确认符合条款后调用。

官方条款：https://docs.virustotal.com/reference/public-vs-premium-api

## 在会话中保存 Key

可以由有权限操作本地项目的 Agent 帮助完成，但不可把密钥放入命令行参数、输出日志、HTML/JSON 报告或版本管理。`.env` 已在 `.gitignore` 中排除，文件仅保存在本机。更安全的备选方式为 `setup` 隐藏输入。

```bash
python scripts/domain_audit.py doctor
python scripts/domain_audit.py doctor --online
python scripts/domain_audit.py audit --domain example.com
```

## urlscan 历史扫描详细分析

配置 `URLSCAN_API_KEY` 后，`audit` 默认先调用 `/api/v1/search/` 搜索已存在的记录，再用每条扫描的 UUID 调用 `/api/v1/result/{uuid}/` 读取扫描详情（默认最多 15 条；最多 50 条）。每条详细结果会消耗一次 Result API 配额；遇到 429 停止继续查询并报告“部分完成”，不要无限重试。

远程实时扫描默认开启，仅在用户已配置 urlscan Key 且目标有公网 IP 时尝试提交。默认提交可见性为 `private`；如果服务商因额度或权限拒绝，应提示用户，不自动改为 Public。可使用 `--no-live-scan` 关闭，或显式通过 `--live-visibility public` 请求公开扫描。免费账户的历史搜索可能仅覆盖最近 90 天；历史记录为空不代表安全。官方文档：https://urlscan.io/docs/api/ 。
