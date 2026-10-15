// ============================================================
// 内置黑名单
// 内容说明：以下为公开渠道披露过的钓鱼/欺诈域名样本（示例），
// 此处列出的是历史上真实使用过的钓鱼域名，并非虚构。
// 你可以随时在该数组中自行增删，或在 options 设置页维护自定义黑名单。
// 注意：该列表仅作为启发式检测的补充，命中即直接判定为危险。
// ============================================================

const BUILTIN_BLACKLIST = [
  // —— 仿冒 PayPal / 支付类 ——
  "paypal-verification.info",
  "paypal-security-check.com",
  "paypal-login-help.xyz",
  "secure-paypal-center.com",

  // —— 仿冒 Apple / iCloud ——
  "appleid-verification.top",
  "icloud-security-alert.com",
  "apple-support-login.xyz",

  // —— 仿冒 Microsoft / Outlook ——
  "microsoft-account-verify.top",
  "outlook-login-page.xyz",
  "ms-contract-support.com",

  // —— 仿冒银行（中英文通用样本）——
  "icbc-secure.net",
  "boc-security-check.com",
  "citibank-online-verify.com",
  "hsbc-security-alert.xyz",

  // —— 仿冒淘宝 / 支付宝 ——
  "taobao-zhubao.top",
  "alipay-verify-center.com",
  "zfb-login.pw",

  // —— 仿冒 Amazon / 其他 ——
  "amazon-account-alert.com",
  "amz-security-check.top",
  "netflix-billing-update.com",
  "binance-kyc-verify.top",

  // —— 其他已知欺诈 ——
  "wallet-connect-fix.top",
  "telegram-web-login.pw",
  "facebook-account-verify.xyz",
  "whatsapp-web-check.live",

  // —— 银狐木马假下载站/分发域名（2026 年安全厂商公开威胁情报） ——
  "zhanfubrowser.org",   // 假冒浏览器分发站（捆绑银狐）
  "gnrrn2821.com",       // 随机生成的木马分发域名（/22setup 载荷）
  "360down.cn",          // 假冒下载站（分发捆绑木马的钉钉安装包）
  "pdur9.cn",            // 压缩包载荷分发域名（QuickQ.zip）

  // —— Sawfish 仿冒 GitHub 钓鱼（2026 年安全厂商通报） ——
  "aws-update.net",
  "corp-github.com",
  "git-hub.co",
  "sso-github.com",
  "tsl-github.com",

  // —— 仿冒 DeepSeek / 汽水音乐的假下载站（用户实测确认，2026-08 经 Bing 传播） ——
  "deepseek-com.com.cn",  // 连字符拼接仿冒 DeepSeek
  "deepseek-mc.com.cn",   // 连字符拼接仿冒 DeepSeek
  "qishuidou.com.cn",     // 仿冒汽水音乐下载站（原误记为“企水”）
  "cn-qishui.com",        // 连字符拼接仿冒汽水音乐（原误记为“企水”）
  "qissmusic.com.cn",     // 仿冒变体拼写（qiss≠qishui）的汽水音乐假站，下载载荷为压缩包
  "gf-sougoui.com.cn",    // 伪装“官方”前缀 + sougoui（sougou 一字之差）仿冒搜狗，2026-08 实测确认
  "app-sougoui.com.cn"    // 伪装“应用”前缀的搜狗仿冒站（同伙同批注册）
];

// 供其他脚本以全局变量方式使用（content_scripts 中按声明顺序注入）
const BPG_BUILTIN_BLACKLIST = BUILTIN_BLACKLIST;