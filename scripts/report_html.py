"""Plain-language standalone HTML report. No JavaScript, external assets, or tracking."""
from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

SOURCE_NAMES = {
    'rdap': '域名注册信息', 'dns': 'DNS 解析', 'ripestat': 'IP / 服务器归属',
    'crtsh': '网站证书历史', 'otx': 'OTX 威胁情报', 'urlscan': '网站历史扫描',
    'virustotal': 'VirusTotal 安全检测', 'tls': 'HTTPS 连接测试',
    'threatbook_api': '微步威胁情报', 'local_ioc': '开源安全名单',
    'threatbook_x_manual': '微步网页人工记录',
    'qianxin_ti_manual': '奇安信网页人工记录',
    'tencent_tix_manual': '腾讯安全网页人工记录',
}

def esc(value):
    return html.escape(str(value if value is not None else '—'), quote=True)


def summarize(report):
    """Verdict applies ONLY to evidence acquired. Missing is not passed."""
    findings = (report.get('assessment') or {}).get('findings') or []
    major = [x for x in findings if x.get('severity') in ('high', 'medium')]
    high = [x for x in major if x.get('severity') == 'high']
    sources = report.get('sources') or {}
    # Require DNS + current local IOC + at least one independent remote TI signal.
    # RDAP is context only and never proves a benign domain.
    dns_ok = (sources.get('dns') or {}).get('status') == 'ok'
    ioc_ok = (sources.get('local_ioc') or {}).get('status') == 'ok' and not any(
        x.get('stale') for x in ((sources.get('local_ioc') or {}).get('data') or {}).get('feeds', []))
    intel_ok = any((sources.get(k) or {}).get('status') == 'ok' for k in
                   ('otx', 'virustotal', 'threatbook_api'))
    if high:
        return dict(level='danger', title='发现严重风险', recommendation='不建议访问这个域名。优先核实恶意情报并停止输入信息或下载文件。',
                    reason='发现至少一条明确的高风险证据。')
    if major:
        return dict(level='caution', title='发现可疑问题', recommendation='建议暂缓访问，先核实下方列出的具体风险线索。',
                    reason=f'本次检查发现 {len(major)} 条需要关注的风险线索。')
    if not (dns_ok and ioc_ok and intel_ok):
        missing = [name for enabled, name in [(dns_ok, 'DNS'), (ioc_ok, '安全名单'), (intel_ok, '威胁情报')] if not enabled]
        return dict(level='unknown', title='信息不足，暂时无法判断', recommendation='建议先补齐下方未完成的检查，再决定是否访问或输入敏感信息。',
                    reason='关键检查尚未完成：' + '、'.join(missing) + '。')
    return dict(level='clear', title='暂未发现明显风险', recommendation='可以谨慎访问，但请核实网站身份，避免泄露密码、验证码或下载未知程序。',
                reason='已完成主要检查，当前未命中本工具定义的明显恶意风险规则。')


def source_view(key, item, problems):
    """Return plain-language state, not misleading green for a positive signal."""
    state = item.get('status', 'not_configured')
    title = SOURCE_NAMES.get(key, key)
    matched = key in problems
    if matched:
        return ('warn', '发现线索', f'{title}发现需要核实的信息')
    if key == 'local_ioc' and state == 'ok' and any(x.get('stale') for x in (item.get('data') or {}).get('feeds', [])):
        return ('mute', '数据过期', '部分本地安全名单过期，建议刷新后重查')
    if state == 'ok':
        return ('ok', '已完成', f'{title}已查询；在本次规则范围内没有触发明显异常')
    if state == 'empty':
        return ('mute', '未找到数据', f'{title}未找到可用的历史记录')
    if state == 'skipped':
        return ('mute', '未检查', (item.get('summary') or '未启用此项检查'))
    if state == 'not_configured':
        return ('mute', '未配置', f'{title}尚未配置 API Key，可运行 setup 补充')
    return ('mute', '检查失败', f'{title}暂时无法取得有效结果，不能视为正常')


def clean_href(value):
    try:
        parsed = urlparse(str(value))
        return str(value) if parsed.scheme == 'https' and parsed.netloc else None
    except (TypeError, ValueError):
        return None


def render(report):
    summary = summarize(report)
    sources = report.get('sources') or {}
    findings = (report.get('assessment') or {}).get('findings') or []
    display_findings = [f for f in findings if f.get('type') not in ('data_egress',)]
    if any(f.get('type') == 'data_egress' for f in findings):
        display_findings.extend(f for f in findings if f.get('type') == 'data_egress')
    mapping = {'rdap': {'new_domain', 'young_domain'}, 'dns': {'non_public_ip'},
               'virustotal': {'virustotal_detection'}, 'otx': {'otx_pulse'},
               'urlscan': {'off_domain_redirect'}, 'threatbook_api': {'threatbook_intel_signal'},
               'local_ioc': {'local_phishing_ioc', 'local_ip_association', 'local_adtracking'},
               'tls': {'tls_probe_failed'}}
    positive = {k for k, v in mapping.items() if any(f.get('type') in v for f in display_findings)}
    def problem_card(f):
        label = '需要注意' if f.get('severity') == 'low' else ('严重风险' if f.get('severity') == 'high' else '可疑线索')
        return (f'<article class="problem"><span class="problem-label">{esc(label)}</span>'
                f'<p>{esc(f.get("detail", "未知问题"))}</p></article>')
    problem_html = ''.join(problem_card(f) for f in display_findings[:7]) if display_findings else '<p class="quiet">本次成功完成的检查中，没有发现明显风险线索。</p>'
    successful = []
    unknown = []
    for key in ('dns', 'rdap', 'ripestat', 'crtsh', 'local_ioc', 'otx', 'urlscan', 'virustotal', 'threatbook_api', 'tls'):
        item = sources.get(key) or {}
        kind, state, detail = source_view(key, item, positive)
        row = f'<li><span>{esc(SOURCE_NAMES.get(key, key))}</span><span class="state {kind}">{esc(state)}</span></li>'
        (successful if kind in ('ok', 'warn') else unknown).append(row)
    # Only show "checked" entries as done if actually executed.
    success_html = '<ul class="checklist">' + ''.join(successful) + '</ul>' if successful else '<p class="quiet">目前没有可确认的已完成项目。</p>'
    unknown_html = '<ul class="checklist">' + ''.join(unknown) + '</ul>' if unknown else '<p class="quiet">没有未完成项。</p>'
    details = []
    for key, src in sources.items():
        label = SOURCE_NAMES.get(key, key)
        state, status_text, _ = source_view(key, src, positive)
        link = clean_href(src.get('source_url'))
        source_link = f'<a href="{esc(link)}" rel="noopener noreferrer" target="_blank">查看来源</a>' if link else ''
        data = json.dumps(src.get('data') or {}, ensure_ascii=False, indent=2, default=str)
        if len(data) > 20000:
            data = data[:20000] + '\n…（原始数据过长，请查看同名 JSON 文件）'
        details.append(f'<details><summary>{esc(label)} · {esc(status_text)}</summary>'
                       f'<p class="fine">{esc(src.get("summary") or "无说明")}　{source_link}</p>'
                       f'<pre>{esc(data)}</pre></details>')
    domain = esc(report.get('domain', '未知域名'))
    checked = esc(report.get('checked_at') or '未知时间')
    rid = esc(report.get('report_id', '—'))
    num_complete = len(successful)
    html_text = '''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><title>域名安全报告 · %s</title>
<style>
:root{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;color:#19283b;background:#f5f7fb}
*{box-sizing:border-box}body{margin:0}main{max-width:880px;margin:40px auto;padding:0 20px 44px}
header{margin-bottom:24px}h1{font-size:26px;margin:0 0 8px;letter-spacing:-.02em}h2{font-size:19px;margin:0 0 16px}
.sub,.quiet,.fine{color:#586679}.sub{font-size:14px;overflow-wrap:anywhere}.fine{font-size:12px}
.panel{background:#fff;border:1px solid #e5eaf0;border-radius:16px;padding:24px;margin-top:16px}
.hero{border-top:6px solid #8191a6}.hero.danger{border-top-color:#c43838}.hero.caution{border-top-color:#d28b26}
.hero.unknown{border-top-color:#818c9a}.hero.clear{border-top-color:#258064}
.status{display:block;font-size:25px;font-weight:760;line-height:1.35;margin:8px 0 12px}
.recommend{font-size:16px;line-height:1.8;font-weight:650;margin:16px 0 0}.small{font-size:14px;color:#586679;line-height:1.7}
.problem{border-left:3px solid #d28b26;padding:4px 0 4px 14px;margin:12px 0}.problem p{margin:7px 0;font-size:15px;line-height:1.75;overflow-wrap:anywhere}
.problem-label{font-size:12px;color:#8b570d;font-weight:700}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.grid .panel{margin:0}.checklist{list-style:none;padding:0;margin:0}
.checklist li{display:flex;gap:12px;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #edf0f4;font-size:14px}
.checklist li:last-child{border:0}.state{white-space:nowrap;font-weight:700}.state.ok{color:#258064}.state.warn{color:#a15f00}.state.mute{color:#707c8d}
details{border-top:1px solid #e9eef3;padding:14px 0}details summary{cursor:pointer;font-size:14px;font-weight:650}
pre{white-space:pre-wrap;word-wrap:break-word;background:#f3f6fa;border-radius:8px;padding:12px;font-size:12px;max-height:380px;overflow:auto}
a{color:#1d5aa6}footer{font-size:12px;color:#586679;line-height:1.7;margin-top:22px}
@media(max-width:660px){main{margin:18px auto;padding:0 12px 28px}.panel{padding:18px}.grid{grid-template-columns:1fr}.status{font-size:22px}h1{font-size:23px}}
@media print{body{background:#fff}main{margin:0;max-width:none}.panel{break-inside:avoid}details:not([open]) pre{display:none}}
</style></head><body><main>
<header><h1>域名安全检查报告</h1><div class="sub">%s · 检查时间：%s</div></header>
<section class="panel hero %s"><div class="small">检查结论</div><div class="status">%s</div>
<p class="small">%s</p><p class="recommend">建议：%s</p></section>
<section class="panel"><h2>发现的问题</h2>%s</section>
<section class="grid"><div class="panel"><h2>已经检查</h2>%s</div>
<div class="panel"><h2>未完成或未配置</h2>%s</div></section>
<section class="panel"><h2>技术详情（需要时再看）</h2><p class="small">点击展开即可查看原始证据，不需要阅读全部内容。</p>%s</section>
<footer>报告编号：%s。由公开信息及本地安全名单自动生成，只代表当前成功完成的检查；未查到不等于绝对安全。报告不主动批准、拦截或修改任何网络访问。</footer>
</main></body></html>''' % (domain, domain, checked, esc(summary['level']), esc(summary['title']), esc(summary['reason']), esc(summary['recommendation']), problem_html, success_html, unknown_html, ''.join(details), rid)
    return html_text
