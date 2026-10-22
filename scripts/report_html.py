"""Plain-language standalone HTML report. No JavaScript, external assets, or tracking."""
from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

SOURCE_NAMES = {
    'rdap': '域名注册信息', 'dns': 'DNS 解析', 'ripestat': 'IP / 服务器归属',
    'crtsh': '网站证书历史', 'urlscan': '网站历史扫描',
    'virustotal': 'VirusTotal 安全检测', 'tls': 'HTTPS 连接测试',
    'local_ioc': '免费开源安全名单',
}

def esc(value):
    return html.escape(str(value if value is not None else '—'), quote=True)


def summarize(report):
    """Verdict applies ONLY to evidence acquired. Missing is not passed."""
    findings = (report.get('assessment') or {}).get('findings') or []
    major = [x for x in findings if x.get('severity') in ('high', 'medium')]
    high = [x for x in major if x.get('severity') == 'high']
    sources = report.get('sources') or {}
    # Do not rate a domain clear unless DNS and one real reputation API completed.
    # RDAP is context only and never proves a benign domain.
    dns_ok = (sources.get('dns') or {}).get('status') == 'ok'
    intel_ok = (sources.get('virustotal') or {}).get('status') in ('ok', 'partial')
    if high:
        return dict(level='danger', title='发现严重风险', recommendation='不建议访问这个域名。优先核实恶意情报并停止输入信息或下载文件。',
                    reason='发现至少一条明确的高风险证据。')
    if major:
        return dict(level='caution', title='发现可疑问题', recommendation='建议暂缓访问，先核实下方列出的具体风险线索。',
                    reason=f'本次检查发现 {len(major)} 条需要关注的风险线索。')
    history_partial = (sources.get('urlscan') or {}).get('status') == 'partial'
    if not (dns_ok and intel_ok) or history_partial:
        missing = [name for enabled, name in [(dns_ok, 'DNS'), (intel_ok, 'VirusTotal 域名信誉'),
                                              (not history_partial, 'urlscan 历史详情（部分缺失）')] if not enabled]
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
    if state == 'ok':
        if key == 'urlscan' and (item.get('data') or {}).get('history_scope') == 'related_subdomains_only':
            return ('mute', '仅关联子域名', '没有目标主机的直接历史，以下仅为相关子域名线索')
        if key == 'local_ioc':
            records = item.get('data') or {}
            feeds = records.get('feeds') or []
            if feeds and not records.get('eligible_feeds'):
                return ('mute', '名单过期', '本地名单全部过期，不能视为已完成有效检查')
            if any(f.get('stale') for f in feeds):
                return ('warn', '部分过期', '部分本地情报未能及时更新，需谨慎解释结果')
        return ('ok', '已完成', f'{title}已查询；在本次规则范围内没有触发明显异常')
    if state == 'partial':
        return ('mute', '部分完成', '扫描结果未全部返回，或部分历史详情无法读取')
    if state == 'empty':
        return ('mute', '未找到数据', f'{title}未找到可用的历史记录')
    if state == 'skipped':
        return ('mute', '未检查', (item.get('summary') or '未启用此项检查'))
    if state == 'not_configured':
        return ('mute', '未准备', '本地安全名单尚未下载/导入' if key == 'local_ioc' else f'{title}尚未配置 API Key，可运行 setup 补充')
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
               'virustotal': {'virustotal_detection'},
               'urlscan': {'off_domain_redirect', 'urlscan_historical_malicious'},
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
    for key in ('dns', 'rdap', 'ripestat', 'crtsh', 'urlscan', 'local_ioc', 'virustotal', 'tls'):
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
    # A readable history timeline, no DOM/cookies/raw request headers embedded in the HTML.
    history = (sources.get('urlscan') or {}).get('data') or {}
    history_entries = history.get('results') or []
    if history_entries:
        def history_card(x):
            title = esc(x.get('page_title') or '无页面标题')
            date = esc(x.get('scan_time') or '时间未知')
            host = esc(x.get('result_page_host') or '未知')
            address = esc(x.get('ip') or '未知')
            requests_count = esc(x.get('total_requests') or 0)
            external_count = esc(x.get('external_resource_domains_count') or 0)
            offsite = '<span class="state warn">存在跨域跳转</span>' if x.get('redirected') == 'off-domain' else ''
            flagged = '<span class="state warn">历史扫描被标记</span>' if x.get('urlscan_malicious') else ''
            result_link = clean_href(x.get('result_url'))
            link = f'<a href="{esc(result_link)}" target="_blank" rel="noopener noreferrer">查看扫描证据 ↗</a>' if result_link else ''
            related_note = '<span class="state mute">关联子域名（不代表当前主机）</span>' if x.get('relation_to_target') == 'related_subdomain' else ''
            return (f'<div class="history-item"><b>{title}</b>　{related_note} {offsite} {flagged}'
                    f'<p class="fine">扫描：{date} · 页面域名：{host} · IP：{address}</p>'
                    f'<p class="small">请求 {requests_count} 次 · 外部资源域名 {external_count} 个　{link}</p></div>')
        related_only = history.get('history_scope') == 'related_subdomains_only'
        scope_note = '未找到目标主机的直接扫描；以下仅是关联子域名历史，不可据此认定目标主机有风险。' if related_only else ''
        history_html = ('<p class="small">' + esc(scope_note) + ' 以下为已有的第三方历史扫描，不能代替网站当前状态。'
                        '没有记录或没有历史风险命中，不等于安全。</p>'
                        f'<div class="history-stats"><b>详细记录 {esc(history.get("detailed_results", len(history_entries)))}</b>'
                        f' · 历史 IP {esc(len(history.get("history_ips") or []))} 个'
                        f' · 跨域跳转 {esc(history.get("cross_domain_redirects", 0))} 次</div>'
                        + ''.join(history_card(x) for x in history_entries[:8]))
        if len(history_entries) > 8:
            history_html += f'<p class="small">另有 {len(history_entries)-8} 条记录详见下方技术详情和 JSON 文件。</p>'
    elif (sources.get('urlscan') or {}).get('status') == 'empty':
        days = history.get('search_date_limit_days')
        age_note = f'当前账户仅能检索最近 {esc(days)} 天。' if days is not None else ''
        history_html = '<p class="quiet">' + age_note + '没有找到该主机及相关子域名的可见历史扫描；不代表网站安全。</p>'
    elif (sources.get('urlscan') or {}).get('status') in ('not_configured','skipped'):
        history_html = '<p class="quiet">未配置 urlscan API Key，网站历史扫描尚未执行。</p>'
    else:
        history_html = '<p class="quiet">历史扫描数据暂时不可用，未能作出判断。</p>'
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
.history-item{border-top:1px solid #edf0f4;padding:12px 0}.history-item p{margin:6px 0}.history-stats{background:#f5f7fa;border-radius:8px;padding:10px;font-size:13px}details{border-top:1px solid #e9eef3;padding:14px 0}details summary{cursor:pointer;font-size:14px;font-weight:650}
pre{white-space:pre-wrap;word-wrap:break-word;background:#f3f6fa;border-radius:8px;padding:12px;font-size:12px;max-height:380px;overflow:auto}
a{color:#1d5aa6}footer{font-size:12px;color:#586679;line-height:1.7;margin-top:22px}
@media(max-width:660px){main{margin:18px auto;padding:0 12px 28px}.panel{padding:18px}.grid{grid-template-columns:1fr}.status{font-size:22px}h1{font-size:23px}}
@media print{body{background:#fff}main{margin:0;max-width:none}.panel{break-inside:avoid}details:not([open]) pre{display:none}}
</style></head><body><main>
<header><h1>域名安全检查报告</h1><div class="sub">%s · 检查时间：%s</div></header>
<section class="panel hero %s"><div class="small">检查结论</div><div class="status">%s</div>
<p class="small">%s</p><p class="recommend">建议：%s</p></section>
<section class="panel"><h2>发现的问题</h2>%s</section>
<section class="panel"><h2>网站历史扫描</h2><p class="small">仅查询已有历史记录与详情，不提交新的 urlscan 网页扫描任务。</p>%s</section>
<section class="grid"><div class="panel"><h2>已经检查</h2>%s</div>
<div class="panel"><h2>未完成或未配置</h2>%s</div></section>
<section class="panel"><h2>技术详情（需要时再看）</h2><p class="small">点击展开即可查看原始证据，不需要阅读全部内容。</p>%s</section>
<footer>报告编号：%s。由公开数据源自动生成，只代表当前成功完成的检查；未查到不等于绝对安全。报告不主动批准、拦截或修改任何网络访问。</footer>
</main></body></html>''' % (domain, domain, checked, esc(summary['level']), esc(summary['title']), esc(summary['reason']), esc(summary['recommendation']), problem_html, history_html, success_html, unknown_html, ''.join(details), rid)
    return html_text
