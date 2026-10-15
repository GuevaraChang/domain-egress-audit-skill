#!/usr/bin/env python3
"""Free-source, read-only external FQDN due-diligence and reporting CLI.

No paid threat intelligence, no URL submission, no active target connection by default.
"""
from __future__ import annotations

import argparse
import getpass
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import dns.exception
import dns.resolver
import requests
# 支持 importlib 按绝对路径加载 CLI（单元测试 / Agent 容器）
sys.path.insert(0, str(Path(__file__).resolve().parent))
import report_html
import local_ioc

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV = ROOT / '.env'
UA = 'DomainSafetySkill/2.1 (historical scan details + opt-in live scan)'
TIMEOUT = 9
RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json'
URLSCAN_SEARCH = 'https://urlscan.io/api/v1/search/'
URLSCAN_RESULT = 'https://urlscan.io/api/v1/result/'
URLSCAN_SUBMIT = 'https://urlscan.io/api/v1/scan/'
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
URLSCAN_HISTORY_DEFAULT = 15
URLSCAN_HISTORY_LIMIT = 50
VT_DOMAIN_API = 'https://www.virustotal.com/api/v3/domains'
VT_POLICY_URL = 'https://docs.virustotal.com/reference/public-vs-premium-api'
VT_KEY_URL = 'https://www.virustotal.com/gui/my-apikey'
RIPESTAT_API = 'https://stat.ripe.net/data/network-info/data.json'
COMMON_SECOND_LEVEL_SUFFIXES = {'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'or.jp', 'ne.jp', 'com.hk', 'com.tw', 'com.sg', 'com.my', 'co.nz', 'com.br', 'co.kr'}
CREDENTIAL_NAMES = ('URLSCAN_API_KEY', 'VT_API_KEY')
CONFIG_NAMES = CREDENTIAL_NAMES + ('VT_USAGE', 'VT_API_TIER', 'ONBOARDING_DONE')
# VirusTotal Public API requires an explicit permitted-use acknowledgement.
# Other configured providers are queried by default unless explicitly disabled.
# Never disclose internal-only namespaces to Internet threat-intelligence services.
NONPUBLIC_TLDS = {'local', 'localhost', 'internal', 'invalid', 'test', 'example', 'lan', 'corp', 'home', 'onion', 'arpa'}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def parse_iso(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def read_env(path=None):
    path = path or DEFAULT_ENV
    # Never print secrets; process environment variables override the local file.
    result = {}
    if path.is_file():
        for line in path.read_text(encoding='utf-8').splitlines():
            s = line.strip()
            if not s or s.startswith('#') or '=' not in s:
                continue
            name, value = s.split('=', 1)
            name = name.strip()
            if name in CONFIG_NAMES:
                result[name] = value.strip().strip('"\'')
    file_vt_usage = result.get('VT_USAGE', '').strip().lower()
    for name in CONFIG_NAMES:
        if name in os.environ:
            # The on-disk business restriction takes precedence over a stray
            # environment-level noncommercial override; never silently loosen it.
            if name == 'VT_USAGE' and file_vt_usage == 'business':
                continue
            result[name] = os.environ[name]
    return result


def validated_domain(value):
    domain = value.strip().rstrip('.').lower()
    if '://' in domain or '/' in domain or '@' in domain or ':' in domain or '?' in domain or '#' in domain:
        raise ValueError('只能输入 FQDN 域名，不要输入 URL、IP、端口、路径或账号。')
    try:
        domain = domain.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('域名 IDNA 编码失败。') from exc
    if len(domain) > 253 or '.' not in domain:
        raise ValueError('请输入公开互联网 FQDN，例如 api.example.com。')
    if domain.rsplit('.', 1)[-1] in NONPUBLIC_TLDS:
        raise ValueError('禁止将内部/保留域名发送至第三方公开查询平台；请检查域名。')
    for label in domain.split('.'):
        if not 1 <= len(label) <= 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label):
            raise ValueError('域名标签格式不合法。')
    try:
        ipaddress.ip_address(domain)
        raise ValueError('请提供域名，不是 IP 地址。')
    except ValueError as exc:
        if str(exc) == '请提供域名，不是 IP 地址。':
            raise
    # Minimal offline estimate. For uncommon multi-label public suffixes, confirm RDAP and override.
    parts = domain.split('.')
    if len(parts) < 2 or parts[-1].isdigit():
        raise ValueError('请输入合法的互联网域名（不可输入 IP）。')
    psl_two = '.'.join(parts[-2:])
    if psl_two in COMMON_SECOND_LEVEL_SUFFIXES:
        if len(parts) < 3:
            raise ValueError('请输入可注册域名或其子域名。')
        registered = '.'.join(parts[-3:])
    else:
        registered = '.'.join(parts[-2:])
    return domain, registered


def req_json(url, *, headers=None, params=None, timeout=TIMEOUT):
    resp = requests.get(
        url, params=params, headers={'User-Agent': UA, 'Accept': 'application/json', **(headers or {})},
        timeout=timeout, allow_redirects=False,
    )
    # Do not follow redirects: API tokens in custom headers could leak across origins.
    resp.raise_for_status()
    if 300 <= resp.status_code < 400:
        raise requests.HTTPError('第三方 API 出现重定向，出于密钥保护已拒绝跟随。')
    return resp.json()


def source(status, summary=None, data=None, error=None, url=None):
    return {'status': status, 'checked_at': utc_now(), 'summary': summary,
            'data': data or {}, 'error': str(error)[:200] if error else None, 'source_url': url}


def rdap_check(registered):
    try:
        bootstrap = req_json(RDAP_BOOTSTRAP)
        tld = registered.rsplit('.', 1)[-1]
        bases = []
        for zones, servers in bootstrap.get('services', []):
            if tld in [z.lower() for z in zones]:
                bases.extend(servers)
        if not bases:
            return source('error', error=f'IANA bootstrap 未找到 .{tld} 的注册局 RDAP 服务', url=RDAP_BOOTSTRAP)
        errors = []
        for base in bases[:4]:
            if urlparse(base).scheme != 'https':
                continue
            endpoint = base.rstrip('/') + '/domain/' + quote(registered, safe='')
            try:
                doc = req_json(endpoint)
                events = {}
                for e in doc.get('events', []):
                    if e.get('eventAction') and e.get('eventDate'):
                        events[e['eventAction']] = e['eventDate']
                created = events.get('registration')
                age_days = None
                created_dt = parse_iso(created)
                if created_dt:
                    age_days = (datetime.now(timezone.utc) - created_dt).days
                registrar = None
                for entity in doc.get('entities', []):
                    if 'registrar' in entity.get('roles', []):
                        registrar = entity.get('handle')
                        vcard = entity.get('vcardArray') or []
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if len(item) > 3 and item[0] == 'fn':
                                    registrar = item[3]
                                    break
                        break
                data = {
                    'registered_domain': registered,
                    'registration_date': created,
                    'age_days': age_days,
                    'expiration_date': events.get('expiration'),
                    'last_changed': events.get('last changed'),
                    'registrar': registrar,
                    'domain_status': doc.get('status', []),
                    'name_servers': [e.get('ldhName') for e in doc.get('nameservers', []) if e.get('ldhName')][:20],
                    'rdap_link': endpoint,
                    'registrant_verified': False,
                }
                return source('ok', summary='已查询注册局 RDAP；注册人真实身份仍须由业务方核验', data=data, url=endpoint)
            except (requests.RequestException, ValueError) as exc:
                errors.append(type(exc).__name__ + ': ' + str(exc)[:80])
        return source('error', error='; '.join(errors) or '没有可用 HTTPS RDAP 地址', url=RDAP_BOOTSTRAP)
    except (requests.RequestException, ValueError, KeyError) as exc:
        return source('error', error=exc, url=RDAP_BOOTSTRAP)


def dns_check(host, registered):
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 3
    resolver.lifetime = 6
    answers = {}
    statuses = {}
    errors = []
    for name, kind in [(host, 'A'), (host, 'AAAA'), (host, 'CNAME'), (registered, 'NS')]:
        key = f'{name} {kind}'
        try:
            responses = resolver.resolve(name, kind, raise_on_no_answer=False)
            rrset = responses.rrset
            entries = [x.to_text().rstrip('.') for x in rrset] if rrset else []
            answers[kind] = sorted(entries)[:40]
            statuses[kind] = 'ok' if entries else 'empty'
        except dns.resolver.NoAnswer:
            answers[kind] = []
            statuses[kind] = 'empty'
        except (dns.exception.DNSException, OSError) as exc:
            answers[kind] = []
            statuses[kind] = 'error'
            errors.append(f'{key}: {type(exc).__name__}')
    ips = []
    for kind in ('A', 'AAAA'):
        for addr in answers[kind]:
            try:
                ips.append({'ip': addr, 'globally_routable': ipaddress.ip_address(addr).is_global})
            except ValueError:
                pass
    state = 'ok' if any(x == 'ok' for x in statuses.values()) else ('error' if errors else 'empty')
    data = {'records': answers, 'record_statuses': statuses, 'ips': ips,
            'resolver_viewpoint': '运行脚本的主机所使用的 DNS 解析器（可能存在内外网视图差异）'}
    return source(state, summary='从当前机器查询 DNS，非完整历史 Passive DNS', data=data,
                  error='; '.join(errors) if errors else None)


def ripestat_check(ips):
    data = []
    errors = []
    for addr in ips[:4]:
        ip = addr['ip']
        if not addr['globally_routable']:
            data.append({'ip': ip, 'status': 'non_global', 'prefix': None, 'asns': []})
            continue
        try:
            obj = req_json(RIPESTAT_API, params={'resource': ip})
            if obj.get('status') != 'ok':
                raise ValueError('RIPEstat 返回非 ok 状态')
            info = obj.get('data', {})
            data.append({'ip': ip, 'status': 'ok', 'prefix': info.get('prefix'), 'asns': info.get('asns', [])})
        except (requests.RequestException, ValueError, KeyError) as exc:
            errors.append(f'{ip}: {type(exc).__name__}')
            data.append({'ip': ip, 'status': 'error', 'prefix': None, 'asns': []})
    if not ips:
        return source('skipped', summary='DNS 未返回可评估 IP', url=RIPESTAT_API)
    return source('ok' if not errors else 'error', summary=f'查询前 {min(len(ips), 4)} 个 IP 的前缀与 ASN；不代表 IP 安全信誉',
                  data={'results': data, 'ip_count': len(ips)}, error='; '.join(errors) if errors else None,
                  url=RIPESTAT_API)


def crt_check(registered):
    url = 'https://crt.sh/'
    try:
        raw = req_json(url, params={'q': registered, 'output': 'json'}, timeout=12)
        if not isinstance(raw, list):
            raise ValueError('非预期证书透明度响应')
        names = sorted({x.strip().lower() for row in raw for x in (row.get('name_value') or '').splitlines()
                        if x.strip().lower() == registered or x.strip().lower().endswith('.' + registered)})
        latest = sorted([row.get('entry_timestamp', '') for row in raw if row.get('entry_timestamp')], reverse=True)
        return source('ok' if raw else 'empty', summary='证书透明度历史（不代表实时证书有效性）',
                      data={'certificate_entries': len(raw), 'unique_names_count': len(names),
                            'name_examples': names[:20], 'latest_entry': latest[0] if latest else None},
                      url='https://crt.sh/?q=' + quote(registered))
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return source('error', error=exc, url=url)


def urlscan_scan_detail(doc, scan_id, host, *, search_item=None):
    """Summarise one EXISTING scan's full Result JSON without storing raw DOM/cookies/PII."""
    item = search_item or {}
    task = doc.get('task') or item.get('task') or {}
    page = doc.get('page') or item.get('page') or {}
    lists = doc.get('lists') or {}
    stats = doc.get('stats') or {}
    verdicts = doc.get('verdicts') or {}
    final_url = page.get('url') or ''
    final_host = (urlparse(final_url).hostname or page.get('domain') or '').lower()
    original_host = (urlparse(task.get('url') or '').hostname or task.get('domain') or host).lower()
    raw_domains = [str(v).lower().rstrip('.') for v in (lists.get('domains') or []) if isinstance(v, str)]
    external_domains = sorted({v for v in raw_domains if v and v != host and not v.endswith('.' + host)})
    # Only record resource hosts. Query strings, cookies, headers, and response bodies are excluded.
    resource_hosts = set()
    for record in (doc.get('data') or {}).get('requests') or []:
        request = (record.get('request') or {}) if isinstance(record, dict) else {}
        req = request.get('request') or request
        u = req.get('url') if isinstance(req, dict) else None
        if isinstance(u, str):
            value = urlparse(u).hostname
            if value:
                resource_hosts.add(value.lower())
    external_domains = sorted(set(external_domains) | {
        v for v in resource_hosts if v != host and not v.endswith('.'+host)
    })
    uv = verdicts.get('urlscan') or {}
    return {
        'scan_id': scan_id,
        'scan_time': task.get('time') or (item.get('task') or {}).get('time'),
        'task_url_host': original_host,
        'result_page_host': final_host,
        'page_title': str(page.get('title') or '')[:180],
        'status_code': page.get('status'), 'ip': page.get('ip'),
        'redirected': 'off-domain' if final_host and final_host != original_host else ('on-domain' if page.get('redirected') else 'none'),
        'total_requests': stats.get('requests') if isinstance(stats.get('requests'), int) else len((doc.get('data') or {}).get('requests') or []),
        'external_resource_domains_count': len(external_domains),
        'external_resource_domains': external_domains[:35],
        'urlscan_malicious': uv.get('malicious') is True,
        'urlscan_score': uv.get('score') if isinstance(uv.get('score'), (int, float)) else None,
        'result_url': 'https://urlscan.io/result/' + scan_id + '/',
        'screenshot_url': 'https://urlscan.io/screenshots/' + scan_id + '.png',
        'scope': '第三方历史扫描完整结果的摘要；不代表当前页面状态或全部网站历史',
    }


def urlscan_fetch_detail(scan_id, api_key, host, *, search_item=None):
    if not UUID_PATTERN.fullmatch(str(scan_id)):
        raise ValueError('urlscan 扫描 ID 无效，拒绝下载未知地址')
    doc = req_json(URLSCAN_RESULT + scan_id + '/', headers={'api-key': api_key}, timeout=12)
    if not isinstance(doc, dict):
        raise ValueError('历史扫描详情响应格式错误')
    return urlscan_scan_detail(doc, scan_id, host, search_item=search_item)


def urlscan_check(host, api_key, *, max_scans=URLSCAN_HISTORY_DEFAULT):
    """Search existing scans and fetch detailed JSON for each selected scan; never submit."""
    if not api_key:
        return source('not_configured', summary='未配置 urlscan API Key，历史完整扫描未执行；不提交新扫描',
                      url='https://urlscan.io/docs/api/')
    limit = min(max(1, int(max_scans)), URLSCAN_HISTORY_LIMIT)
    try:
        raw = req_json(URLSCAN_SEARCH, headers={'api-key': api_key},
                       params={'q': f'(task.domain.keyword:"{host}" OR page.domain.keyword:"{host}")', 'size': limit})
        rows = []
        for entry in raw.get('results') or []:
            page, task = entry.get('page') or {}, entry.get('task') or {}
            if (page.get('domain') or '').lower() != host and (task.get('domain') or '').lower() != host:
                continue
            rows.append(entry)
        selected = rows[:limit]
        if not selected:
            return source('empty', summary='该账户可搜索的历史范围内未发现扫描记录；不证明网站安全',
                          data={'matched_results':0, 'detailed_results':0, 'results':[],
                                'history_limit':limit,'search_date_limit_days':raw.get('search_date_limit_days'),
                                'scope':'仅 urlscan 可见的历史范围'},
                          url='https://urlscan.io/search/#domain:' + quote(host))
        results, problems = [], []
        for item in selected:
            scan_id = str(item.get('_id') or (item.get('task') or {}).get('uuid') or '')
            if not UUID_PATTERN.fullmatch(scan_id):
                problems.append('历史记录未返回有效扫描 ID')
                # Missing detail stays partial. Search preview is NOT a complete scan.
                continue
            try:
                results.append(urlscan_fetch_detail(scan_id, api_key, host, search_item=item))
            except requests.HTTPError as exc:
                code = exc.response.status_code if exc.response is not None else None
                problems.append(f'扫描 {scan_id[:8]} 详情不可用（HTTP {code or "?"}）')
                if code == 429:
                    break  # Respect quota; do not retry repeatedly.
            except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
                problems.append(f'扫描 {scan_id[:8]} 详情失败（{type(exc).__name__}）')
        status = 'ok' if len(results) == len(selected) else 'partial'
        ips = sorted({v.get('ip') for v in results if v.get('ip')})
        titles = sorted({v.get('page_title') for v in results if v.get('page_title')})
        redirect_count = sum(v.get('redirected') == 'off-domain' for v in results)
        malicious_count = sum(v.get('urlscan_malicious') is True for v in results)
        return source(status, summary=f'已读取 {len(results)}/{len(selected)} 条历史扫描完整结果摘要，跨域跳转 {redirect_count} 条；仅反映历史行为',
                      data={'matched_results': len(selected), 'detailed_results':len(results),
                            'results':results, 'history_limit':limit,
                            'search_has_more':bool(raw.get('has_more')),
                            'search_date_limit_days':raw.get('search_date_limit_days'),
                            'history_ips':ips, 'historical_titles':titles[:20],
                            'cross_domain_redirects': redirect_count,
                            'urlscan_malicious_scans':malicious_count,
                            'detail_errors':problems[:15],
                            'coverage_note':'读取可见历史记录的详情，非全网或无限量历史扫描；截图提供链接但未自动下载'},
                      url='https://urlscan.io/search/#domain:' + quote(host))
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return source('error', summary='urlscan 历史扫描查询失败，不当作安全', error=exc, url=URLSCAN_SEARCH)


def urlscan_live_check(host, api_key, *, enabled=False, visibility='private', public_ips=None, attempts=5, delay=4):
    """Explicit opt-in submission; private by default, no automatic switch to public."""
    if not enabled:
        return source('skipped', summary='默认不提交实时网站扫描（需明确使用 --live-scan）')
    if not api_key:
        return source('not_configured', summary='实时网站扫描需先配置 urlscan.io API Key')
    if visibility not in ('private','unlisted','public'):
        return source('error', error='无效扫描可见性')
    if not public_ips:
        return source('skipped', summary='DNS 未确认公网地址，不提交实时网站扫描')
    # The scan URL is constructed ONLY from the validated FQDN, never a user-provided URL.
    scan_url = 'https://' + host + '/'
    try:
        response = requests.post(URLSCAN_SUBMIT, headers={'api-key': api_key, 'Content-Type':'application/json',
                                  'User-Agent':UA}, json={'url':scan_url, 'visibility':visibility},
                                 timeout=12, allow_redirects=False)
        response.raise_for_status()
        if response.status_code >= 300:
            raise requests.HTTPError('urlscan 提交出现重定向，已拒绝')
        doc = response.json()
        scan_id = str(doc.get('uuid') or '')
        if not UUID_PATTERN.fullmatch(scan_id):
            raise ValueError('urlscan 未返回有效扫描 ID')
        link = 'https://urlscan.io/result/' + scan_id + '/'
        for i in range(max(0, min(int(attempts), 8))):
            if i or delay:
                time.sleep(max(0, min(float(delay), 8)))
            try:
                detail = urlscan_fetch_detail(scan_id, api_key, host)
                return source('ok', summary='经明确请求已完成实时远程网页扫描，结果可查看；这不是本机直接扫描',
                              data={'submission_status':'complete', 'visibility':visibility,
                                    'scan_url':scan_url, 'result':detail}, url=link)
            except requests.HTTPError as exc:
                if exc.response is None or exc.response.status_code != 404:
                    break
            except (requests.RequestException, ValueError):
                break
        return source('partial', summary='已提交实时扫描，尚未取得完整结果；请稍后查看 urlscan 链接',
                      data={'submission_status':'pending', 'visibility':visibility,
                            'scan_url':scan_url, 'scan_id':scan_id}, url=link)
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return source('error', summary='实时扫描提交失败，可能受账号配额或可见性权限限制；不会自动切换到公开模式',
                      error=exc, url='https://urlscan.io/docs/api/')


def effective_vt_usage(env, ctx=None):
    """Only enable free VT when the user has acknowledged its actual terms.

    Paid/licensed VT keys can be enabled with VT_API_TIER=premium. No provider is
    granted extra rights merely because a key was supplied.
    """
    if str(env.get('VT_API_TIER', '')).strip().lower() == 'premium':
        return 'licensed'
    return 'noncommercial' if str(env.get('VT_USAGE', '')).strip().lower() == 'noncommercial' else 'not_enabled'


def vt_check(host, api_key, usage):
    """Read an existing VirusTotal domain report; never submit a URL for scanning."""
    if not api_key:
        return source('not_configured', summary='未配置 VirusTotal API Key',
                      data={'api_called': False}, url=VT_KEY_URL)
    if usage not in ('noncommercial', 'licensed'):
        return source('skipped', summary='需要确认已获得符合使用条款的 API 权限',
                      data={'skip_reason': 'permission_not_confirmed', 'api_called': False},
                      url=VT_POLICY_URL)
    url = VT_DOMAIN_API + '/' + quote(host, safe='')
    try:
        raw = req_json(url, headers={'x-apikey': api_key})
        attrs = (raw.get('data') or {}).get('attributes') or {}
        stats = attrs.get('last_analysis_stats') or {}
        values = {key: int(stats.get(key, 0) or 0) for key in ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout')}
        stamp = attrs.get('last_analysis_date')
        analysis_date = datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat() if isinstance(stamp, (int, float)) else None
        return source('ok', summary='已读取 VirusTotal 既有域名检测结果',
            data={'api_called': True, 'last_analysis_stats': values,
                  'last_analysis_date': analysis_date, 'reputation': attrs.get('reputation')},
            url='https://www.virustotal.com/gui/domain/' + quote(host, safe=''))
    except (requests.RequestException, ValueError, KeyError, TypeError, OverflowError) as exc:
        return source('error', summary='VirusTotal 查询失败，不能当成无风险', error=exc,
                      data={'api_called': True},
                      url='https://www.virustotal.com/gui/domain/' + quote(host, safe=''))


def tls_check(host, port, ips, enabled=False):
    if not enabled:
        return source('skipped', summary='未启用目标 TCP/TLS 主动连接（默认安全模式）')
    if not 1 <= port <= 65535:
        return source('error', error='端口不合法')
    public_ips = [x['ip'] for x in ips if x['globally_routable']][:3]
    if not public_ips:
        return source('skipped', summary='无公网 IP，安全保护阻止主动探测')
    outcomes = []
    for ip in public_ips:
        try:
            with socket.create_connection((ip, port), timeout=5) as raw_sock:
                raw_sock.settimeout(5)
                with ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host) as sock:
                    cert = sock.getpeercert()
                    outcome = {'ip': ip, 'status': 'ok', 'tls_version': sock.version(),
                               'not_after': cert.get('notAfter'), 'subject': cert.get('subject')}
                    outcomes.append(outcome)
        except (ssl.SSLError, socket.timeout, TimeoutError, OSError) as exc:
            outcomes.append({'ip': ip, 'status': 'error', 'error': f'{type(exc).__name__}: {str(exc)[:130]}'})
    return source('ok' if outcomes and all(x['status'] == 'ok' for x in outcomes) else 'error',
                  summary='只探测已解析的公网 IP，SNI 为目标 FQDN；没有发起 HTTP 请求',
                  data={'results': outcomes})


def read_context(path, host):
    if not path:
        return {'target_fqdn': host,
                'data_classification': 'unknown', 'context_status': 'not_provided'}, None
    obj = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError('业务上下文必须是 JSON 对象')
    target = obj.get('target_fqdn')
    if target and validated_domain(target)[0] != host:
        raise ValueError('业务上下文 target_fqdn 与命令行 domain 不一致，已中止。')
    return obj, None



def build_asset_inventory(report):
    """In-scope single FQDN plus passive dependencies, with explicit attribution boundaries.

    Discovered CNAMEs / historical redirect hosts are *leads*, not targets to
    expand, scan or automatically whitelist. There are no extra network requests.
    """
    host = report['domain']
    dns_src = report['sources']['dns']
    data = dns_src.get('data') or {}
    records = data.get('records') or {}
    out = [{
        'hostname': host, 'role': '申请访问的唯一 FQDN',
        'relationship': '申请目标', 'in_approved_scope': True,
        'ips': [x.get('ip') for x in data.get('ips', []) if x.get('ip')],
        'cname_targets': list(records.get('CNAME') or []),
        'attribution': '域名与申请相关，但供应商所有权未由 DNS 证明',
        'attribution_confidence': 'unconfirmed', 'evidence_source': 'dns',
        'observed_at': dns_src.get('checked_at'),
    }]
    seen = {host}
    for cname in (records.get('CNAME') or [])[:15]:
        cname = cname.rstrip('.').lower()
        if cname and cname not in seen:
            seen.add(cname)
            out.append({'hostname': cname, 'role': 'CNAME 依赖目标',
                        'relationship': f'{host} -> CNAME', 'in_approved_scope': False,
                        'ips': [], 'cname_targets': [], 'attribution': '可能是第三方 SaaS/CDN，不得推定同一所有者',
                        'attribution_confidence': 'unconfirmed', 'evidence_source': 'dns',
                        'observed_at': dns_src.get('checked_at')})
    us = report['sources']['urlscan']
    for rec in (us.get('data') or {}).get('results', [])[:15]:
        redirect = (rec.get('result_page_host') or '').lower()
        if redirect and redirect not in seen:
            seen.add(redirect)
            out.append({'hostname': redirect, 'role': 'urlscan 历史最终页面域名',
                        'relationship': '历史扫描可能出现跨域访问，不等于当前会跳转',
                        'in_approved_scope': False, 'ips': [], 'cname_targets': [],
                        'attribution': '未经证实的第三方历史关联',
                        'attribution_confidence': 'unconfirmed', 'evidence_source': 'urlscan',
                        'observed_at': rec.get('scan_time')})
    return out


def evidence_ledger(report):
    """One provenance record per source. Capture coverage and historical staleness."""
    semantics = {
        'rdap': ('注册局 RDAP', '注册信息：不直接确认真实经营主体', 'registration_date'),
        'dns': ('运行机当前 DNS', '当前机器解析器视角，非公网权威全景', None),
        'ripestat': ('RIPEstat', '路由归属信息：非安全信誉分数', None),
        'crtsh': ('crt.sh / CT', '历史证书记录：不等于实时 TLS 有效性', 'latest_entry'),
        'urlscan': ('urlscan', '公开历史扫描，可能过时/样本有偏', 'latest_scan'),
        'virustotal': ('VirusTotal', '第三方检测统计，不等于恶意定性；某些用途自动跳过', 'last_analysis_date'),
        'tls': ('可选 TLS 探测', '仅在明确授权时可做的实时目标连接', None),
        'local_ioc': ('开源本地安全名单', '离线匹配公开名单；域名精确匹配与共享 IP 弱关联不同，广告追踪不等于恶意', None),
        'urlscan_live': ('urlscan 可选实时扫描', '用户明确选择时才提交，可能暴露所访问的 URL；不会自动公开', None),
    }
    ledger = []
    status_counts = {k: 0 for k in ('ok', 'empty', 'error', 'not_configured', 'skipped')}
    stale = []
    for index, (key, item) in enumerate(report['sources'].items(), 1):
        title, meaning, time_key = semantics.get(key, (key, '未分类证据', None))
        record = item.get('data') or {}
        observed = record.get(time_key) if time_key else None
        if key == 'urlscan':
            observed = max((r.get('scan_time') for r in record.get('results', []) if r.get('scan_time')), default=None)
        # Observed time is NULL rather than dishonestly substituting collection time.
        age_days = None
        dt = parse_iso(observed)
        if dt:
            age_days = max(0, (datetime.now(timezone.utc) - dt).days)
        row = {
            'id': f'EV-{index:02d}', 'source': key, 'source_name': title,
            'status': item.get('status', 'error'), 'checked_at': item.get('checked_at'),
            'observed_at': observed, 'observation_age_days': age_days,
            'evidence_url': item.get('source_url'), 'interpretation_limit': meaning,
            'scope': 'FQDN / 注册域 / 解析 IP：详见 sources.' + key,
        }
        ledger.append(row)
        status = item.get('status')
        if status in status_counts:
            status_counts[status] += 1
        if age_days is not None and age_days > 90 and key in ('urlscan', 'virustotal', 'crtsh'):
            stale.append({'source': key, 'observed_at': observed, 'age_days': age_days})
    return ledger, {'status_counts': status_counts, 'stale_observations_over_90_days': stale,
                    'note': '覆盖率表示查询是否完成，不是域名安全得分。skipped/empty 不代表安全。'}


def compare_reports(previous, current):
    """Compare two local JSON snapshots; changes are review triggers, not proof of attack."""
    if not isinstance(previous, dict) or previous.get('domain') != current.get('domain'):
        raise ValueError('基线报告中的目标域名与本次 FQDN 不一致；禁止跨域对比')
    old_src = previous.get('sources') or {}
    new_src = current.get('sources') or {}
    old_dns = ((old_src.get('dns') or {}).get('data') or {})
    new_dns = ((new_src.get('dns') or {}).get('data') or {})
    changes = []
    old_ips = {v.get('ip') for v in old_dns.get('ips', []) if v.get('ip')}
    new_ips = {v.get('ip') for v in new_dns.get('ips', []) if v.get('ip')}
    # Avoid interpreting query failures as IP churn.
    if (old_src.get('dns') or {}).get('status') == 'ok' and (new_src.get('dns') or {}).get('status') == 'ok':
        if old_ips != new_ips:
            changes.append({'field': 'dns_ip_set', 'before': sorted(old_ips), 'after': sorted(new_ips),
                            'review': '检查 CDN/解析调度/供应商变更；不构成恶意证据'})
        old_cn = sorted(old_dns.get('records', {}).get('CNAME') or [])
        new_cn = sorted(new_dns.get('records', {}).get('CNAME') or [])
        if old_cn != new_cn:
            changes.append({'field': 'dns_cname', 'before': old_cn, 'after': new_cn,
                            'review': '核实新 CNAME 指向及第三方托管链；不自动扩展批准范围'})
    old_rd = old_src.get('rdap') or {}
    new_rd = new_src.get('rdap') or {}
    if old_rd.get('status') == 'ok' and new_rd.get('status') == 'ok':
        a = (old_rd.get('data') or {}).get('registrar')
        b = (new_rd.get('data') or {}).get('registrar')
        if a and b and a != b:
            changes.append({'field': 'registrar', 'before': a, 'after': b,
                            'review': '核实注册商迁移或供应商通知'})
    return {'baseline_report_id': previous.get('report_id'),
            'baseline_checked_at': previous.get('checked_at'), 'changes': changes,
            'summary': '发现变化，必须人工复核' if changes else '在可比较项目中没有发现变化（不代表无风险）',
            'limitations': '仅比较两份本地快照中均有效的 RDAP/DNS 字段，不具备完整 Passive DNS。'}


def attach_baseline(report, previous):
    comparison = compare_reports(previous, report)
    report['baseline_comparison'] = comparison
    if comparison['changes']:
        report['assessment']['pending_items'] = sorted(set(
            report['assessment']['pending_items'] + ['历史快照差异待人工确认（DNS/注册信息变化）']))
        report['assessment']['findings'].append({
            'severity': 'medium', 'type': 'baseline_change', 'confidence': 'high',
            'evidence_ids': [e['id'] for e in report.get('evidence_ledger', []) if e.get('source') in ('dns','rdap')],
            'detail': f"与基线相比有 {len(comparison['changes'])} 项变化；仅为待核查信号，不是恶意证据。"})
        report['assessment']['risk_label'] = '存在风险信号，需人工调查'
        report['assessment']['decision'] = '检测到历史变化，建议核实后再访问'
    if 'technical_assessment' in report:
        report['technical_assessment'] = technical_assessment(report)
    return report

def evaluate(report):
    src = report['sources']
    ctx = report['business_context']
    ev = {row['source']:row['id'] for row in report.get('evidence_ledger', [])}
    def ids(*names):
        return [ev[name] for name in names if name in ev]
    findings = []
    pending = []
    high_confidence = False
    rd = src['rdap']
    if rd['status'] == 'ok':
        age = rd['data'].get('age_days')
        if isinstance(age, int) and age < 0:
            findings.append({'severity': 'medium', 'type': 'rdap', 'detail': 'RDAP 创建时间晚于当前时间；需核验时钟或注册数据'})
        elif isinstance(age, int) and age < 30:
            findings.append({'severity': 'medium', 'type': 'new_domain', 'confidence': 'medium', 'evidence_ids': ids('rdap'), 'detail': f'域名注册仅 {age} 天，建议加强主体核验'})
        elif isinstance(age, int) and age < 90:
            findings.append({'severity': 'low', 'type': 'young_domain', 'confidence': 'medium', 'evidence_ids': ids('rdap'), 'detail': f'域名注册约 {age} 天，建议关注业务匹配性'})
    else:
        pending.append('RDAP 注册信息未成功获取')
    dns_data = src['dns']['data']
    ips = dns_data.get('ips') or []
    if src['dns']['status'] == 'error' or not ips:
        pending.append('DNS A/AAAA 地址未成功取得；应确认确切目标 FQDN 和当前解析状态')
    if any(not x['globally_routable'] for x in ips):
        findings.append({'severity': 'medium', 'type': 'non_public_ip', 'confidence': 'high', 'evidence_ids': ids('dns'), 'detail': '外部域名解析结果出现非公网地址，需排查分视图、私有解析或污染'})
    vt = src.get('virustotal', source('skipped', summary='旧版报告未包含 VirusTotal'))
    if vt['status'] == 'ok':
        stats = vt['data'].get('last_analysis_stats') or {}
        malicious, suspicious = stats.get('malicious', 0), stats.get('suspicious', 0)
        if malicious or suspicious:
            findings.append({'severity': 'medium', 'type': 'virustotal_detection', 'confidence': 'medium', 'evidence_ids': ids('virustotal'),
                             'detail': f'VirusTotal 既有分析中 malicious={malicious}, suspicious={suspicious}；需核实具体引擎和时效，不能直接判定恶意'})
    elif vt['status'] in ('not_configured', 'error') and ctx.get('manual_threat_review_completed') is not True:
        pending.append('VirusTotal 数据不可用')
    # vt.status=skipped 且因为某些用途限制时，是合规跳过而不是技术无风险。
    us = src['urlscan']
    live = src.get('urlscan_live') or {}
    if live.get('status') == 'ok' and ((live.get('data') or {}).get('result') or {}).get('urlscan_malicious') is True:
        findings.append({'severity':'medium', 'type':'urlscan_live_malicious', 'confidence':'medium',
                         'evidence_ids':ids('urlscan_live'),
                         'detail':'本次可选实时网页扫描被 urlscan 标为恶意，需核实具体页面和相关证据'})
    if us['status'] == 'partial':
        pending.append('urlscan 部分历史扫描详情未能获取，结果不完整')
    if us['status'] in ('ok','partial'):
        flagged = [x for x in us['data'].get('results', []) if x.get('urlscan_malicious') is True]
        if flagged:
            findings.append({'severity':'medium','type':'urlscan_historical_malicious', 'confidence':'medium',
                             'evidence_ids':ids('urlscan'),
                             'detail': f'urlscan 历史记录中 {len(flagged)} 条被标记为恶意，请核实历史页面和误报；不能证明当前恶意'})
        redirects = [x for x in us['data'].get('results', [])
                     if x.get('redirected') == 'off-domain'
                     or (x.get('result_page_host') and x.get('task_url_host')
                         and x['result_page_host'].lower() != x['task_url_host'].lower())]
        if redirects:
            findings.append({'severity': 'medium', 'type': 'off_domain_redirect', 'confidence': 'low', 'evidence_ids': ids('urlscan'),
                             'detail': f'urlscan 历史记录中有 {len(redirects)} 条跨域跳转，需要判断跳转目标是否属于批准业务'})
    elif us['status'] in ('not_configured', 'error') and ctx.get('manual_threat_review_completed') is not True:
        pending.append('urlscan 历史数据未查询到')
    # 本地缓存中每个命中都记录来源；禁止把广告名单或共享 IP 自动定性恶意。
    local = src.get('local_ioc') or {}
    local_data = local.get('data') or {}
    local_ledger_id = next((e['id'] for e in report.get('evidence_ledger', []) if e.get('source') == 'local_ioc'), None)
    if local.get('status') != 'ok':
        pending.append('本地安全名单暂时无法使用')
    else:
        if any(f.get('stale') for f in local_data.get('feeds', [])):
            pending.append('本地 IOC 规则存在过期源（默认超过 7 天）：先更新并复核旧数据命中')
        active_matches = [m for m in local_data.get('matched', []) if not m.get('stale')]
        for kind, code, sev, confidence, description in [
            ('phishing_domain', 'local_phishing_ioc', 'medium', 'medium', '钓鱼域名社区名单精确 FQDN 命中'),
            ('attacking_ip', 'local_ip_association', 'medium', 'low', '解析 IP 在社区攻击来源名单中出现（CDN/共享 IP 弱关联）'),
            ('ad_tracking', 'local_adtracking', 'low', 'context_only', '域名出现在广告/追踪过滤表，不能解释为恶意域名')
        ]:
            relevant = [m for m in active_matches if m['kind'] == kind]
            if relevant:
                findings.append({'severity':sev,'type':code,'confidence':confidence,
                                 'evidence_ids':[local_ledger_id] if local_ledger_id else [],
                                 'detail': description + '：' + ', '.join(m['feed'] + ' [' + m['indicator'] + ']' for m in relevant[:5]) + '；必须人工复核源证据及误报'})
                if sev == 'medium':
                    pending.append('本地 IOC 发现待核查线索：核实是否为真实攻击资产、是否仍有效及是否共享服务')
        stale_matches = [m for m in local_data.get('matched', []) if m.get('stale')]
        if stale_matches:
            pending.append('本地 IOC 历史过期缓存曾命中，需更新验证；不把过期名单当作实时恶意情报')

    tls = src['tls']
    if tls['status'] == 'error':
        findings.append({'severity': 'medium', 'type': 'tls_probe_failed', 'confidence': 'high', 'evidence_ids': ids('tls'),
                         'detail': '主动 TLS 校验失败或不完整，可能是证书问题、端口不通或网络策略导致；需核实'})
    if tls['status'] == 'skipped' and ctx.get('tls_review_completed') is not True:
        pass  # 无主动连接权限时，TLS 探测属于可选能力
    for source_name in ('crtsh', 'ripestat'):
        if src[source_name]['status'] == 'error' and ctx.get('manual_infrastructure_review_completed') is not True:
            pending.append(f'{source_name} 查询不完整（可通过人工基础设施复核补充）')
    # 业务背景是完全可选的。未提供这些信息，不影响域名技术报告出具。
    # 如果明确提供了上传敏感数据等事实，仍提示需要谨慎处理。
    if ctx.get('data_classification') in ('confidential', 'restricted') or ctx.get('upload_data') is True:
        findings.append({'severity': 'medium', 'type': 'data_egress',
                         'detail': '计划向该网站上传敏感信息，请先核实接收方和数据处理方式'})
    if ctx.get('confirmed_malicious_evidence') is True:
        if ctx.get('confirmed_malicious_evidence_reference'):
            high_confidence = True
            findings.append({'severity': 'high', 'type': 'confirmed_malicious', 'confidence': 'human_verified', 'evidence_ids': [], 'detail': '已有经核实的恶意证据，不建议继续访问'})
        else:
            findings.append({'severity': 'medium', 'type': 'unverified_malicious_flag', 'confidence': 'unverified', 'evidence_ids': [], 'detail': '材料已勾选恶意风险，但没有证据引用，需安全人员核实'})
            pending.append('补充明确的恶意证据链接或内部情报工单编号')
    if high_confidence:
        risk = '高风险（人工确认恶意证据）'
        decision = '不建议访问该域名'
    elif any(x['severity'] == 'medium' for x in findings):
        risk = '发现可疑信号'
        decision = '建议暂缓访问，先核实提示的问题'
    elif pending:
        risk = '证据不充分，无法判定为低风险'
        decision = '信息不足，建议暂不信任此域名'
    else:
        risk = '未发现明显风险信号'
        decision = '可以谨慎访问，避免输入敏感信息或下载未知文件'
    return {'risk_label': risk, 'decision': decision, 'findings': findings,
            'pending_items': sorted(set(pending)), 'automatic_approval': False}


def technical_assessment(report):
    """Deterministic machine summary; does not pretend to approve egress."""
    src = report['sources']
    checks = ('rdap', 'dns', 'ripestat', 'crtsh', 'urlscan', 'local_ioc', 'virustotal', 'tls')
    states = {k: (src.get(k) or {}).get('status', 'not_available') for k in checks}
    positive = [f for f in report['assessment']['findings']
                if f.get('severity') in ('high', 'medium') and f.get('type') not in ('data_egress',)]
    core = ('rdap', 'dns', 'ripestat', 'crtsh', 'local_ioc')
    coverage = all(states[k] in ('ok', 'empty') for k in core)
    if positive:
        verdict = 'review_signals_detected'
        label = '已检测到风险线索（自动分析，需核实）'
    elif not coverage:
        verdict = 'insufficient_technical_evidence'
        label = '自动技术证据不足，无法排除风险'
    else:
        verdict = 'no_obvious_signals_in_checked_sources'
        label = '已完成主要自动检查，未触发明显技术风险信号（不代表安全）'
    return {
        'verdict': verdict, 'label': label,
        'source_statuses': states,
        'core_sources_complete': coverage,
        'signal_types': sorted({f.get('type') for f in positive}),
        'business_data_risk': 'not_assessed' if report['business_context'].get('context_status') == 'not_provided' else 'provided_information_only',
        'access_authorization': 'not_granted', 'automatic_approval': False,
        'limitations': '公开情报的自动判断；业务必要性、数据分类、真实归属和授权控制不能仅靠公网域名信息证明。',
    }


def auto_refresh_local_ioc(db, max_age_days=7):
    """Update approved default feeds only when missing/stale, without target disclosure."""
    local_ioc.seed_bundled_feeds(db=db)
    now = datetime.now(timezone.utc)
    rows = {r['feed']: r for r in local_ioc.list_feeds(db=db)}
    due = []
    for name, cfg in local_ioc.FEEDS.items():
        if not cfg['enabled_by_default']:
            continue
        row = rows.get(name)
        updated = parse_iso(row.get('updated_at')) if row else None
        if not updated or (now - updated).total_seconds() >= max_age_days * 86400:
            due.append(name)
    if not due:
        return {'status': 'fresh_cache', 'checked_at': utc_now(), 'refreshed': [], 'errors': {}, 'target_sent': False}
    outcome = local_ioc.update_feeds(db=db, names=due)
    errors = {k: v.get('error', '未知失败') for k, v in outcome.items() if v.get('status') != 'ok'}
    return {'status': 'partial' if errors else 'updated', 'checked_at': utc_now(),
            'refreshed': [k for k,v in outcome.items() if v.get('status') == 'ok'],
            'attempted': due, 'errors': errors, 'target_sent': False}

def locate_baseline(output_dir, host):
    """Find most recent valid report for exactly this FQDN, no human input."""
    folder = Path(output_dir)
    if not folder.is_dir():
        return None, None
    safe = re.sub(r'[^a-z0-9.-]', '_', host)
    candidates = sorted(folder.glob(safe + '_*.json'), reverse=True)
    for path in candidates[:40]:
        try:
            item = json.loads(path.read_text(encoding='utf-8'))
            if item.get('domain') == host and isinstance(item.get('sources'), dict):
                return item, str(path)
        except (ValueError, OSError, UnicodeError):
            continue
    return None, None


def md(value):
    return str(value if value is not None else '未取得').replace('|', '\\|').replace('\n', ' ')[:500]


def render_markdown(report):
    """Optional compact Markdown summary; HTML is the default report."""
    summary = report_html.summarize(report)
    lines = ['# 域名安全检查报告', '',
             f"- 域名：{report['domain']}",
             f"- 检查时间：{report['checked_at']}",
             f"- 检查结论：**{summary['title']}**",
             f"- 最终建议：**{summary['recommendation']}**", '',
             '## 发现的问题']
    lines.extend('- '+str(x.get('detail') or '待核实') for x in report['assessment'].get('findings', []))
    if not report['assessment'].get('findings'):
        lines.append('- 已完成的检查未触发明显风险线索')
    lines += ['', '## 已检查与未检查']
    for key,item in report.get('sources',{}).items():
        lines.append(f"- {report_html.SOURCE_NAMES.get(key, key)}：{item.get('status','未知')}")
    lines += ['', '## 说明', '- 缺少数据不代表没有风险；详细证据请查看同名 JSON 文件。',
              '- 以上是自动技术分析，不会修改任何访问权限。']
    return '\n'.join(lines) + '\n'


def build_report(host, registered, ctx, tls_probe=False, env=None, ioc_db=None, history_limit=URLSCAN_HISTORY_DEFAULT, live_scan=False, live_visibility="private"):
    env = env if env is not None else read_env()
    d = dns_check(host, registered)
    r = rdap_check(registered)
    ips = d['data'].get('ips', [])
    vt_usage = effective_vt_usage(env, ctx)
    sources = {
        'rdap': r, 'dns': d, 'ripestat': ripestat_check(ips),
        'crtsh': crt_check(registered),
        'urlscan': urlscan_check(host, env.get('URLSCAN_API_KEY', ''), max_scans=history_limit),
        'virustotal': vt_check(host, env.get('VT_API_KEY', ''), vt_usage),
        'local_ioc': local_ioc.inspect_cached(host, [x['ip'] for x in ips if x.get('globally_routable')],
                                              db=ioc_db or local_ioc.DEFAULT_DB),
        'tls': tls_check(host, int(ctx.get('target_port') or 443), ips, tls_probe),
        'urlscan_live': urlscan_live_check(host, env.get('URLSCAN_API_KEY', ''), enabled=live_scan,
                                          visibility=live_visibility, public_ips=[v['ip'] for v in ips if v['globally_routable']]),
    }
    instant = datetime.now(timezone.utc)
    report = {'schema_version': '2.1.0',
              'report_id': 'EDA-' + instant.strftime('%Y%m%dT%H%M%SZ') + '-' + re.sub(r'[^a-z0-9]+', '-', host)[:48],
              'checked_at': instant.isoformat(timespec='seconds'), 'domain': host,
              'registered_domain': registered, 'vt_usage': vt_usage,
              'business_context': ctx, 'sources': sources,
              'assessment': {}}
    report['evidence_ledger'], report['evidence_coverage'] = evidence_ledger(report)
    report['asset_inventory'] = build_asset_inventory(report)
    report['assessment'] = evaluate(report)
    report['technical_assessment'] = technical_assessment(report)
    result = report_html.summarize(report)
    report['assessment']['risk_label'] = result['title']
    report['assessment']['decision'] = result['recommendation']
    return report


def write_local_env(env, path=None):
    path = path or DEFAULT_ENV
    """Atomically save known settings; never output secrets to logs/reports."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    lines = ['# 本地私有配置，不要上传到 Git 或分享给他人。']
    for key in CONFIG_NAMES:
        if env.get(key) is not None:
            value = str(env[key]).replace('\n', '').replace('\r', '')
            lines.append(f'{key}={value}')
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(lines) + '\n')
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def init_cmd(args):
    """Step-by-step key setup. Called automatically by audit on first TTY run."""
    print('\n=== 免费 API 配置向导 ===')
    print('无需 API Key：DNS、RDAP、IP 归属、证书历史。')
    print('可选账号：urlscan.io、VirusTotal。获得相应 API Key 后可自动查询。')
    print('密钥只保存于本机 .env，不会显示在屏幕上，也不会写入报告。')
    env = read_env()
    interactive = sys.stdin.isatty() and not args.non_interactive
    providers = [
      ('URLSCAN_API_KEY', 'urlscan.io', 'https://urlscan.io/user/signup/',
       '注册并进入 Settings & API → New API Key；用于查询已有的公开扫描记录。'),
    ]
    for key, title, url, how in providers:
        if env.get(key) and not args.force:
            print(f'✓ {title} 已配置。')
            continue
        print(f'\n【{title}】注册地址：{url}\n获取方法：{how}')
        if interactive:
            answer = getpass.getpass(f'{title} API Key（回车跳过，输入不回显）：').strip()
            if answer:
                env[key] = answer
        else:
            print('暂无 Key 时可跳过。以后执行 setup 继续配置。')
    print('\n【VirusTotal（可选）】https://www.virustotal.com/gui/join-us')
    print('获取 Key：https://www.virustotal.com/gui/my-apikey')
    print('该服务的免费 API 有使用范围限制；仅在你确认符合官方条款后启用。')
    print('详情：' + VT_POLICY_URL)
    if interactive and (args.force or not env.get('VT_API_KEY')):
        enable = input('你已确认可使用该 API（个人非商业免费 API 或已获许可的订阅）？[y/N]：').strip().lower()
        if enable == 'y':
            tier = input('使用的授权类型：[1] 个人非商业免费 API [2] 已获许可的订阅，默认 1：').strip()
            value = getpass.getpass('VirusTotal API Key（输入不回显）：').strip()
            if value:
                env['VT_API_KEY'] = value
                if tier == '2':
                    env['VT_API_TIER'] = 'premium'
                    env.pop('VT_USAGE', None)
                else:
                    env['VT_USAGE'] = 'noncommercial'
                    env.pop('VT_API_TIER', None)
    env['ONBOARDING_DONE'] = 'yes' if interactive else env.get('ONBOARDING_DONE', 'no')
    write_local_env(env)
    print('\n配置已保存到本机：' + str(DEFAULT_ENV))
    print('以后可以直接 audit --domain example.com；要补充 Key 可再次运行 setup。')
    return 0


def set_key_cmd(args):
    """Configure a user-supplied API key safely from stdin (Agent) or hidden TTY input.

    Do not include secret bytes in shell arguments, transcripts, logs, reports, or source files.
    """
    if args.name not in CREDENTIAL_NAMES:
        raise ValueError('不支持该 API Key 配置项')
    if args.stdin:
        value = sys.stdin.readline().strip()
    elif sys.stdin.isatty():
        value = getpass.getpass(f'{args.name}（隐藏输入）：').strip()
    else:
        raise ValueError('非交互模式请使用 --stdin 从标准输入安全读取 Key')
    if not value or len(value) > 4096 or any(c in value for c in '\n\r\x00'):
        raise ValueError('API Key 为空或格式异常')
    env = read_env()
    env[args.name] = value
    if args.name == 'VT_API_KEY' and args.vt_tier:
        if args.vt_tier == 'premium':
            env['VT_API_TIER'] = 'premium'
            env.pop('VT_USAGE', None)
        else:
            env['VT_USAGE'] = 'noncommercial'
            env.pop('VT_API_TIER', None)
    env['ONBOARDING_DONE'] = 'yes'
    write_local_env(env)
    print(f'{args.name} 已保存到本地私有配置文件（不会显示密钥）。')
    return 0


def doctor_cmd(args):
    env = read_env()
    print('=== API 配置检查 ===')
    for key, label in [('URLSCAN_API_KEY', 'urlscan'),
                       ('VT_API_KEY', 'VirusTotal')]:
        eligible = key != 'VT_API_KEY' or effective_vt_usage(env) != 'not_enabled'
        print(label + ': ' + ('已配置' if env.get(key) and eligible else '未启用'))
    if not args.online:
        print('如需验证接口连通性，请运行 doctor --online。')
        return 0
    tests = {
        'IANA RDAP': lambda: bool(req_json(RDAP_BOOTSTRAP).get('services')),
        'RIPEstat': lambda: req_json(RIPESTAT_API, params={'resource':'1.1.1.1'}).get('status') == 'ok',
    }
    if env.get('URLSCAN_API_KEY'):
        tests['urlscan'] = lambda: req_json('https://urlscan.io/api/v1/quotas', headers={'api-key': env['URLSCAN_API_KEY']}) is not None
    if env.get('VT_API_KEY') and effective_vt_usage(env) != 'not_enabled':
        tests['VirusTotal'] = lambda: req_json(VT_DOMAIN_API + '/example.com', headers={'x-apikey': env['VT_API_KEY']}).get('data') is not None
    for name, check in tests.items():
        try:
            print(name + ': ' + ('正常' if check() else '返回数据无法识别'))
        except (requests.RequestException, ValueError) as exc:
            print(name + ': 暂时失败（' + type(exc).__name__ + '），不会影响其他检查')
    return 0


def audit_cmd(args):
    """One-command unattended collection & reporting; no interactive prompts."""
    host, registered = validated_domain(args.domain)
    if args.registered_domain:
        override, _ = validated_domain(args.registered_domain)
        if host != override and not host.endswith('.' + override):
            raise ValueError('--registered-domain 必须是目标 FQDN 的父域名')
        registered = override
    if sys.stdin.isatty() and not getattr(args, 'no_prompt', False) and read_env().get('ONBOARDING_DONE') != 'yes':
        print('首次使用，先配置免费的威胁情报 API。')
        init_cmd(argparse.Namespace(force=False, non_interactive=False))
    ctx, _ = read_context(args.business_file, host)
    tls_probe = not getattr(args, 'no_tls_probe', False)
    if tls_probe:
        print('TLS：默认检查目标公网 IP:443（SNI 证书验证，不发送 HTTP 请求；可使用 --no-tls-probe 关闭）。')
    usage = effective_vt_usage(read_env(), ctx)
    if getattr(args, 'live_scan', False):
        print(f'按用户选择将向 urlscan.io 提交 https://{host}/ 的实时扫描，可见性：{args.live_visibility}。')
    print(f'正在检查 {host}，检查完成后会生成易读的 HTML 报告。')
    db = getattr(args, 'ioc_db', str(local_ioc.DEFAULT_DB))
    if getattr(args, 'no_auto_ioc_update', False):
        sync = {'status': 'disabled_by_argument', 'checked_at': utc_now(), 'target_sent': False}
    else:
        try:
            sync = auto_refresh_local_ioc(db)
        except (OSError, ValueError, local_ioc.sqlite3.Error) as exc:
            sync = {'status': 'error', 'checked_at': utc_now(), 'errors': {'local_ioc': str(exc)[:200]}, 'target_sent': False}
    if sync['status'] in ('partial', 'error'):
        print('本地 IOC 名单更新不完整：保留历史缓存，并在报告中说明；继续其他检查。')
    report = build_report(host, registered, ctx, tls_probe, ioc_db=db,
                          history_limit=getattr(args, 'history_limit', URLSCAN_HISTORY_DEFAULT),
                          live_scan=getattr(args,'live_scan',False),
                          live_visibility=getattr(args,'live_visibility','private'))
    out = Path(args.output).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    previous, baseline_path = (None, None)
    if getattr(args, 'baseline', None):
        baseline_path = str(Path(args.baseline).expanduser())
        previous = json.loads(Path(baseline_path).read_text(encoding='utf-8'))
    elif not getattr(args, 'no_auto_baseline', False):
        previous, baseline_path = locate_baseline(out, host)
    if previous is not None:
        attach_baseline(report, previous)
    # Ensure HTML and JSON summaries remain exactly consistent even after baseline comparison.
    user_summary = report_html.summarize(report)
    report['assessment']['risk_label'] = user_summary['title']
    report['assessment']['decision'] = user_summary['recommendation']
    report['execution'] = {'mode': 'unattended', 'ioc_refresh': sync,
                           'baseline_file': baseline_path, 'manual_input_required': False,
                           'api_keys_optional': True}
    safe = re.sub(r'[^a-z0-9.-]', '_', host)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    base = out / f'{safe}_{stamp}'
    counter = 1
    while Path(str(base) + '.json').exists() or Path(str(base) + '.html').exists():
        base = out / f'{safe}_{stamp}_{counter:02d}'
        counter += 1
    jfile = Path(str(base) + '.json')
    hfile = Path(str(base) + '.html')
    jfile.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    hfile.write_text(report_html.render(report), encoding='utf-8')
    if getattr(args, 'markdown', False):
        Path(str(base) + '.md').write_text(render_markdown(report), encoding='utf-8')
    result = report_html.summarize(report)
    print('检查结论：' + result['title'])
    print('建议：' + result['recommendation'])
    print('HTML:', hfile)
    print('JSON:', jfile)
    return 0


def ioc_update_cmd(args):
    names = [name for name, cfg in local_ioc.FEEDS.items() if cfg['enabled_by_default']]
    if getattr(args, 'exclude_adtracking', False):
        names = [name for name in names if name != 'cn_antiad']
    print('仅获取开源静态数据，不上传申请域名/IP；不会自动封禁。')
    results = local_ioc.update_feeds(db=args.ioc_db, names=names)
    for key, value in results.items():
        print(f"{key}: {value['status']} ({value.get('count', value.get('error', '未知'))})")
    print('原有成功缓存遇下载失败会保留；失败源不得当作无命中。')
    return 0 if all(v['status'] == 'ok' for v in results.values()) else 1


def ioc_import_cmd(args):
    if args.feed not in local_ioc.FEEDS:
        raise ValueError('非允许的数据源')
    p = Path(args.file).expanduser().resolve()
    if not p.is_file() or p.stat().st_size > local_ioc.MAX_BYTES:
        raise ValueError('源文件不存在或超出安全大小限制')
    payload = p.read_bytes()
    print('只从本地文件导入离线 IOC；不做任何外部请求、不会自动封禁。')
    result = local_ioc.update_feeds(args.ioc_db, names=[args.feed], fetcher=lambda url: payload)
    row = result[args.feed]
    print(f"{args.feed}: {row['status']} ({row.get('count', row.get('error', '未知'))})")
    return 0 if row['status']=='ok' else 1


def ioc_status_cmd(args):
    rows = local_ioc.list_feeds(db=args.ioc_db)
    if not rows:
        print('尚无本地 IOC 数据库或快照；请执行 ioc-update。')
        return 0
    for row in rows:
        print(f"{row['feed']}: {row['item_count']} 条 | 更新 {row['updated_at']} | SHA256 {row['sha256']} | {row['license']}")
    return 0


def ioc_check_cmd(args):
    host, _ = validated_domain(args.domain)
    res = local_ioc.inspect_cached(host, args.ip or [], db=args.ioc_db)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description='免费域名安全检查：首次引导配置 API，自动生成 HTML 风险报告')
    sub = parser.add_subparsers(dest='command', required=True)
    s_init = sub.add_parser('setup', aliases=['init'], help='配置或补充免费 API Key（交互式向导）')
    s_init.add_argument('--force', action='store_true', help='覆盖现有本地配置（谨慎）')
    s_init.add_argument('--non-interactive', action='store_true', help='只创建空密钥配置，不提示输入')
    s_key = sub.add_parser('set-key', help='从 stdin 或隐藏输入保存 API Key（适用于对话式 Agent）')
    s_key.add_argument('--name', choices=CREDENTIAL_NAMES, required=True)
    s_key.add_argument('--stdin', action='store_true', help='从标准输入读取密钥，避免通过命令行参数暴露')
    s_key.add_argument('--vt-tier', choices=['noncommercial','premium'], help='VirusTotal 授权类型，仅当用户确认符合条款后使用')
    s_doctor = sub.add_parser('doctor', help='检查配置，可选择检查外部 API 连通性')
    s_doctor.add_argument('--online', action='store_true', help='联网检查公共端点及已配置的 API Key')
    s_audit = sub.add_parser('audit', help='一键域名检查，生成 HTML 和 JSON 报告')
    s_audit.add_argument('--domain', required=True, help='例如 ifuwuyun.com；不要传完整 URL')
    s_audit.add_argument('--registered-domain', help='复杂多级后缀时手动指定经核实的注册域名')
    s_audit.add_argument('--business-file', help='可选补充资料 JSON；普通用户无需使用')
    s_audit.add_argument('--baseline', help='可选的指定历史报告；默认自动使用 reports 中最新同域名 JSON')
    s_audit.add_argument('--no-auto-baseline', action='store_true', help='关闭自动历史基线比较')
    s_audit.add_argument('--output', default=str(ROOT / 'reports'), help='HTML 与 JSON 报告保存位置')
    s_audit.add_argument('--markdown', action='store_true', help='额外生成旧版 Markdown 技术报告')
    s_audit.add_argument('--no-prompt', action='store_true', help='不弹出首次 API 配置向导，适用于自动化任务')
    s_audit.add_argument('--tls-probe', action='store_true', help='兼容旧版参数；TLS 默认开启')
    s_audit.add_argument('--no-tls-probe', action='store_true', help='关闭默认 TLS 实时连接（仅被动查询）')
    s_audit.add_argument('--history-limit', type=int, choices=range(1, 51), metavar='1-50', default=15, help='默认分析最多 15 条历史扫描的详细结果；最多 50 条，受账号配额限制')
    s_audit.add_argument('--live-scan', action='store_true', help='明确同意通过 urlscan.io 远程扫描目标网站，默认不提交')
    s_audit.add_argument('--live-visibility', choices=['private','unlisted','public'], default='private', help='远程扫描结果可见性，默认 private，不自动降低隐私等级')
    s_audit.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB), help='本地安全名单 SQLite 路径')
    s_audit.add_argument('--no-auto-ioc-update', action='store_true', help='禁用自动更新，仍使用现有本地缓存')
    s_ioc_update = sub.add_parser('ioc-update', help='更新免费开源 IOC 名单；不发送被检测域名')
    s_ioc_update.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))
    s_ioc_update.add_argument('--include-adtracking', action='store_true', help='兼容旧版参数；anti-AD 默认启用')
    s_ioc_update.add_argument('--exclude-adtracking', action='store_true', help='可选跳过 anti-AD 下载')
    s_ioc_update.add_argument('--license-reviewed', action='store_true', help='兼容旧版参数；请自行查看数据来源及许可证')
    s_ioc_import = sub.add_parser('ioc-import', help='从本地文件导入公开 IOC 清单')
    s_ioc_import.add_argument('--feed', choices=list(local_ioc.FEEDS), required=True)
    s_ioc_import.add_argument('--file', required=True)
    s_ioc_import.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))
    s_ioc_import.add_argument('--license-reviewed', action='store_true', help='兼容旧版参数')
    s_ioc_status = sub.add_parser('ioc-status', help='查看规则库版本与更新时间')
    s_ioc_status.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))
    s_ioc_check = sub.add_parser('ioc-check', help='使用本地 IOC 数据库离线检查')
    s_ioc_check.add_argument('--domain', required=True)
    s_ioc_check.add_argument('--ip', action='append')
    s_ioc_check.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))

    args = parser.parse_args(argv)
    try:
        return {'init': init_cmd, 'setup': init_cmd, 'set-key': set_key_cmd, 'doctor': doctor_cmd, 'audit': audit_cmd,
                'ioc-update': ioc_update_cmd, 'ioc-import': ioc_import_cmd,
                'ioc-status': ioc_status_cmd, 'ioc-check': ioc_check_cmd}[args.command](args)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        parser.exit(2, f'参数/配置错误：{exc}\n')
    except KeyboardInterrupt:
        parser.exit(130, '已中断\n')


if __name__ == '__main__':
    sys.exit(main())
