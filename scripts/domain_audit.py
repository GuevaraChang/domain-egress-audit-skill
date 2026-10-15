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
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import dns.exception
import dns.resolver
import requests
# 支持 importlib 按绝对路径加载 CLI（单元测试 / Agent 容器）
sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_ioc
import report_html

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV = ROOT / '.env'
UA = 'DomainEgressAuditSkill/1.6 (passive domain safety check)'
TIMEOUT = 9
RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json'
OTX_BASE = 'https://otx.alienvault.com/api/v1/indicators/domain'
URLSCAN_SEARCH = 'https://urlscan.io/api/v1/search/'
VT_DOMAIN_API = 'https://www.virustotal.com/api/v3/domains'
VT_POLICY_URL = 'https://docs.virustotal.com/reference/public-vs-premium-api'
VT_KEY_URL = 'https://www.virustotal.com/gui/my-apikey'
THREATBOOK_API = 'https://api.threatbook.cn/v3/domain/query'
DOMESTIC_PORTALS = {
    'threatbook_x': ('微步在线 X 情报社区', 'https://x.threatbook.com/'),
    'qianxin_ti': ('奇安信威胁情报中心', 'https://ti.qianxin.com/portal/'),
    'tencent_tix': ('腾讯安全威胁情报中心', 'https://tix.qq.com/'),
}
DOMESTIC_VERDICTS = {'malicious', 'suspicious', 'no_known_threat', 'inconclusive'}
DOMESTIC_LABELS = {
    'malicious':'命中恶意情报（待人工验证）',
    'suspicious':'存在可疑线索',
    'no_known_threat':'当前未发现已知恶意（不等于安全）',
    'inconclusive':'信息不足/无法定性',
}

RIPESTAT_API = 'https://stat.ripe.net/data/network-info/data.json'
COMMON_SECOND_LEVEL_SUFFIXES = {'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'or.jp', 'ne.jp', 'com.hk', 'com.tw', 'com.sg', 'com.my', 'co.nz', 'com.br', 'co.kr'}
CREDENTIAL_NAMES = ('OTX_API_KEY', 'URLSCAN_API_KEY', 'VT_API_KEY', 'THREATBOOK_API_KEY')
CONFIG_NAMES = CREDENTIAL_NAMES + ('VT_USAGE', 'VT_API_TIER', 'THREATBOOK_API_AUTHORIZED', 'ONBOARDING_DONE')
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


def otx_check(host, api_key):
    if not api_key:
        return source('not_configured', summary='OTX API Key 未配置，可继续基础检查', url='https://otx.alienvault.com/api/')
    url = f'{OTX_BASE}/{quote(host, safe="")}/general'
    try:
        raw = req_json(url, headers={'X-OTX-API-KEY': api_key})
        pi = raw.get('pulse_info') or {}
        pulses = pi.get('pulses') or []
        count = pi.get('count', len(pulses))
        return source('ok', summary='社区 Pulse 仅为调查线索，不能直接证明域名恶意',
                      data={'pulse_count': count, 'pulse_examples': [{'name': p.get('name'),
                            'id': p.get('id'), 'modified': p.get('modified')} for p in pulses[:8]]}, url=url)
    except (requests.RequestException, ValueError, KeyError) as exc:
        return source('error', error=exc, url=url)


def urlscan_check(host, api_key):
    # Only searches PRE-EXISTING public scans; never submits scans or internal URLs.
    if not api_key:
        return source('not_configured', summary='urlscan API Key 未配置；不主动提交 URL', url='https://urlscan.io/docs/api/')
    try:
        raw = req_json(URLSCAN_SEARCH, headers={'api-key': api_key},
                       params={'q': f'(task.domain.keyword:"{host}" OR page.domain.keyword:"{host}")', 'size': 15})
        items = []
        for entry in raw.get('results') or []:
            page = entry.get('page') or {}
            task = entry.get('task') or {}
            if (page.get('domain') or '').lower() != host and (task.get('domain') or '').lower() != host:
                continue
            items.append({'scan_time': task.get('time'), 'task_url_host': task.get('domain'),
                          'result_page_host': urlparse(page.get('url') or '').hostname, 'status_code': page.get('status'),
                          'redirected': page.get('redirected'), 'result_url': entry.get('result'),
                          'ip': page.get('ip'), 'scope': '历史第三方扫描，不代表当前访问路径',
                          'relation_confidence': 'low' if (page.get('domain') or '').lower() != host else 'medium'})
        return source('ok' if items else 'empty', summary='仅查询已有扫描历史；样本不全面且部分历史可能已过期',
                      data={'matched_results': len(items), 'results': items[:15],
                            'returned_results': len(raw.get('results') or [])},
                      url='https://urlscan.io/search/#task.domain.keyword:' + quote(host))
    except (requests.RequestException, ValueError, KeyError) as exc:
        return source('error', error=exc, url=URLSCAN_SEARCH)



def threatbook_check(host, env):
    """Optional Chinese TI API. Never consume uncertain/free domain quota or commercial rights.

    Users must explicitly attest their account has this endpoint enabled AND their
    organization permits this exact use. Default: zero network requests.
    API key is sent only in HTTPS POST body, never in the report, URL or logging.
    """
    if str(env.get('THREATBOOK_API_AUTHORIZED', '')).strip().lower() != 'yes':
        return source('skipped', summary='微步在线域名分析 API 未声明获得接口额度与机构用途授权；免费 X 网页人工核查仍可用',
                      data={'skip_reason':'license_or_quota_not_confirmed','api_called':False},
                      url='https://x.threatbook.com/apiDocs/start/confirm_api_permissions')
    key = env.get('THREATBOOK_API_KEY', '').strip()
    if not key:
        return source('not_configured', summary='已确认使用许可但没有配置微步在线 API Key',
                      data={'api_called':False}, url='https://x.threatbook.com/apiDocs/domain/query')
    try:
        # API 官方支持 POST/GET；选择 POST 以避免 apikey 出现在 URL/代理访问日志。
        response = requests.post(THREATBOOK_API, data={'apikey':key,'resource':host,'lang':'zh'},
                                 headers={'User-Agent':UA,'Accept':'application/json'},
                                 timeout=TIMEOUT, allow_redirects=False)
        if 300 <= response.status_code < 400:
            raise ValueError('接口重定向已拒绝，防止凭据泄露')
        response.raise_for_status()
        raw = response.json()
        if raw.get('response_code') != 0:
            # Do not echo raw error messages; they may include request values.
            raise ValueError('接口业务响应失败或权限/配额不足：response_code=' + str(raw.get('response_code'))[:15])
        domain_result = (raw.get('data') or {}).get(host)
        if not isinstance(domain_result, dict):
            raise ValueError('正常响应中缺少目标 FQDN 对应情报')
        judgments = domain_result.get('judgments') or []
        if not isinstance(judgments, list):
            judgments = []
        ioc = domain_result.get('intelligences') or {}
        evidence = []
        for bucket in ('threatbook_lab','x_reward','open_source'):
            for row in (ioc.get(bucket) or [])[:12]:
                if not isinstance(row, dict):
                    continue
                evidence.append({'category':bucket,'source':str(row.get('source') or '')[:80],
                                 'intel_types':list(row.get('intel_types') or [])[:10],
                                 'expired':row.get('expired'),
                                 'confidence':row.get('confidence'),
                                 'observed_at':row.get('find_time'), 'updated_at':row.get('update_time')})
        return source('ok', summary='微步在线域名情报返回；区分实验室/奖励计划/开源转载，结果须人工核实',
            data={'api_called':True,'target_domain':host,'judgments':[str(x)[:60] for x in judgments[:20]],
                  'intelligences':evidence[:25],
                  'sample_count':len(domain_result.get('samples') or []),
                  'source_independence_note':'open_source 可能转载 OTX 等情报，不得作为独立第二家佐证'},
            url='https://x.threatbook.com/')
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        # Suppress external text; avoid accidentally serializing request's apikey.
        return source('error', summary='微步 API 查询未成功，不得计为零命中',
                      data={'api_called':True,'error_type':type(exc).__name__},
                      url='https://x.threatbook.com/apiDocs/domain/query')


def load_domestic_evidence(path, host):
    """Read an explicitly provided *local* analyst review, not scraped platform results.

    The evidence has to match the exact FQDN. Claim of a threat never becomes
    confirmed malicious automatically; even two hits require review.
    """
    if not path:
        return {}
    obj = json.loads(Path(path).expanduser().read_text(encoding='utf-8'))
    if not isinstance(obj, dict) or validated_domain(str(obj.get('target_fqdn','')))[0] != host:
        raise ValueError('国内情报人工核查记录中的 target_fqdn 必须与审查目标完全一致')
    reviews = obj.get('reviews') or {}
    if not isinstance(reviews, dict):
        raise ValueError('reviews 必须是以平台代码为键的 JSON 对象')
    unexpected = set(reviews) - set(DOMESTIC_PORTALS)
    if unexpected:
        raise ValueError('未知国内情报平台代码：'+', '.join(sorted(unexpected)))
    parsed = {}
    for provider, row in reviews.items():
        if not isinstance(row, dict):
            raise ValueError(provider + ' 必须是 JSON 对象')
        verdict = str(row.get('verdict') or '').strip().lower()
        if verdict not in DOMESTIC_VERDICTS:
            raise ValueError(provider + ' 的 verdict 不受支持：'+verdict)
        fqdn = validated_domain(str(row.get('queried_fqdn') or ''))[0]
        if fqdn != host:
            raise ValueError(provider + ' 的 queried_fqdn 不匹配当前申请 FQDN')
        checked = row.get('checked_at')
        if not parse_iso(checked):
            raise ValueError(provider + ' 必须提供真实 checked_at（ISO 8601），不可把采集时间冒充观测时间')
        reviewer = str(row.get('reviewer') or '').strip()
        ref = str(row.get('evidence_ref') or '').strip()
        if not reviewer or not ref:
            raise ValueError(provider + ' 必须填 reviewer 与截图/工单 evidence_ref，避免无依据自报无风险')
        parsed[provider] = {
            'verdict':verdict, 'queried_fqdn':host, 'checked_at':checked,
            'reviewer':reviewer[:100], 'evidence_ref':ref[:220],
            'notes':str(row.get('notes') or '')[:350],
            'exact_fqdn_match':True, 'manually_supplied':True,
        }
    return parsed


def domestic_manual_source(key, record):
    title, url = DOMESTIC_PORTALS[key]
    if not record:
        return source('not_configured', summary=f'{title}：未导入人工核查证据（不是零命中）',
                      data={'manual_only':True}, url=url)
    return source('ok', summary=f'本地人工提供的网页复核结果：{DOMESTIC_LABELS[record["verdict"]]}（未由脚本验证网页真伪）',
                  data=record, url=url)


def domestic_cross_validate(src):
    """Separate sources, not votes. Avoid multiplying mirrors of a single IOC feed."""
    matrix = []
    threat_sources = []
    for key in DOMESTIC_PORTALS:
        row = src.get(key+'_manual') or {}
        info = row.get('data') or {}
        verdict = info.get('verdict') if row.get('status') == 'ok' else None
        matrix.append({'provider':key,'name':DOMESTIC_PORTALS[key][0],
                       'mode':'manual_review','status':row.get('status','not_configured'),
                       'verdict':verdict,'label':DOMESTIC_LABELS.get(verdict,'未取得'),
                       'checked_at':info.get('checked_at'), 'evidence_ref':info.get('evidence_ref'),
                       'exact_fqdn_match':info.get('exact_fqdn_match',False)})
        if verdict in ('malicious','suspicious'):
            threat_sources.append(key)
    t = src.get('threatbook_api') or {}
    td = t.get('data') or {}
    matrix.append({'provider':'threatbook_api','name':'微步在线域名分析 API',
                   'mode':'authorized_api','status':t.get('status','skipped'),
                   'verdict':'unreviewed_indicators' if t.get('status')=='ok' else None,
                   'label':'原始标签/情报待复核' if t.get('status')=='ok' else '未取得',
                   'judgments':td.get('judgments',[])})
    # 本地静态 feed 与人工厂商结论属于不同层次，不能凑成“两家厂商”。
    loc = (src.get('local_ioc') or {}).get('data') or {}
    local_groups = set()
    for feed in loc.get('feeds', []):
        relevant = [m for m in loc.get('matched', []) if m['feed'] == feed['feed']]
        fresh_hits = [m for m in relevant if not m.get('stale')]
        if fresh_hits and feed.get('kind') == 'phishing_domain':
            local_groups.add(feed.get('origin_group'))
        matrix.append({'provider':feed['feed'], 'name':feed['title'], 'mode':'offline_feed',
                       'status':'stale' if feed['stale'] else 'ok',
                       'verdict':'candidate' if fresh_hits else None,
                       'label':('精确域名疑似钓鱼线索' if feed['kind'] == 'phishing_domain' else
                                '仅解析 IP 弱关联' if feed['kind'] == 'attacking_ip' else
                                '广告/跟踪名单，非恶意证据') if fresh_hits else '本地缓存未命中（不等于安全）',
                       'checked_at':feed['updated_at'], 'evidence_ref':feed['project'],
                       'origin_group':feed.get('origin_group'), 'fresh_hit_count':len(fresh_hits),
                       'correlation_only':True})
    manual_checked = [x for x in matrix if x['mode']=='manual_review' and x['status']=='ok']
    negatives = [x['provider'] for x in manual_checked if x['verdict']=='no_known_threat']
    if threat_sources and negatives:
        alignment = 'conflicting_sources_require_investigation'
    elif len(threat_sources) >= 2:
        alignment = 'multiple_vendor_alerts_verify_common_upstream'
    elif threat_sources:
        alignment = 'single_vendor_alert_requires_review'
    elif len(manual_checked) >= 2:
        alignment = 'no_known_hits_not_proven_safe'
    else:
        alignment = 'insufficient_domestic_coverage'
    # Vendor-level unique coverage; the same provider's webpage and API are not two votes.
    checked_providers = {x['provider'] for x in manual_checked}
    if t.get('status') == 'ok':
        checked_providers.add('threatbook_x')
    return {'matrix':matrix, 'manual_hit_providers':threat_sources,
            'manual_checked_count':len(manual_checked),
            'unique_vendor_count':len(checked_providers), 'alignment':alignment,
            'needs_analyst_validation':True, 'local_security_origin_groups': sorted(local_groups),
            'methodology':'各平台可转载相同 IOC，不能把 2 家命中等同独立确认；仅精确 FQDN、原始证据、时效核验后由安全人员定性。',
            'api_rights_notice':'微步 API 仅账号实际授予域名接口额度且机构用途已获许可时调用，默认跳过。'}


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
        'otx': ('OTX', '社区 Pulse，仅为可疑关联线索', None),
        'urlscan': ('urlscan', '公开历史扫描，可能过时/样本有偏', 'latest_scan'),
        'virustotal': ('VirusTotal', '第三方检测统计，不等于恶意定性；某些用途自动跳过', 'last_analysis_date'),
        'tls': ('可选 TLS 探测', '仅在明确授权时可做的实时目标连接', None),
        'threatbook_api': ('微步域名情报 API', '仅在确认接口额度/机构授权后使用；含来源转载；不是恶意证明', None),
        'threatbook_x_manual': ('微步 X 人工网页', '用户提供截图/工单；非程序自动验证；不得与微步 API 算两家独立平台', 'checked_at'),
        'qianxin_ti_manual': ('奇安信人工网页', '用户提供截图/工单；非程序自动验证', 'checked_at'),
        'tencent_tix_manual': ('腾讯威胁情报人工网页', '用户提供截图/工单；不保证全部查询功能免费', 'checked_at'),
        'local_ioc': ('中国开源本地 IOC 规则库', '本地离线精确域名匹配/解析 IP 弱关联；广告名单不是恶意定性', None),
    }
    ledger = []
    status_counts = {k: 0 for k in ('ok', 'empty', 'error', 'not_configured', 'skipped')}
    stale = []
    for index, (key, item) in enumerate(report['sources'].items(), 1):
        title, meaning, time_key = semantics.get(key, (key, '未分类证据', None))
        record = item.get('data') or {}
        observed = record.get(time_key) if time_key else None
        if key.endswith('_manual'):
            observed = record.get('checked_at')
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
            'evidence_ids': ['EV-02', 'EV-01'],
            'detail': f"与基线相比有 {len(comparison['changes'])} 项变化；仅为待核查信号，不是恶意证据。"})
        report['assessment']['risk_label'] = '存在风险信号，需人工调查'
        report['assessment']['decision'] = '检测到历史变化，建议核实后再访问'
    if 'technical_assessment' in report:
        report['technical_assessment'] = technical_assessment(report)
    return report

def evaluate(report):
    src = report['sources']
    ctx = report['business_context']
    findings = []
    pending = []
    high_confidence = False
    rd = src['rdap']
    if rd['status'] == 'ok':
        age = rd['data'].get('age_days')
        if isinstance(age, int) and age < 0:
            findings.append({'severity': 'medium', 'type': 'rdap', 'detail': 'RDAP 创建时间晚于当前时间；需核验时钟或注册数据'})
        elif isinstance(age, int) and age < 30:
            findings.append({'severity': 'medium', 'type': 'new_domain', 'confidence': 'medium', 'evidence_ids': ['EV-01'], 'detail': f'域名注册仅 {age} 天，建议加强主体核验'})
        elif isinstance(age, int) and age < 90:
            findings.append({'severity': 'low', 'type': 'young_domain', 'confidence': 'medium', 'evidence_ids': ['EV-01'], 'detail': f'域名注册约 {age} 天，建议关注业务匹配性'})
    else:
        pending.append('RDAP 注册信息未成功获取')
    dns_data = src['dns']['data']
    ips = dns_data.get('ips') or []
    if src['dns']['status'] == 'error' or not ips:
        pending.append('DNS A/AAAA 地址未成功取得；应确认确切目标 FQDN 和当前解析状态')
    if any(not x['globally_routable'] for x in ips):
        findings.append({'severity': 'medium', 'type': 'non_public_ip', 'confidence': 'high', 'evidence_ids': ['EV-02'], 'detail': '外部域名解析结果出现非公网地址，需排查分视图、私有解析或污染'})
    vt = src.get('virustotal', source('skipped', summary='旧版报告未包含 VirusTotal'))
    if vt['status'] == 'ok':
        stats = vt['data'].get('last_analysis_stats') or {}
        malicious, suspicious = stats.get('malicious', 0), stats.get('suspicious', 0)
        if malicious or suspicious:
            findings.append({'severity': 'medium', 'type': 'virustotal_detection', 'confidence': 'medium', 'evidence_ids': ['EV-07'],
                             'detail': f'VirusTotal 既有分析中 malicious={malicious}, suspicious={suspicious}；需核实具体引擎和时效，不能直接判定恶意'})
    elif vt['status'] in ('not_configured', 'error') and ctx.get('manual_threat_review_completed') is not True:
        pending.append('VirusTotal 数据不可用')
    # vt.status=skipped 且因为某些用途限制时，是合规跳过而不是技术无风险。
    otx = src['otx']
    if otx['status'] == 'ok' and (otx['data'].get('pulse_count') or 0) > 0:
        findings.append({'severity': 'medium', 'type': 'otx_pulse', 'confidence': 'low', 'evidence_ids': ['EV-05'],
                         'detail': f"OTX 存在 {otx['data']['pulse_count']} 条关联 Pulse，仅为社区关联线索，需要人工判定相关性与时效"})
    if otx['status'] in ('not_configured', 'error') and ctx.get('manual_threat_review_completed') is not True:
        pending.append('OTX 情报未查询到')
    us = src['urlscan']
    if us['status'] == 'ok':
        redirects = [x for x in us['data'].get('results', [])
                     if x.get('redirected') == 'off-domain'
                     or (x.get('result_page_host') and x.get('task_url_host')
                         and x['result_page_host'].lower() != x['task_url_host'].lower())]
        if redirects:
            findings.append({'severity': 'medium', 'type': 'off_domain_redirect', 'confidence': 'low', 'evidence_ids': ['EV-06'],
                             'detail': f'urlscan 历史记录中有 {len(redirects)} 条跨域跳转，需要判断跳转目标是否属于批准业务'})
    elif us['status'] in ('not_configured', 'error') and ctx.get('manual_threat_review_completed') is not True:
        pending.append('urlscan 历史数据未查询到')
    # 国内平台的人工情报不是机器校验；命中优先人工核实原始 IOC，不能直接凭命中数判定恶意。
    cn = report.get('domestic_cross_validation') or domestic_cross_validate(src)
    if cn.get('unique_vendor_count',0) < 2 and ctx.get('domestic_intel_review_waived') is not True:
        pending.append('国内情报覆盖有限；已使用可自动查询的数据源，未查询到的平台不计为安全')
    if cn.get('alignment') == 'conflicting_sources_require_investigation':
        pending.append('国内情报结论冲突：逐条对照原始 IOC、标签生效时间和数据来源')
    if cn['manual_hit_providers']:
        findings.append({'severity':'medium','type':'domestic_intel_hit',
                         'confidence':'manual_unverified',
                         'evidence_ids':[f'EV-{9+list(DOMESTIC_PORTALS).index(k)+1:02d}' for k in cn['manual_hit_providers']],
                         'detail':'国内平台人工记录存在恶意/可疑线索：' + ', '.join(cn['manual_hit_providers']) +
                                  '；需复核原始证据、是否精确命中 FQDN，以及来源独立性'})
        pending.append('国内情报有命中：需安全人员核实原始证据与来源独立性')
    tb = src.get('threatbook_api') or {}
    if tb.get('status') == 'ok':
        d = tb.get('data') or {}
        # Labels do not all mean malicious (e.g. Whitelist or ICP); avoid naive positive-match rules.
        benign = {'whitelist','icp','unknown','other'}
        live = [e for e in d.get('intelligences',[]) if e.get('expired') is False
                and e.get('category') in ('threatbook_lab','x_reward')
                and any(str(x).lower() not in benign for x in e.get('intel_types',[]))]
        if live:
            findings.append({'severity':'medium','type':'threatbook_intel_signal',
                'confidence':'source_claim_requires_review','evidence_ids':['EV-09'],
                'detail':f'微步原生/奖励情报有 {len(live)} 条未过期的非白名单类型记录；需核验类别与原始证据'})
            pending.append('微步 API 威胁标签需人工确认（区分原生与转载情报）')
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
        findings.append({'severity': 'medium', 'type': 'tls_probe_failed', 'confidence': 'high', 'evidence_ids': ['EV-08'],
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
    checks = ('rdap', 'dns', 'ripestat', 'crtsh', 'otx', 'urlscan', 'local_ioc',
              'threatbook_api', 'virustotal')
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
        'limitations': '公开情报和已加载 IOC 的自动判断；业务必要性、数据分类、真实归属和授权控制不能仅靠公网域名信息证明。',
    }


def auto_refresh_local_ioc(db, max_age_days=7):
    """Update approved default feeds only when missing/stale, without target disclosure."""
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


def build_report(host, registered, ctx, tls_probe=False, env=None, domestic_reviews=None, ioc_db=None):
    env = env if env is not None else read_env()
    d = dns_check(host, registered)
    r = rdap_check(registered)
    ips = d['data'].get('ips', [])
    vt_usage = effective_vt_usage(env, ctx)
    sources = {
        'rdap': r, 'dns': d, 'ripestat': ripestat_check(ips),
        'crtsh': crt_check(registered), 'otx': otx_check(host, env.get('OTX_API_KEY', '')),
        'urlscan': urlscan_check(host, env.get('URLSCAN_API_KEY', '')),
        'virustotal': vt_check(host, env.get('VT_API_KEY', ''), vt_usage),
        'tls': tls_check(host, int(ctx.get('target_port') or 443), ips, tls_probe),
        'threatbook_api': threatbook_check(host, env),
        **{key+'_manual':domestic_manual_source(key,(domestic_reviews or {}).get(key))
           for key in DOMESTIC_PORTALS},
        'local_ioc': local_ioc.inspect_cached(host, [x['ip'] for x in ips if x.get('globally_routable')],
                                              db=ioc_db or local_ioc.DEFAULT_DB),
    }
    instant = datetime.now(timezone.utc)
    report = {'schema_version': '1.6.0',
              'report_id': 'EDA-' + instant.strftime('%Y%m%dT%H%M%SZ') + '-' + re.sub(r'[^a-z0-9]+', '-', host)[:48],
              'checked_at': instant.isoformat(timespec='seconds'), 'domain': host,
              'registered_domain': registered, 'vt_usage': vt_usage,
              'business_context': ctx, 'sources': sources,
              'assessment': {}}
    report['domestic_cross_validation'] = domestic_cross_validate(sources)
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
    print('无需 API Key：DNS、RDAP、IP 归属、证书记录、本地安全名单。')
    print('需要免费账号：AlienVault OTX、urlscan.io。完成一次配置后，以后自动查询。')
    print('密钥只保存于本机 .env，不会显示在屏幕上，也不会写入报告。')
    env = read_env()
    interactive = sys.stdin.isatty() and not args.non_interactive
    providers = [
      ('OTX_API_KEY', 'AlienVault OTX', 'https://otx.alienvault.com/',
       '登录后从账户 Settings / API Key 页面复制 Key。'),
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
        enable = input('你已确认可使用该 API（个人非某些用途免费额度或已获许可的订阅）？[y/N]：').strip().lower()
        if enable == 'y':
            tier = input('使用的授权类型：[1] 个人非某些用途免费 [2] 已获许可的订阅，默认 1：').strip()
            value = getpass.getpass('VirusTotal API Key（输入不回显）：').strip()
            if value:
                env['VT_API_KEY'] = value
                if tier == '2':
                    env['VT_API_TIER'] = 'premium'
                    env.pop('VT_USAGE', None)
                else:
                    env['VT_USAGE'] = 'noncommercial'
                    env.pop('VT_API_TIER', None)
    print('\n【微步在线（可选）】https://x.threatbook.com/')
    print('域名分析 API 是否免费及可用取决于账户权限；已有接口授权及额度时才能启用。')
    if interactive and (args.force or not env.get('THREATBOOK_API_KEY')):
        enable = input('已从平台获得域名分析 API 调用权限？[y/N]：').strip().lower()
        if enable == 'y':
            key = getpass.getpass('微步 API Key（输入不回显）：').strip()
            if key:
                env['THREATBOOK_API_KEY'] = key
                env['THREATBOOK_API_AUTHORIZED'] = 'yes'
    env['ONBOARDING_DONE'] = 'yes' if interactive else env.get('ONBOARDING_DONE', 'no')
    write_local_env(env)
    print('\n配置已保存到本机：' + str(DEFAULT_ENV))
    print('以后可以直接 audit --domain example.com；要补充 Key 可再次运行 setup。')
    return 0


def doctor_cmd(args):
    env = read_env()
    print('=== API 配置检查 ===')
    for key, label in [('OTX_API_KEY', 'OTX'), ('URLSCAN_API_KEY', 'urlscan'),
                       ('VT_API_KEY', 'VirusTotal'), ('THREATBOOK_API_KEY', '微步在线')]:
        eligible = key != 'VT_API_KEY' or effective_vt_usage(env) != 'not_enabled'
        if key == 'THREATBOOK_API_KEY':
            eligible = env.get('THREATBOOK_API_AUTHORIZED') == 'yes'
        print(label + ': ' + ('已配置' if env.get(key) and eligible else '未启用'))
    if not args.online:
        print('如需验证接口连通性，请运行 doctor --online。')
        return 0
    tests = {
        'IANA RDAP': lambda: bool(req_json(RDAP_BOOTSTRAP).get('services')),
        'RIPEstat': lambda: req_json(RIPESTAT_API, params={'resource':'1.1.1.1'}).get('status') == 'ok',
    }
    if env.get('OTX_API_KEY'):
        tests['OTX'] = lambda: req_json(f'{OTX_BASE}/example.com/general', headers={'X-OTX-API-KEY': env['OTX_API_KEY']}) is not None
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
    if args.tls_probe:
        print('提示：已选择主动 TLS 探测，会与公网目标建立连接（不发送 HTTP 请求）。')
    usage = effective_vt_usage(read_env(), ctx)
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
        print('部分 IOC 更新失败，保留历史缓存并在报告中标明；继续执行其他检查。')
    domestic_reviews = load_domestic_evidence(getattr(args, 'domestic_evidence', None), host)
    report = build_report(host, registered, ctx, args.tls_probe,
                          domestic_reviews=domestic_reviews, ioc_db=db)
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
    names = list(local_ioc.FEEDS) if args.include_adtracking else [name for name, cfg in local_ioc.FEEDS.items() if cfg['enabled_by_default']]
    if args.include_adtracking and not args.license_reviewed:
        raise ValueError('anti-AD 为上游聚合列表，请先核实机构某些用途与上游数据许可；确认后同时使用 --license-reviewed')
    print('仅获取开源静态数据，不上传申请域名/IP；不会自动封禁。')
    results = local_ioc.update_feeds(db=args.ioc_db, names=names)
    for key, value in results.items():
        print(f"{key}: {value['status']} ({value.get('count', value.get('error', '未知'))})")
    print('原有成功缓存遇下载失败会保留；失败源不得当作无命中。')
    return 0 if all(v['status'] == 'ok' for v in results.values()) else 1


def ioc_import_cmd(args):
    if args.feed not in local_ioc.FEEDS:
        raise ValueError('非允许的数据源')
    if args.feed == 'cn_antiad' and not args.license_reviewed:
        raise ValueError('导入 anti-AD 需先审核聚合上游数据许可并设置 --license-reviewed')
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
        print('尚无本地 IOC 数据库或未成功更新。请执行 ioc-update。')
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
    s_doctor = sub.add_parser('doctor', help='检查配置，可选择检查外部 API 连通性')
    s_doctor.add_argument('--online', action='store_true', help='联网检查公共端点及已配置的 API Key')
    s_audit = sub.add_parser('audit', help='一键域名检查，生成 HTML 和 JSON 报告')
    s_audit.add_argument('--domain', required=True, help='例如 ifuwuyun.com；不要传完整 URL')
    s_audit.add_argument('--registered-domain', help='复杂多级后缀时手动指定经核实的注册域名')
    s_audit.add_argument('--business-file', help='可选补充资料 JSON；普通用户无需使用')
    s_audit.add_argument('--baseline', help='可选的指定历史报告；默认自动使用 reports 中最新同域名 JSON')
    s_audit.add_argument('--no-auto-baseline', action='store_true', help='关闭自动历史基线比较')
    s_audit.add_argument('--no-auto-ioc-update', action='store_true', help='不尝试联网更新本地 IOC（使用现有缓存）')
    s_audit.add_argument('--domestic-evidence', help='可选历史网页复核记录，不影响自动检测')
    s_audit.add_argument('--output', default=str(ROOT / 'reports'), help='HTML 与 JSON 报告保存位置')
    s_audit.add_argument('--markdown', action='store_true', help='额外生成旧版 Markdown 技术报告')
    s_audit.add_argument('--no-prompt', action='store_true', help='不弹出首次 API 配置向导，适用于自动化任务')
    s_audit.add_argument('--tls-probe', action='store_true', help='主动连接目标公网 IP 测试 TLS（默认禁用）')
    s_audit.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB), help='本地 SQLite IOC 规则库（只读审查；默认 data/ioc_rules.sqlite3）')
    s_ioc_update = sub.add_parser('ioc-update', help='更新允许拉取的国内开源 IOC 本地缓存，不上传待审查域名')
    s_ioc_update.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))
    s_ioc_update.add_argument('--include-adtracking', action='store_true', help='可选广告/跟踪清单；不作为恶意证据')
    s_ioc_update.add_argument('--license-reviewed', action='store_true', help='已由机构核实聚合上游数据许可（用于 anti-AD）')
    s_ioc_import = sub.add_parser('ioc-import', help='从批准的本地静态清单文件导入 IOC，无任何网络请求')
    s_ioc_import.add_argument('--feed', choices=list(local_ioc.FEEDS), required=True)
    s_ioc_import.add_argument('--file', required=True, help='通过单位批准渠道下载到本地的上游静态文件')
    s_ioc_import.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))
    s_ioc_import.add_argument('--license-reviewed', action='store_true', help='anti-AD 聚合上游许可已核实')
    s_ioc_status = sub.add_parser('ioc-status', help='查看离线 IOC 缓存版本/条数/许可')
    s_ioc_status.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))
    s_ioc_check = sub.add_parser('ioc-check', help='纯离线 IOC 查询，无 DNS、无第三方请求')
    s_ioc_check.add_argument('--domain', required=True)
    s_ioc_check.add_argument('--ip', action='append', help='可选目标解析出的公网 IP（可多次指定）')
    s_ioc_check.add_argument('--ioc-db', default=str(local_ioc.DEFAULT_DB))
    args = parser.parse_args(argv)
    try:
        return {'init': init_cmd, 'setup': init_cmd, 'doctor': doctor_cmd, 'audit': audit_cmd, 'ioc-update': ioc_update_cmd, 'ioc-import': ioc_import_cmd, 'ioc-status': ioc_status_cmd, 'ioc-check': ioc_check_cmd}[args.command](args)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        parser.exit(2, f'参数/配置错误：{exc}\n')
    except KeyboardInterrupt:
        parser.exit(130, '已中断\n')


if __name__ == '__main__':
    sys.exit(main())
