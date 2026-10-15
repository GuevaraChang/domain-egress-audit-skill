#!/usr/bin/env python3
"""Free-source, read-only external FQDN due-diligence and reporting CLI.

No paid threat intelligence, no URL submission, no active target connection by default.
"""
from __future__ import annotations

import argparse
import getpass
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

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV = ROOT / '.env'
UA = 'DomainEgressAuditSkill/1.5 (defensive FQDN due-diligence; contact: local-admin)'
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
CONFIG_NAMES = CREDENTIAL_NAMES + ('VT_USAGE', 'THREATBOOK_API_AUTHORIZED')
# Default to business/commercial: fail closed whenever intent is not explicitly noncommercial.
BUSINESS_USES = {'business', 'commercial', 'enterprise', 'government', 'bank', 'banking'}
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


def read_env(path=DEFAULT_ENV):
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
    """A business-scoped audit overrides a noncommercial profile (fail closed)."""
    ctx = ctx or {}
    context_use = str(ctx.get('usage_type') or '').strip().lower()
    if context_use in BUSINESS_USES:
        return 'business'
    configured = str(env.get('VT_USAGE') or 'business').strip().lower()
    return 'noncommercial' if configured == 'noncommercial' else 'business'


def vt_check(host, api_key, usage):
    """Retrieve an existing public domain report; NEVER submit a scan.

    Commercial/business (including internal bank approval): no Public API calls,
    even if an API key is installed or supplied via process environment.
    """
    if usage != 'noncommercial':
        return source('skipped',
            summary='商业/银行业务流程自动跳过 VirusTotal 免费 Public API：官方限制商用产品及不贡献新文件的业务工作流；本次未请求该 API',
            data={'skip_reason': 'commercial_use_restriction', 'usage': 'business',
                  'api_called': False}, url=VT_POLICY_URL)
    if not api_key:
        return source('not_configured',
            summary='仅非商业用途可申请 VirusTotal Public API Key；尚未配置',
            data={'usage': 'noncommercial', 'api_called': False}, url=VT_KEY_URL)
    url = VT_DOMAIN_API + '/' + quote(host, safe='')
    try:
        raw = req_json(url, headers={'x-apikey': api_key})
        attrs = (raw.get('data') or {}).get('attributes') or {}
        stats = attrs.get('last_analysis_stats') or {}
        values = {key: int(stats.get(key, 0) or 0) for key in ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout')}
        stamp = attrs.get('last_analysis_date')
        analysis_date = datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat() if isinstance(stamp, (int, float)) else None
        return source('ok', summary='VirusTotal Public API 既有域名分析统计；只供线索研判，不是安全证明',
            data={'usage': 'noncommercial', 'api_called': True, 'last_analysis_stats': values,
                  'last_analysis_date': analysis_date, 'reputation': attrs.get('reputation')},
            url='https://www.virustotal.com/gui/domain/' + quote(host, safe=''))
    except (requests.RequestException, ValueError, KeyError, TypeError, OverflowError) as exc:
        return source('error', summary='VirusTotal 公共 API 查询失败；不能当作零命中',
                      error=exc, data={'usage': 'noncommercial', 'api_called': True},
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
        'virustotal': ('VirusTotal', '第三方检测统计，不等于恶意定性；商用自动跳过', 'last_analysis_date'),
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
        report['assessment']['decision'] = '暂缓放通；先确认历史变化及其他审批资料'
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
        pending.append('VirusTotal 非商业查询未取得结果（可由人工合规情报复核替代）')
    # vt.status=skipped 且因为商用限制时，是合规跳过而不是技术无风险。
    otx = src['otx']
    if otx['status'] == 'ok' and (otx['data'].get('pulse_count') or 0) > 0:
        findings.append({'severity': 'medium', 'type': 'otx_pulse', 'confidence': 'low', 'evidence_ids': ['EV-05'],
                         'detail': f"OTX 存在 {otx['data']['pulse_count']} 条关联 Pulse，仅为社区关联线索，需要人工判定相关性与时效"})
    if otx['status'] in ('not_configured', 'error') and ctx.get('manual_threat_review_completed') is not True:
        pending.append('OTX 情报未获得有效结果（可通过已批准的人工情报复核替代）')
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
        pending.append('urlscan 历史网站情报未获得有效结果（可通过已批准的人工情报复核替代）')
    # 国内平台的人工情报不是机器校验；命中优先人工核实原始 IOC，不能直接凭命中数判定恶意。
    cn = report.get('domestic_cross_validation') or domestic_cross_validate(src)
    if cn.get('unique_vendor_count',0) < 2 and ctx.get('domestic_intel_review_waived') is not True:
        pending.append('国内情报交叉验证尚不足两家不同厂商；建议补充人工查询，或记录经审批的豁免理由')
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
        pending.append('本地免费 IOC 名单尚未初始化或不可用：在获批准的联网环境运行 ioc-update（无命中不等于安全）')
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
        pending.append('未执行主动 TLS 测试（可由批准的代理/网关侧 TLS 验证替代）')
    for source_name in ('crtsh', 'ripestat'):
        if src[source_name]['status'] == 'error' and ctx.get('manual_infrastructure_review_completed') is not True:
            pending.append(f'{source_name} 查询不完整（可通过人工基础设施复核补充）')
    fields = [
        ('business_owner', '业务责任人'), ('vendor_name', '外部服务商名称'),
        ('ownership_evidence', '域名归属证明材料'), ('purpose', '访问必要性/具体用途'),
        ('source_system', '访问源系统'), ('data_classification', '传输数据等级'),
    ]
    for k, label in fields:
        if not ctx.get(k) or ctx.get(k) in ('unknown', '待填写', '待确认'):
            pending.append(f'业务上下文缺失：{label}')
    if ctx.get('owner_verified') is not True:
        pending.append('业务方尚未确认域名归属材料已核验')
    if ctx.get('security_controls_implemented') is not True:
        pending.append('尚未验证网络最小权限、审计和监测控制已落实')
    if ctx.get('data_classification') in ('confidential', 'restricted') or ctx.get('upload_data') is True:
        findings.append({'severity': 'medium', 'type': 'data_egress',
                         'detail': '涉及上传数据或敏感等级，须经过数据安全/供应商及合规审批'})
        if ctx.get('data_security_approved') is not True:
            pending.append('数据安全审批未完成')
    if ctx.get('business_approved') is not True:
        pending.append('业务负责人尚未批准此项外联')
    if ctx.get('manual_threat_review_completed') is not True:
        pending.append('免费网页情报（如 Talos/微步）人工交叉核查未完成')
    if ctx.get('confirmed_malicious_evidence') is True:
        if ctx.get('confirmed_malicious_evidence_reference'):
            high_confidence = True
            findings.append({'severity': 'high', 'type': 'confirmed_malicious', 'confidence': 'human_verified', 'evidence_ids': [], 'detail': '人工材料记录了经核实的恶意证据；暂停放通并升级安全审查'})
        else:
            findings.append({'severity': 'medium', 'type': 'unverified_malicious_flag', 'confidence': 'unverified', 'evidence_ids': [], 'detail': '材料已勾选恶意风险，但没有证据引用，需安全人员核实'})
            pending.append('补充明确的恶意证据链接或内部情报工单编号')
    if high_confidence:
        risk = '高风险（人工确认恶意证据）'
        decision = '不建议放通，升级安全审查'
    elif any(x['severity'] == 'medium' for x in findings):
        risk = '存在风险信号，需人工调查'
        decision = '暂缓放通；处置风险信号并补齐资料'
    elif pending:
        risk = '证据不充分，无法判定为低风险'
        decision = '暂缓放通；补充证据后提交人工审批'
    else:
        risk = '当前检查未发现明显风险信号（不等于绝对安全）'
        decision = '可以进入人工准入审批，禁止自动放通'
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
    fmt = [
        '# 互联网外联域名安全评估报告',
        '',
        f"- **报告编号**：{md(report['report_id'])}",
        f"- **评估时间（UTC）**：{md(report['checked_at'])}",
        f"- **目标 FQDN**：`{md(report['domain'])}`",
        f"- **注册域**：`{md(report['registered_domain'])}`",
        f"- **VirusTotal 使用场景**：{md(report.get('vt_usage', 'business'))}（商业用途禁止调用免费 Public API）",
        f"- **评估范围**：外联前公开证据调查；不包含漏洞扫描、渗透测试或完整商业情报覆盖",
        f"- **综合结论**：**{md(report['assessment']['risk_label'])}**",
        f"- **准入建议**：**{md(report['assessment']['decision'])}**",
        f"- **自动技术结论**：**{md((report.get('technical_assessment') or {}).get('label', '旧版无此结果'))}**",
        '- **外联访问授权**：未授予（此报告不能自动生成网络放通权限）',
        '',
        '## 一、业务用途与访问边界', '',
        '| 字段 | 内容 |', '| --- | --- |',
    ]
    columns = [('business_owner', '业务责任人'), ('vendor_name', '外部服务商'),
               ('ownership_evidence', '域名归属证明'), ('purpose', '访问用途'),
               ('source_system', '访问源系统'), ('target_fqdn', '目标 FQDN'),
               ('protocol', '协议'), ('target_port', '目标端口'),
               ('data_classification', '传输数据等级'), ('upload_data', '是否向外上传数据'),
               ('owner_verified', '域名归属核验完成'), ('business_approved', '业务审批完成'),
               ('data_security_approved', '数据安全审批完成'),
               ('security_controls_implemented', '外联管控落实'),
               ('manual_threat_review_completed', '人工威胁情报复核完成'),
               ('tls_review_completed', 'TLS 替代核验完成'),
               ('confirmed_malicious_evidence_reference', '恶意证据引用')] 
    for key, name in columns:
        fmt.append(f"| {name} | {md(report['business_context'].get(key))} |")
    fmt.extend(['', '## 二、自动化采集证据', '',
                '| 来源 | 查询状态 | 查询时间 (UTC) | 证据摘要 | 证据链接 |', '| --- | --- | --- | --- | --- |'])
    titles = [('rdap', '注册局 RDAP'), ('dns', '当前 DNS'), ('ripestat', 'RIPEstat'),
              ('crtsh', 'crt.sh / CT'), ('otx', 'AlienVault OTX'),
              ('urlscan', 'urlscan 历史'), ('virustotal', 'VirusTotal Public API'), ('tls', 'TLS 主动探测'),
              ('threatbook_api', '微步域名分析 API（授权后）'),
              ('threatbook_x_manual', '微步 X 网页人工复核'),
              ('qianxin_ti_manual', '奇安信情报人工复核'),
              ('tencent_tix_manual', '腾讯威胁情报人工复核'),
              ('local_ioc', '中国开源本地 IOC 规则库')]
    for key, title in titles:
        item = report['sources'].get(key, source('skipped', summary='旧版报告未提供该数据源'))
        link = item.get('source_url')
        fmt.append(f"| {title} | {md(item['status'])} | {md(item.get('checked_at'))} | {md(item.get('summary') or item.get('error'))} | {f'[来源]({link})' if link else '—'} |")
    rd = report['sources']['rdap']['data']
    dns_data = report['sources']['dns']['data']
    ips = dns_data.get('ips') or []
    fmt.extend(['', '### RDAP 注册信息', '',
                f"- 注册时间：{md(rd.get('registration_date'))}；域龄：{md(rd.get('age_days'))} 天",
                f"- 注册商：{md(rd.get('registrar'))}；到期时间：{md(rd.get('expiration_date'))}",
                '- 注意：RDAP 中的注册信息不等于供应商归属证明。',
                '', '### DNS / IP / ASN', ''])
    for record_type in ('A', 'AAAA', 'CNAME', 'NS'):
        fmt.append(f"- {record_type}：{md(', '.join(dns_data.get('records', {}).get(record_type, [])) or '无记录/未取得')}")
    fmt.append(f"- 当前 IP 列表：{md(', '.join(x['ip'] for x in ips) or '未取得')}")
    for item in report['sources']['ripestat']['data'].get('results', []):
        fmt.append(f"- `{md(item.get('ip'))}` → 前缀 `{md(item.get('prefix'))}`；ASN `{md(item.get('asns'))}`")
    fmt.extend(['', '### 第三方历史情报', ''])
    o = report['sources']['otx']
    fmt.append(f"- OTX Pulse 数量：{md(o['data'].get('pulse_count'))}（仅为关联线索；0 不等于安全）")
    u = report['sources']['urlscan']
    fmt.append(f"- urlscan 匹配历史扫描：{md(u['data'].get('matched_results'))}（样本并不全面）")
    vt = report['sources'].get('virustotal', source('skipped', summary='旧版样例未包含 VirusTotal'))
    if vt['status'] == 'ok':
        fmt.append(f"- VirusTotal 既有检测：{md(vt['data'].get('last_analysis_stats'))}；最近分析时间：{md(vt['data'].get('last_analysis_date'))}（仅为线索）")
    else:
        fmt.append(f"- VirusTotal：{md(vt['status'])}；{md(vt.get('summary') or vt.get('error'))}（未请求不能标记为无恶意）")
    ct = report['sources']['crtsh']
    fmt.append(f"- CT 证书条目数量：{md(ct['data'].get('certificate_entries'))}；最后记录：{md(ct['data'].get('latest_entry'))}")
    fmt.extend(['', '### 国内情报交叉验证（人工记录 + 授权 API）', '',
                '| 平台 | 查询状态 | 结论 | 人工核查时间 | 证据编号/截图引用 |',
                '| --- | --- | --- | --- | --- |'])
    cross = report.get('domestic_cross_validation') or domestic_cross_validate(report['sources'])
    for item in cross['matrix']:
        fmt.append(f"| {md(item['name'])} | {md(item['status'])} | {md(item['label'])} | {md(item.get('checked_at'))} | {md(item.get('evidence_ref'))} |")
    fmt.append('- 交叉核验状态：**' + md(cross.get('alignment')) + '**；独立厂商覆盖：' + md(cross.get('unique_vendor_count')) + ' 家（不等于独立 IOC 证据数）。')
    fmt.append('- 交叉判断：' + md(cross['methodology']))
    fmt.append('- 重要：网页人工证据是**审核人员填报**，本程序无法验证其真实性；不同供应商可能互引同一 IOC。')
    fmt.extend(['', '### 中国开源本地 IOC 规则库（离线缓存、精确匹配）', '',
                '| 数据源 | 类型 | 下载时间 | 规则数 | 过期 | 许可证/项目 |',
                '| --- | --- | --- | ---: | --- | --- |'])
    local_info = (report['sources'].get('local_ioc') or {}).get('data') or {}
    for row in local_info.get('feeds', []):
        fmt.append(f"| {md(row.get('feed'))} | {md(row.get('kind'))} | {md(row.get('updated_at'))} | {md(row.get('entries'))} | {md(row.get('stale'))} | {md(row.get('license'))}；{md(row.get('project'))} |")
    if not local_info.get('feeds'):
        fmt.append('| 未建立本地缓存 | — | — | — | — | 自动更新失败或被禁用，不能把未检测理解为 0 命中 |')
    fmt.extend(['', '| 命中来源 | IOC | 匹配关系 | 提示类别 | 数据时效 |',
                '| --- | --- | --- | --- | --- |'])
    for row in local_info.get('matched', []):
        fmt.append(f"| {md(row['feed'])} | `{md(row['indicator'])}` | {md(row['match_type'])} | {md(row['kind'])} | {'过期/需更新' if row['stale'] else '新鲜/仍需复核'} |")
    if not local_info.get('matched'):
        fmt.append('| 无匹配记录 | — | — | **不等于已证明安全** | — |')
    fmt.append('- 区分：钓鱼名单为候选 IOC；IPGuard 解析 IP 仅是共享基础设施弱关联；anti-AD 仅代表广告/追踪类拦截，不应当成恶意或自动封禁依据。')
    fmt.append('- 自动交叉验证仅对**已经离线加载的来源**有效；不同清单可能转引同一上游，不按命中数量简单投票；更新时只下载公开清单，不上传目标 FQDN。')
    fmt.extend(['', '## 三、风险信号与审核结论', ''])
    findings = report['assessment']['findings']
    if not findings:
        fmt.append('- 在已成功的自动化检查中，未触发本工具定义的明显风险信号。**不代表安全、也不代表已满足准入条件。**')
    else:
        for f in findings:
            fmt.append(f"- **{md(f['severity'])} / {md(f['type'])}**（可信度：{md(f.get('confidence', '待人工核实'))}；证据编号：{md(', '.join(f.get('evidence_ids', [])) or '人工证据/待补')}）：{md(f['detail'])}")
    fmt.extend(['', '### 证据可追溯性与时效', '',
                '证据可信度针对**观察/归属关联**，不是安全保障等级；`checked_at` 为本次采集时间，`observed_at` 为第三方原始记录时间。',
                '', '| 证据编号 | 来源 | 状态 | 观测日期 | 观测年龄(天) | 解读限制 |',
                '| --- | --- | --- | --- | --- | --- |'])
    for item in report.get('evidence_ledger', []):
        fmt.append(f"| {md(item['id'])} | {md(item['source_name'])} | {md(item['status'])} | {md(item.get('observed_at'))} | {md(item.get('observation_age_days'))} | {md(item['interpretation_limit'])} |")
    coverage = report.get('evidence_coverage') or {}
    fmt.append(f"- 查询状态分布（非安全评分）：{md(coverage.get('status_counts'))}")
    for old in coverage.get('stale_observations_over_90_days', []):
        fmt.append(f"- **历史证据可能过期**：{md(old['source'])}，距今约 {md(old['age_days'])} 天，请核实当前实际状态。")
    fmt.extend(['', '### 被动关系资产清单（不扩张申请范围）', '',
                '| 主机名 | 角色 | 是否在本次批准范围 | 归属可信度 | 观察时间 |',
                '| --- | --- | --- | --- | --- |'])
    for item in report.get('asset_inventory', []):
        fmt.append(f"| `{md(item['hostname'])}` | {md(item['role'])} | {'是' if item['in_approved_scope'] else '否，必须另行核实'} | {md(item['attribution_confidence'])} | {md(item.get('observed_at'))} |")
    diff = report.get('baseline_comparison')
    if diff:
        fmt.extend(['', '### 历史基线变化（仅在使用 --baseline 时显示）', '',
                    f"- 基线报告：{md(diff.get('baseline_report_id'))}，基线采集：{md(diff.get('baseline_checked_at'))}",
                    f"- 比较结论：{md(diff.get('summary'))}"])
        for ch in diff['changes']:
            fmt.append(f"- **{md(ch['field'])}**：{md(ch['before'])} → {md(ch['after'])}。{md(ch['review'])}")
        fmt.append(f"- 局限：{md(diff.get('limitations'))}")
    fmt.extend(['', '## 四、待补充证据与待办事项', ''])
    for item in report['assessment']['pending_items']:
        fmt.append(f'- [ ] {md(item)}')
    if not report['assessment']['pending_items']:
        fmt.append('- 自动化审查未发现待补充字段；仍须按单位制度人工审批。')
    execution = report.get('execution') or {}
    fmt.extend(['', '## 五、无人值守执行记录', '',
                '- 本次评估无需提供 `business_context.json`、国内人工证据文件或 API Key。',
                '- 本地 IOC 更新：' + md((execution.get('ioc_refresh') or {}).get('status', '旧版未记录')),
                '- IOC 更新失败详情：' + md((execution.get('ioc_refresh') or {}).get('errors', {})),
                '- 自动基线来源：' + md(execution.get('baseline_file')),
                '- 自动化检查状态：' + md((report.get('technical_assessment') or {}).get('source_statuses')),
                '- 业务与数据风险：' + md((report.get('technical_assessment') or {}).get('business_data_risk', 'not_assessed')),
                '- 运行结果：报告已生成；若有检查失败会如实标明，不会伪造安全结论。',
                '- 重要：报告能够无人值守生成，但公开技术情报不能推断内部数据流或自动授予防火墙放通权限。',
                '', '## 六、审计声明', '',

                '1. 本报告仅基于执行时取得的公开数据和提交的业务上下文，不是安全认证。',
                '2. 查询失败、未配置、无记录、未发现恶意，均不能理解为“安全”。',
                '3. OTX Pulse、共享云 IP 的间接关联等不得单独作为恶意定性依据。',
                '4. 默认不主动访问被评估网站、不提交网址扫描、不传送内部业务信息到情报平台。',
                '5. 本工具不能自动批准或执行网络放通；最终决策由业务、网络、安全、数据合规审批确定。',
                '6. 免费第三方服务使用前应由单位核实服务条款、数据出境、查询合规与限额。',
                '7. 企业/银行/其他商业业务流程自动跳过 VirusTotal Public API（不调用）；不影响其他免费查询，跳过不等于低风险。',
                '8. 国内网页证据来自人工填写，程序未抓取奇安信、腾讯、微步网页，不得声称已自动检索。',
                '9. 微步 API 默认跳过；只有接口额度且机构用途获授权才允许请求；免费网页不等于免费域名 API。',
                '10. audit 自动按需更新默认本地 IOC 源；PhishShield/IPGuard/anti-AD 可能出现误报或上游许可差异，命中不自动等于恶意；anti-AD 为广告/追踪类来源，不属于安全恶意 IOC 证明。',
                '', '## 七、机器可读证据', '',
                '同名 `.json` 文件包含检查状态、结构化证据、风险信号和待办事项。', ''])
    return '\n'.join(fmt)


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
    report = {'schema_version': '1.5.0',
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
    return report


def init_cmd(args):
    print('=== 外联域名审查 Skill · 首次配置（免费来源）===')
    print('无需密钥：IANA RDAP / DNS / RIPEstat / crt.sh；中国开源 IOC 本地缓存也不需要 Key。')
    print('  如机构允许拉取公开 Github 静态规则：python scripts/domain_audit.py ioc-update')
    print('  本地执行 ioc-status 查看更新时间和许可；默认仅 PhishShield 与 IPGuard，anti-AD 需另行接受聚合上游许可证。')
    print('可选账号：OTX https://otx.alienvault.com/api/；urlscan https://urlscan.io/docs/api/')
    print('【国内免费网页交叉验证】微步 X：https://x.threatbook.com/；奇安信：https://ti.qianxin.com/portal/；腾讯：https://tix.qq.com/')
    print('  网页人工查询后填写 assets/domestic_evidence.example.json 模板，并用 audit --domestic-evidence 导入。')
    print('  国内免费网页功能/额度因账号而异；此 Skill 不会未授权抓取页面或使用非公开 API。')
    print('【微步域名分析 API】个人免费额度不保证包含域名分析接口，商业授权也需核实。')
    print('  只有确认账号可调用该接口、当前有免费配额且单位批准用途后，才能本地设置')
    print('  THREATBOOK_API_AUTHORIZED=yes 和 THREATBOOK_API_KEY。默认全部跳过，不收费也不自动订购。')
    print('VirusTotal 免费 Public API 使用限制：')
    print('  商业产品/服务，以及不贡献新文件的业务工作流不能使用；银行外联审批属于此类业务工作流。')
    print('  官方说明：' + VT_POLICY_URL)
    print('  商业用途将自动跳过 VirusTotal 注册/Key 配置/API 查询，不影响其他数据源。')
    print('  个人非商业/学术用途可访问 https://www.virustotal.com/ 注册，登录后在 ' + VT_KEY_URL + ' 获取 Key。')
    print('  Public API 限额：4 次/分钟、500 次/天；不得通过多账号规避限额。')
    print('仅当单位允许向第三方提供待查公网 FQDN、认可条款和隐私要求时配置可选 API。')
    print('禁止向聊天、截图、日志或 Git 提交真实 API Key。\n')
    if DEFAULT_ENV.exists() and not args.force:
        existing = read_env()
        current_usage = effective_vt_usage(existing)
        print(f'本地配置已存在：{DEFAULT_ENV}，为避免覆盖未修改。使用 init --force 覆盖。')
        if current_usage == 'business':
            print('已有配置按 business 处理；现阶段将自动跳过 VirusTotal Public API，绝不请求。')
        else:
            print('已有配置声明 noncommercial：仅应在确属非商业用途且条款许可时使用。')
        return 0
    if args.usage:
        usage = args.usage
    elif sys.stdin.isatty() and not args.non_interactive:
        answer = input('是否用于银行/企业/客户项目或其他商业业务流程？[Y/n，默认 Y]：').strip().lower()
        usage = 'noncommercial' if answer in ('n', 'no') else 'business'
    else:
        usage = 'business'  # never silently opt in to free VirusTotal in CI or agents
    if usage == 'business':
        print('【自动跳过 VirusTotal】当前为商业/业务用途；免费 Public API 不适用。无需注册、无需填入 Key、后续查询也不会调用。')
        print('原因：VirusTotal 的公开 API 许可限制；银行如需自动化集成应走单独的合规采购/授权流程。')
    else:
        print('【非商业用途】可以申请 VirusTotal 免费 Public API Key；仅限符合官网许可的个人/非商业研究。')
        print('注册地址：https://www.virustotal.com/；API Key 页面：' + VT_KEY_URL)
    secrets = {}
    if sys.stdin.isatty() and not args.non_interactive:
        for key, title in [('OTX_API_KEY', 'OTX API Key'), ('URLSCAN_API_KEY', 'urlscan API Key')]:
            secrets[key] = getpass.getpass(f'{title}（可回车跳过，输入不回显）：').strip()
        if usage == 'noncommercial':
            secrets['VT_API_KEY'] = getpass.getpass('VirusTotal API Key（仅非商业；可回车跳过）：').strip()
    # Explicit empty VT_API_KEY for commercial use, regardless of any prior key.
    content = '# 由 init 创建。不要提交到版本库！\n'
    content += f'VT_USAGE={usage}\n'
    content += 'THREATBOOK_API_AUTHORIZED=no\n'
    content += ''.join(f'{key}={secrets.get(key, "")}\n' for key in CREDENTIAL_NAMES)
    fd = os.open(str(DEFAULT_ENV), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    try:
        os.chmod(DEFAULT_ENV, 0o600)
    except OSError:
        pass
    print(f'配置文件已创建：{DEFAULT_ENV}（密钥默认空；可稍后本地编辑）')
    print('后续操作：python scripts/domain_audit.py doctor；随后 audit --domain example.com')
    return 0


def doctor_cmd(args):
    env = read_env()
    usage = effective_vt_usage(env)
    print('=== API / 环境诊断（不输出 Key）===')
    print('OTX Key:', '已配置' if env.get('OTX_API_KEY') else '未配置（可跳过）')
    print('urlscan Key:', '已配置' if env.get('URLSCAN_API_KEY') else '未配置（可跳过）')
    tb_auth = str(env.get('THREATBOOK_API_AUTHORIZED','')).strip().lower() == 'yes'
    print('微步在线域名 API:', '已人工确认许可/额度且 Key 已配置（可查询）' if tb_auth and env.get('THREATBOOK_API_KEY')
          else '默认合规跳过（许可/免费域名查询额度或 Key 未确认）')
    print('国内网页：微步 X / 奇安信 / 腾讯请在授权账户手工查询，再导入本地 JSON，doctor 不爬取。')
    if usage == 'business':
        print('VirusTotal: 自动跳过（商业/银行业务流程不允许使用免费 Public API），无论是否存在 Key 都不调用')
        print('说明：' + VT_POLICY_URL)
    else:
        print('VirusTotal: 非商业模式；Key ' + ('已配置' if env.get('VT_API_KEY') else '未配置（可跳过）'))
    print('Python 依赖：正常')
    if not args.online:
        print('尚未请求网络。加 --online 将访问示例公开域名检查服务连通性。')
        return 0
    tests = {
        'IANA RDAP Bootstrap': lambda: req_json(RDAP_BOOTSTRAP).get('services', []) != [],
        'RIPEstat': lambda: req_json(RIPESTAT_API, params={'resource': '1.1.1.1'}).get('status') == 'ok',
    }
    if env.get('OTX_API_KEY'):
        tests['OTX'] = lambda: req_json(f'{OTX_BASE}/example.com/general',
                                         headers={'X-OTX-API-KEY': env['OTX_API_KEY']}) is not None
    if env.get('URLSCAN_API_KEY'):
        tests['urlscan Quotas'] = lambda: req_json('https://urlscan.io/user/quotas/',
                                             headers={'api-key': env['URLSCAN_API_KEY']}) is not None
    if usage == 'noncommercial' and env.get('VT_API_KEY'):
        tests['VirusTotal Public API'] = lambda: req_json(
            VT_DOMAIN_API + '/example.com', headers={'x-apikey': env['VT_API_KEY']}).get('data') is not None
    for name, f in tests.items():
        try:
            print(f'{name}:', 'OK' if f() else '返回内容不符合预期')
        except (requests.RequestException, ValueError) as exc:
            print(f'{name}: 失败（{type(exc).__name__}）；检查权限、出口代理和免费额度')
    return 0


def audit_cmd(args):
    """One-command unattended collection & reporting; no interactive prompts."""
    host, registered = validated_domain(args.domain)
    if args.registered_domain:
        override, _ = validated_domain(args.registered_domain)
        if host != override and not host.endswith('.' + override):
            raise ValueError('--registered-domain 必须是目标 FQDN 的父域名')
        registered = override
    ctx, _ = read_context(args.business_file, host)
    if args.tls_probe:
        print('提示：已选择主动 TLS 探测，会与公网目标建立连接（不发送 HTTP 请求）。')
    usage = effective_vt_usage(read_env(), ctx)
    if usage == 'business':
        print('VirusTotal：商业/银行业务自动跳过免费 Public API。')
    print(f'正在自动评估 {host}（注册域 {registered}）；无人工问答、不发送内部业务数据。')
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
    report['execution'] = {'mode': 'unattended', 'ioc_refresh': sync,
                           'baseline_file': baseline_path, 'manual_input_required': False,
                           'api_keys_optional': True}
    safe = re.sub(r'[^a-z0-9.-]', '_', host)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    base = out / f'{safe}_{stamp}'
    counter = 1
    while Path(str(base) + '.json').exists() or Path(str(base) + '.md').exists():
        base = out / f'{safe}_{stamp}_{counter:02d}'
        counter += 1
    jfile = Path(str(base) + '.json')
    mfile = Path(str(base) + '.md')
    jfile.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    mfile.write_text(render_markdown(report), encoding='utf-8')
    print('自动技术结论：' + report['technical_assessment']['label'])
    print('准入状态：未授权自动放通')
    print('待补证据：' + str(len(report['assessment']['pending_items'])))
    print('JSON:', jfile)
    print('Markdown:', mfile)
    return 0


def ioc_update_cmd(args):
    names = list(local_ioc.FEEDS) if args.include_adtracking else [name for name, cfg in local_ioc.FEEDS.items() if cfg['enabled_by_default']]
    if args.include_adtracking and not args.license_reviewed:
        raise ValueError('anti-AD 为上游聚合列表，请先核实机构商用与上游数据许可；确认后同时使用 --license-reviewed')
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
    parser = argparse.ArgumentParser(description='完全免费公开数据驱动的互联网外联域名审查（非自动准入）')
    sub = parser.add_subparsers(dest='command', required=True)
    s_init = sub.add_parser('init', help='首次注册、申请 API Key 指引及创建本地配置')
    s_init.add_argument('--force', action='store_true', help='覆盖现有本地配置（谨慎）')
    s_init.add_argument('--usage', choices=['business', 'noncommercial'],
                        help='设置用途；非交互环境默认 business，银行/企业务必选 business')
    s_init.add_argument('--non-interactive', action='store_true', help='只创建空密钥配置，不提示输入')
    s_doctor = sub.add_parser('doctor', help='检查配置，可选择检查外部 API 连通性')
    s_doctor.add_argument('--online', action='store_true', help='联网检查公共端点及已配置的 API Key')
    s_audit = sub.add_parser('audit', help='查询指定 FQDN，生成 JSON/Markdown 双报告')
    s_audit.add_argument('--domain', required=True, help='例如 ifuwuyun.com；不要传完整 URL')
    s_audit.add_argument('--registered-domain', help='复杂多级后缀时手动指定经核实的注册域名')
    s_audit.add_argument('--business-file', help='可选的业务上下文 JSON；默认无人值守，不需要此文件')
    s_audit.add_argument('--baseline', help='可选的指定历史报告；默认自动使用 reports 中最新同域名 JSON')
    s_audit.add_argument('--no-auto-baseline', action='store_true', help='关闭自动历史基线比较')
    s_audit.add_argument('--no-auto-ioc-update', action='store_true', help='不尝试联网更新本地 IOC（使用现有缓存）')
    s_audit.add_argument('--domestic-evidence', help='国内威胁情报网页人工复核记录 JSON；仅本地导入，不抓取网页')
    s_audit.add_argument('--output', default=str(ROOT / 'reports'), help='报告输出目录')
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
        return {'init': init_cmd, 'doctor': doctor_cmd, 'audit': audit_cmd, 'ioc-update': ioc_update_cmd, 'ioc-import': ioc_import_cmd, 'ioc-status': ioc_status_cmd, 'ioc-check': ioc_check_cmd}[args.command](args)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        parser.exit(2, f'参数/配置错误：{exc}\n')
    except KeyboardInterrupt:
        parser.exit(130, '已中断\n')


if __name__ == '__main__':
    sys.exit(main())
