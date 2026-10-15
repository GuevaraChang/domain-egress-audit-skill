#!/usr/bin/env python3
"""Opt-in, locally cached community IOC feeds for FQDN egress review.

Never sends target FQDN/IP to a feed; only pulls allowlisted public data.
No automatic blocking, no implied threat classification for advertising lists.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import re
import sqlite3

import requests

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / 'data' / 'ioc_rules.sqlite3'
MAX_BYTES = 16 * 1024 * 1024
MAX_AGE_DAYS = 7

# These are specifically selected public repository files, not vendor APIs.
# Always review LICENSE + original upstream data rights before production deployment.
FEEDS = {
    'cn_phishshield': {
        'title': 'PhishShield（中文社区人工钓鱼站点清单）',
        'url': 'https://raw.githubusercontent.com/Lu-yanmo/phishshield/main/common/blacklist.js',
        'project': 'https://github.com/Lu-yanmo/phishshield',
        'license': 'MIT（仓库声明；请核验使用条件）',
        'kind': 'phishing_domain', 'format': 'phishshield_js',
        'min_count': 10, 'enabled_by_default': True, 'origin_group': 'phishshield_maintainer',
    },
    'cn_ipguard': {
        'title': 'IPGuard（中国社区攻击来源 IP 清单）',
        'url': 'https://raw.githubusercontent.com/chxovo/IPguard/main/blacklist.txt',
        'project': 'https://github.com/chxovo/IPguard',
        'license': 'CC BY 4.0（署名、保留注释、标记修改）',
        'kind': 'attacking_ip', 'format': 'ip_comment',
        'min_count': 5, 'enabled_by_default': True, 'origin_group': 'ipguard_community',
    },
    'cn_antiad': {
        'title': 'anti-AD（中文广告/追踪/隐私过滤，非恶意 IOC 定性）',
        'url': 'https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt',
        'project': 'https://github.com/privacy-protection-tools/anti-AD',
        'license': '仓库 MIT；聚合上游许可需要机构额外核实',
        'kind': 'ad_tracking', 'format': 'plain_domain',
        'min_count': 1000, 'enabled_by_default': False, 'origin_group': 'antiad_aggregated',
    },
}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def is_domain(value):
    s = str(value).strip().strip('.').lower()
    if not 3 <= len(s) <= 253 or '.' not in s or s.rsplit('.', 1)[-1].isdigit():
        return False
    return all(0 < len(label) <= 63 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label)
               for label in s.split('.'))


def parse_phishshield(text):
    """Parses only quoted domains inside literal array/Set blocks (never evaluates JS).

    Formats may change upstream: a failed parse is a failure, NEVER an empty clean feed.
    Extracted domains are unverified leads even when upstream calls them malicious.
    """
    text = re.sub(r'/\*.*?\*/|(^\s*//[^\n]*$)', '', text, flags=re.S | re.M)
    # Limit extraction to array literals assigned to blacklists or Set constructors.
    candidates = re.findall(
        r'\b\w*(?:blacklist|phish(?:ing)?(?:domains)?)\w*\s*=\s*(?:new\s+Set\s*\(\s*)?\[([^\]]{1,200000})\]',
        text, flags=re.I | re.S)
    if not candidates:
        raise ValueError('上游 JS 格式未识别（仅支持显式名单数组）；拒绝把未知脚本猜作 IOC')
    domain_set = set()
    for section in candidates:
        for _, candidate in re.findall(r'(["\x27`])([^"\x27`\r\n]{1,254})\1', section):
            if is_domain(candidate):
                domain_set.add(candidate.lower())
    return [(d, '') for d in sorted(domain_set)]


def parse_text(feed, text):
    cfg = FEEDS[feed]
    if cfg['format'] == 'phishshield_js':
        return parse_phishshield(text)
    values = {}
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith(('#', '!', ';')):
            continue
        if cfg['format'] == 'ip_comment':
            ip, _, comment = raw.partition('#')
            ip = ip.strip()
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_global:
                    values[str(addr)] = comment.strip()[:240]
            except ValueError:
                continue
        else:
            domain = raw.lower()
            if is_domain(domain):
                values[domain] = ''
    return sorted(values.items())


@contextmanager
def connect(db=DEFAULT_DB):
    db = Path(db)
    db.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(db), timeout=10)
    c.execute('CREATE TABLE IF NOT EXISTS feed_meta (feed TEXT PRIMARY KEY, updated_at TEXT NOT NULL, source_url TEXT NOT NULL, project_url TEXT NOT NULL, license TEXT NOT NULL, sha256 TEXT NOT NULL, item_count INTEGER NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS indicators (feed TEXT NOT NULL, indicator TEXT NOT NULL, details TEXT NOT NULL DEFAULT \'\', PRIMARY KEY(feed, indicator))')
    try:
        with c:
            c.execute('CREATE INDEX IF NOT EXISTS indicator_lookup ON indicators(indicator)')
            yield c
    finally:
        c.close()


def fetch_feed(url):
    if not url.startswith('https://raw.githubusercontent.com/'):
        raise ValueError('仅支持事先审核的 GitHub HTTPS Raw 来源')
    headers = {'User-Agent': 'DomainEgressAudit/1.4; offline-ioc-only', 'Accept': 'text/plain'}
    # Bounded streamed downloads, no redirects, no target FQDN/IP in requests.
    with requests.get(url, headers=headers, timeout=(5, 35), stream=True, allow_redirects=False) as resp:
        if resp.status_code != 200:
            raise ValueError('下载失败（HTTP ' + str(resp.status_code) + '）；不替换原有规则')
        content_len = resp.headers.get('Content-Length')
        if content_len and int(content_len) > MAX_BYTES:
            raise ValueError('上游文件过大')
        contents, size = [], 0
        for chunk in resp.iter_content(chunk_size=65536):
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError('上游文件超过限制')
            contents.append(chunk)
    return b''.join(contents)


def update_feeds(db=DEFAULT_DB, *, names=None, fetcher=None):
    names = tuple(names if names is not None else (name for name, cfg in FEEDS.items() if cfg['enabled_by_default']))
    fetcher = fetcher or fetch_feed
    result = {}
    for name in names:
        if name not in FEEDS:
            result[name] = {'status': 'error', 'error': '未知或未审核数据源'}
            continue
        cfg = FEEDS[name]
        try:
            raw = fetcher(cfg['url'])
            if len(raw) > MAX_BYTES or len(raw) < 10:
                raise ValueError('下载的数据为空或大小异常')
            txt = raw.decode('utf-8-sig', errors='strict')
            rows = parse_text(name, txt)
            if len(rows) < cfg['min_count']:
                raise ValueError('有效条目不足，可能是源格式变化；保留旧规则：' + str(len(rows)))
            with connect(db) as c:
                c.execute('DELETE FROM indicators WHERE feed = ?', (name,))
                c.executemany('INSERT INTO indicators(feed, indicator, details) VALUES(?, ?, ?)',
                              ((name, value, info) for value, info in rows))
                c.execute('INSERT OR REPLACE INTO feed_meta(feed,updated_at,source_url,project_url,license,sha256,item_count) VALUES(?,?,?,?,?,?,?)',
                          (name, now_iso(), cfg['url'], cfg['project'], cfg['license'], sha256(raw).hexdigest(), len(rows)))
            result[name] = {'status': 'ok', 'count': len(rows), 'sha256': sha256(raw).hexdigest(), 'updated_at': now_iso()}
        except (ValueError, requests.RequestException, UnicodeError, OSError, sqlite3.Error) as exc:
            result[name] = {'status': 'error', 'error': f'{type(exc).__name__}: {str(exc)[:140]}',
                            'previous_cache_preserved': True}
    return result


def list_feeds(db=DEFAULT_DB):
    if not Path(db).is_file():
        return []
    with connect(db) as c:
        data = c.execute('SELECT feed, updated_at, source_url, project_url, license, sha256, item_count FROM feed_meta ORDER BY feed').fetchall()
    return [dict(zip(('feed', 'updated_at', 'source_url', 'project_url', 'license', 'sha256', 'item_count'), r)) for r in data]


def inspect_cached(host, ips, db=DEFAULT_DB, max_age_days=MAX_AGE_DAYS):
    meta = list_feeds(db)
    if not meta:
        return {'status': 'not_configured', 'checked_at': now_iso(),
                'summary': '没有本地 IOC 规则缓存，请在获准联网的环境执行 ioc-update；未查询不等于无恶意',
                'source_url': None,
                'data': {'matched': [], 'feeds': [], 'eligible_feeds': 0,
                         'assessment': 'not_checked', 'target_not_uploaded': True}, 'error': None}
    now = datetime.now(timezone.utc)
    matches, feeds = [], []
    host = host.lower().rstrip('.')
    ip_set = {str(ipaddress.ip_address(p)) for p in ips if isinstance(p, str) and _valid_ip(p)}
    with connect(db) as c:
        for m in meta:
            cfg = FEEDS.get(m['feed'])
            if not cfg:
                continue
            dt = datetime.fromisoformat(m['updated_at'].replace('Z', '+00:00'))
            age = max(0, (now - dt).total_seconds() / 86400)
            stale = age > max_age_days
            feeds.append({'feed': m['feed'], 'title': cfg['title'], 'kind': cfg['kind'],
                          'license': cfg['license'], 'project': cfg['project'],
                          'updated_at': m['updated_at'], 'age_days': round(age, 2),
                          'stale': stale, 'sha256': m['sha256'], 'entries': m['item_count'],
                          'origin_group': cfg['origin_group']})
            # Always exact FQDN; no auto suffix/wildcard expansion. Related IP is a weak association.
            keys = sorted(ip_set) if cfg['kind'] == 'attacking_ip' else [host]
            for indicator in keys:
                row = c.execute('SELECT details FROM indicators WHERE feed=? AND indicator=?',
                                (m['feed'], indicator)).fetchone()
                if row is None:
                    continue
                matches.append({'feed': m['feed'], 'kind': cfg['kind'], 'indicator': indicator,
                                'match_type': 'resolved_ip_shared_infrastructure' if cfg['kind'] == 'attacking_ip' else 'exact_fqdn',
                                'strength': 'weak_association' if cfg['kind'] == 'attacking_ip' else
                                            ('context_only' if cfg['kind'] == 'ad_tracking' else 'candidate'),
                                'details': row[0], 'stale': stale, 'feed_updated_at': m['updated_at'],
                                'project': cfg['project'], 'license': cfg['license'],
                                'origin_group': cfg['origin_group']})
    return {'status': 'ok', 'checked_at': now_iso(),
            'summary': f'只读取本地 SQLite IOC 缓存；{len(feeds)} 个来源、{len(matches)} 条关联；未命中/旧数据不证明安全',
            'source_url': None, 'error': None,
            'data': {'matched': matches, 'feeds': feeds,
                     'eligible_feeds': sum(not f['stale'] for f in feeds),
                     'assessment': 'local_matches_need_review', 'target_not_uploaded': True,
                     'license_warning': '仓库许可不自动覆盖聚合上游许可，使用者须复核名单及上游数据再利用条件'}}


def _valid_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False
