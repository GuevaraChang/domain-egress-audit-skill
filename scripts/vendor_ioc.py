#!/usr/bin/env python3
"""Download allowlisted IOC snapshots into the repository for offline first-use.

Data is retained verbatim with attribution and SHA256. Nothing is executed.
Use in a trusted online environment or the scheduled GitHub Actions workflow.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_ioc

FILES = {'cn_phishshield':'phishshield_blacklist.js',
         'cn_ipguard':'ipguard_blacklist.txt',
         'cn_antiad':'anti_ad_domains.txt'}


def vendor(*, destination=local_ioc.VENDOR_DIR, fetcher=None):
    fetcher = fetcher or local_ioc.fetch_feed
    destination = Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    existing = {}
    manifest_path = destination / 'manifest.json'
    if manifest_path.exists():
        try:
            existing = json.loads(manifest_path.read_text('utf-8')).get('feeds') or {}
        except (ValueError, OSError):
            pass
    records = {}
    for name, filename in FILES.items():
        cfg = local_ioc.FEEDS[name]
        raw = fetcher(cfg['url'])
        if not 10 <= len(raw) <= local_ioc.MAX_BYTES:
            raise ValueError(f'{name}: 下载体积不合法')
        text = raw.decode('utf-8-sig', 'strict')
        entries = local_ioc.parse_text(name,text)
        if len(entries) < cfg['min_count']:
            raise ValueError(f'{name}: 规则条目不足（{len(entries)}）；拒绝覆盖旧版本')
        tmp = destination / (filename+'.tmp')
        tmp.write_bytes(raw)
        os.replace(tmp,destination/filename)
        records[name] = {'file':filename,'sha256':sha256(raw).hexdigest(),
                         'entries':len(entries),'license':cfg['license'],
                         'source_url':cfg['url'],'project_url':cfg['project']}
    stamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
    meta = {'schema_version':1,'generated_at':stamp,'feeds':records,
            'note':'数据原样镜像，不代表逐条核实；IPGuard 保留原行注释，anti-AD 仅广告/追踪信息。'}
    tmp=manifest_path.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(meta,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    os.replace(tmp,manifest_path)
    return meta


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--destination',default=str(local_ioc.VENDOR_DIR))
    a=p.parse_args()
    result=vendor(destination=a.destination)
    for name,data in result['feeds'].items():
        print(f"{name}: {data['entries']} 条，SHA256 {data['sha256']}")
