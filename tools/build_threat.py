#!/usr/bin/env python3
"""NovaGuard 위협 데이터 만들기 (GitHub 자동 작업이 매일 실행)

공개 위협 정보에서 '지금 공격에 쓰이는 주소'를 모아 검증·병합해 novaguard-threat.txt 로 쓴다.
서명은 이 스크립트 밖에서 openssl 로 한다 (.github/workflows/threat-data.yml).

출처 (이용 조건은 각 사이트에서 확인):
  - abuse.ch Feodo Tracker  : 봇넷 지휘 서버 (권장 목록)
  - Spamhaus DROP / DROPv6  : 범죄 조직이 쓰는 주소 대역
  - Emerging Threats        : 해킹된 것으로 알려진 주소

검사: 내부·예약 주소 제외, IPv4 /8 · IPv6 /16 보다 넓은 대역 제외, 겹치는 대역 합치기, 최대 50,000개.
모은 주소가 지나치게 적으면(출처가 대부분 실패) 실패로 끝내 지난 목록을 그대로 둔다.

  python3 tools/build_threat.py --out novaguard-threat.txt
  python3 tools/build_threat.py --out t.txt --from-files a.txt b.txt   (시험: 인터넷 없이 파일에서)
"""
import argparse, datetime, ipaddress, json, sys, urllib.request

SOURCES = [
    ('feodotracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', 'lines'),
    ('spamhaus-drop', 'https://www.spamhaus.org/drop/drop_v4.json', 'ndjson'),
    ('spamhaus-dropv6', 'https://www.spamhaus.org/drop/drop_v6.json', 'ndjson'),
    ('et-compromised', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'lines'),
]
MAX_ENTRIES = 50000
MIN_ENTRIES = 50


def parse(text, kind):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if kind == 'ndjson':
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            cidr = obj.get('cidr')
            if not cidr:
                continue
            line = cidr
        else:
            line = line.split()[0].split(';')[0]
        try:
            out.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return out


def usable(n):
    if n.version == 4 and n.prefixlen < 8:
        return False
    if n.version == 6 and n.prefixlen < 16:
        return False
    a = n.network_address
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--from-files', nargs='*')
    args = ap.parse_args()

    nets, used = [], []
    if args.from_files:
        for f in args.from_files:
            nets += parse(open(f, encoding='utf-8').read(), 'lines')
            used.append(f)
    else:
        for name, url, kind in SOURCES:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'NovaGuard-threat-builder'})
                text = urllib.request.urlopen(req, timeout=60).read().decode('utf-8', 'replace')
                got = parse(text, kind)
                nets += got
                used.append(name)
                print(f'{name}: {len(got)}개', file=sys.stderr)
            except Exception as e:   # 한 출처가 실패해도 나머지로 계속
                print(f'{name}: 실패 ({e})', file=sys.stderr)

    good = [n for n in nets if usable(n)]
    v4 = list(ipaddress.collapse_addresses([n for n in good if n.version == 4]))
    v6 = list(ipaddress.collapse_addresses([n for n in good if n.version == 6]))
    merged = v4 + v6
    if len(merged) < MIN_ENTRIES and not args.from_files:
        sys.exit(f'모은 주소가 {len(merged)}개뿐이라 올리지 않습니다 (지난 목록 유지)')
    if len(merged) > MAX_ENTRIES:
        merged = merged[:MAX_ENTRIES]

    now = datetime.datetime.now(datetime.timezone.utc)
    lines = [
        '# NovaGuard threat data',
        f'# version={now:%Y%m%d%H}',
        f'# generated={now:%Y-%m-%dT%H:%M:%SZ}',
        f'# sources={",".join(used)}',
        f'# count={len(merged)}',
    ]
    for n in merged:
        lines.append(str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n))
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'{args.out}: {len(merged)}개 (IPv4 {len(v4)}, IPv6 {len(v6)})', file=sys.stderr)


if __name__ == '__main__':
    main()
