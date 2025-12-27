"""checker/main.py

Парсер подписки (vmess/vless/trojan/ss) и базовый TCP-connect тест для проверки доступности узлов.

Использование:
    python main.py --url <subscription_url> --output nodes.json

Зависимости: requests
"""
import argparse
import base64
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote

import subprocess
import statistics
import platform
import requests
import tempfile
import os
import threading
import shutil
from datetime import datetime
import webbrowser
from pathlib import Path

# optional progress bar
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

LINK_RE = re.compile(r"(vless|vmess|trojan|ss)://[^\s'\"<>]+", re.IGNORECASE)


def fetch_url(url, timeout=15):
    try:
        resp = requests.get(url, timeout=timeout, verify=False)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch URL: {exc}")


def try_base64_decode(text):
    """Попытаться декодировать base64 (если это закодированная подписка).
    Возвращает декодированную строку или None.
    """
    s = ''.join(text.strip().split())
    # base64 должен иметь длину кратную 4
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    try:
        data = base64.b64decode(s)
        text2 = None
        try:
            text2 = data.decode('utf-8', errors='ignore')
        except Exception:
            text2 = None
        if text2 and LINK_RE.search(text2):
            return text2
    except Exception:
        return None
    return None




def find_links(text):
    if LINK_RE.search(text):
        # use finditer to get full matches
        return [m.group(0) for m in LINK_RE.finditer(text)]
    return []


def parse_vmess(link):
    # vmess://<base64_json>
    b64 = link[len('vmess://'):]
    try:
        decoded = base64.b64decode(b64 + '===').decode('utf-8', errors='ignore')
        data = json.loads(decoded)
        return {
            'protocol': 'vmess',
            'ps': data.get('ps') or data.get('name'),
            'add': data.get('add') or data.get('host'),
            'port': int(data.get('port')) if data.get('port') else None,
            'id': data.get('id') or data.get('uuid'),
            'net': data.get('net'),
            'type': data.get('type'),
            'tls': data.get('tls'),
            'raw': link,
        }
    except Exception:
        return {'protocol': 'vmess', 'raw': link}


def parse_vless(link):
    # vless://<uuid>@host:port?query#name
    u = urlparse(link)
    qs = parse_qs(u.query)
    name = unquote(u.fragment) if u.fragment else None
    return {
        'protocol': 'vless',
        'ps': name,
        'add': u.hostname,
        'port': u.port,
        'id': u.username,
        'net': qs.get('type', [None])[0],
        'path': qs.get('path', [None])[0],
        'tls': 'tls' if qs.get('security', [None])[0] == 'tls' or qs.get('tls', [None])[0] == 'tls' else None,
        'raw': link,
    }


def parse_trojan(link):
    # trojan://password@host:port?params#name
    u = urlparse(link)
    name = unquote(u.fragment) if u.fragment else None
    return {
        'protocol': 'trojan',
        'ps': name,
        'add': u.hostname,
        'port': u.port,
        'password': u.username,
        'raw': link,
    }


def parse_ss(link):
    # ss://<base64>@host:port or ss://<method:password>@host:port
    # Simplified parsing
    rest = link[len('ss://'):]
    try:
        if '@' in rest:
            head, addr = rest.split('@', 1)
            if ':' in head:
                method, password = head.split(':', 1)
            else:
                method, password = None, None
            if ':' in addr:
                host, port = addr.rsplit(':', 1)
                port = int(port)
            else:
                host, port = addr, None
            return {'protocol': 'ss', 'add': host, 'port': port, 'method': method, 'password': password, 'raw': link}
        else:
            # base64 encoded
            dec = base64.b64decode(rest + '===').decode('utf-8', errors='ignore')
            return parse_ss('ss://' + dec)
    except Exception:
        return {'protocol': 'ss', 'raw': link}


def parse_link(link):
    scheme = link.split('://', 1)[0].lower()
    if scheme == 'vmess':
        return parse_vmess(link)
    if scheme == 'vless':
        return parse_vless(link)
    if scheme == 'trojan':
        return parse_trojan(link)
    if scheme == 'ss':
        return parse_ss(link)
    return {'protocol': scheme, 'raw': link}


def gather_nodes_from_text(text):
    # try to find links directly
    links = find_links(text)
    if not links:
        # try base64 decode whole text
        decoded = try_base64_decode(text)
        if decoded:
            links = find_links(decoded)
    nodes = []
    for ln in links:
        try:
            node = parse_link(ln)
            nodes.append(node)
        except Exception:
            nodes.append({'protocol': 'unknown', 'raw': ln})
    return nodes


def tcp_connect_test(host, port, timeout=5):
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        rtt = (time.time() - start)
        return True, rtt
    except Exception:
        return False, None


def percentile(data, p):
    if not data:
        return None
    data = sorted(data)
    k = (len(data)-1) * (p/100.0)
    f = int(k)
    c = min(f+1, len(data)-1)
    if f == c:
        return data[int(k)]
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return d0 + d1


def ping_host(host, count=4, timeout_ms=1000):
    """Call system ping and parse results. Returns dict with sent/received/loss and rtts list and stats."""
    if platform.system().lower().startswith('win'):
        cmd = ['ping', '-n', str(count), '-w', str(timeout_ms), host]
    else:
        # -c count, -W timeout in seconds (per-packet)
        cmd = ['ping', '-c', str(count), '-W', str(max(1, int(timeout_ms/1000))), host]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=(count * (timeout_ms/1000.0) + 5))
    except subprocess.CalledProcessError as e:
        out = e.output
    except Exception:
        return {'sent': count, 'received': 0, 'loss_percent': 100.0, 'rtts': [], 'min': None, 'avg': None, 'max': None}

    # extract per-reply times
    rtts = []
    for line in out.splitlines():
        line = line.strip()
        # unix-like: time=12.3 ms
        if 'time=' in line:
            m = re.search(r'time[=<]\s*([0-9]+\.?[0-9]*)', line)
            if m:
                try:
                    rtts.append(float(m.group(1)))
                except Exception:
                    pass
        # windows: time=12ms or time<1ms
        if 'TTL=' in line and 'time=' in line:
            m = re.search(r'time[=<]\s*([0-9]+)', line)
            if m:
                try:
                    rtts.append(float(m.group(1)))
                except Exception:
                    pass

    # packets statistics
    sent = count
    received = 0
    loss_percent = 100.0
    # try to parse summary
    # windows: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
    m = re.search(r'Sent = (\d+), Received = (\d+), Lost = (\d+)', out)
    if m:
        sent = int(m.group(1))
        received = int(m.group(2))
        loss_percent = (int(m.group(3)) / sent) * 100.0 if sent else 100.0
    else:
        # unix: "4 packets transmitted, 4 received, 0% packet loss"
        m = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received, (\d+)% packet loss', out)
        if m:
            sent = int(m.group(1))
            received = int(m.group(2))
            loss_percent = float(m.group(3))

    stats = {'sent': sent, 'received': received, 'loss_percent': loss_percent, 'rtts': rtts}
    if rtts:
        stats.update({'min': min(rtts), 'avg': statistics.mean(rtts), 'max': max(rtts)})
    else:
        stats.update({'min': None, 'avg': None, 'max': None})
    return stats


def repeated_tcp_test(host, port, retries=6, timeout=3):
    attempts = 0
    successes = 0
    rtts = []
    for i in range(retries):
        attempts += 1
        ok, rtt = tcp_connect_test(host, port, timeout=timeout)
        if ok and rtt is not None:
            successes += 1
            # store in ms
            rtts.append(rtt * 1000.0)
        time.sleep(0.05)
    result = {'attempts': attempts, 'successes': successes, 'loss_percent': (1 - successes/attempts) * 100.0 if attempts else 100.0, 'rtts': rtts}
    if rtts:
        result.update({'min': min(rtts), 'avg': statistics.mean(rtts), 'max': max(rtts), 'p50': percentile(rtts, 50), 'p95': percentile(rtts, 95), 'p99': percentile(rtts, 99)})
    else:
        result.update({'min': None, 'avg': None, 'max': None, 'p50': None, 'p95': None, 'p99': None})
    return result


def http_download_test(url, proxy=None, duration=10, concurrency=1, chunk_size=64*1024):
    """Download for `duration` seconds (or until EOF) and measure throughput.
    Returns dict: total_bytes, duration, avg_bps, peak_bps
    """
    stop_time = time.time() + duration
    total_bytes = 0
    lock = threading.Lock()
    peak = 0

    proxies = None
    if proxy:
        proxies = {'http': proxy, 'https': proxy}

    def worker():
        nonlocal total_bytes, peak
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)
        try:
            r = session.get(url, stream=True, timeout=10)
            start = time.time()
            bytes_read = 0
            window_start = start
            window_bytes = 0
            for chunk in r.iter_content(chunk_size=chunk_size):
                if not chunk:
                    break
                now = time.time()
                bytes_read += len(chunk)
                window_bytes += len(chunk)
                if now - window_start >= 0.5:
                    bw = window_bytes / (now - window_start)
                    with lock:
                        if bw > peak:
                            peak = bw
                        total_bytes += window_bytes
                    window_start = now
                    window_bytes = 0
                if now >= stop_time:
                    break
            # add leftover
            with lock:
                total_bytes += window_bytes
        except Exception:
            pass

    threads = []
    for _ in range(max(1, concurrency)):
        t = threading.Thread(target=worker, daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=duration + 5)

    actual_duration = duration
    avg_bps = (total_bytes / actual_duration) if actual_duration > 0 else 0
    return {'total_bytes': total_bytes, 'duration': actual_duration, 'avg_bps': avg_bps, 'peak_bps': peak}


def udp_game_test(target_host, target_port, duration=5, psize=60, interval_ms=20, expect_echo=False):
    """Send small UDP packets for duration seconds. If expect_echo True, waits for echo and measures RTTs.
    Returns: sent, received, loss_percent, rtts list, pps
    """
    addr = (target_host, int(target_port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    stop = time.time() + duration
    sent = 0
    rcv = 0
    rtts = []
    payload = os.urandom(psize)
    seq = 0
    while time.time() < stop:
        seq += 1
        ts = time.time()
        try:
            sock.sendto(payload, addr)
            sent += 1
            if expect_echo:
                try:
                    data, _ = sock.recvfrom(2048)
                    rcv += 1
                    rtts.append((time.time() - ts) * 1000.0)
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(interval_ms / 1000.0)
    sock.close()
    loss = (1 - (rcv / sent)) * 100.0 if sent else 100.0
    pps = sent / duration if duration > 0 else 0
    stats = {'sent': sent, 'received': rcv, 'loss_percent': loss, 'rtts': rtts, 'pps': pps}
    if rtts:
        stats.update({'min': min(rtts), 'avg': statistics.mean(rtts), 'max': max(rtts), 'p50': percentile(rtts, 50), 'p95': percentile(rtts, 95)})
    else:
        stats.update({'min': None, 'avg': None, 'max': None, 'p50': None, 'p95': None})
    return stats


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_xray_for_node(node, xray_path='xray', start_timeout=5):
    """Try to start xray with a minimal client config for this single outbound node.
    Returns: {'proc': Popen, 'socks': 'socks5://127.0.0.1:PORT', 'http': 'http://127.0.0.1:PORT'} or None on failure.

    NOTE: This is a best-effort helper: not all node types/options are covered. Use --xray-path to set binary path.
    """
    proto = node.get('protocol')
    if proto not in ('vless', 'vmess'):
        return None

    # prepare ports
    socks_port = get_free_port()
    http_port = get_free_port()
    tempdir = tempfile.mkdtemp(prefix='xray-client-')
    cfg_path = os.path.join(tempdir, 'config.json')

    # build minimal outbound
    if proto == 'vless':
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": node.get('add'),
                        "port": int(node.get('port') or 0),
                        "users": [
                            {"id": node.get('id'), "flow": ""}
                        ]
                    }
                ]
            }
        }
    else:  # vmess
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": node.get('add'),
                        "port": int(node.get('port') or 0),
                        "users": [
                            {"id": node.get('id')}
                        ]
                    }
                ]
            }
        }

    cfg = {
        "log": {"access":"", "error":"", "loglevel":"warning"},
        "inbounds": [
            {"port": socks_port, "protocol": "socks", "settings": {"udp": True}},
            {"port": http_port, "protocol": "http", "settings": {}}
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "settings": {}}
        ]
    }

    try:
        with open(cfg_path, 'w', encoding='utf-8') as fh:
            json.dump(cfg, fh)
        proc = subprocess.Popen([xray_path, '-config', cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # wait a bit for the process to become ready
        t0 = time.time()
        while time.time() - t0 < start_timeout:
            # try to connect to socks port
            try:
                s = socket.create_connection(('127.0.0.1', socks_port), timeout=1)
                s.close()
                return {'proc': proc, 'socks': f'socks5h://127.0.0.1:{socks_port}', 'http': f'http://127.0.0.1:{http_port}', 'tmpdir': tempdir}
            except Exception:
                time.sleep(0.1)
        # failed to start
        proc.kill()
    except Exception:
        pass
    try:
        shutil.rmtree(tempdir)
    except Exception:
        pass
    return None


def stop_xray(x):
    try:
        x['proc'].terminate()
        x['proc'].wait(timeout=2)
    except Exception:
        try:
            x['proc'].kill()
        except Exception:
            pass
    try:
        shutil.rmtree(x.get('tmpdir', ''), ignore_errors=True)
    except Exception:
        pass


def test_nodes(nodes, timeout=5, workers=10, ping_count=4, tcp_retries=6, tcp_timeout=3, do_speed=False, speed_url=None, speed_duration=10, speed_concurrency=1, speed_requests=None, do_game=False, udp_target=None, game_duration=5, game_psize=60, game_interval_ms=20, expect_echo=False, start_xray=False, xray_path='xray', show_progress=True):
    results = []

    def worker(node):
        add = node.get('add')
        port = node.get('port')
        node_res = {**node}

        steps = ['ping', 'tcp']
        if do_speed:
            steps.append('speed')
        if do_game:
            steps.append('game')

        pbar_local = None
        if show_progress and tqdm:
            try:
                pbar_local = tqdm(total=len(steps), desc=f"{node.get('ps') or node.get('raw')[:20]}", leave=False)
            except Exception:
                pbar_local = None

        # optionally start xray proxy for this node
        x = None
        proxy_http = None
        if start_xray:
            x = run_xray_for_node(node, xray_path=xray_path)
            if x:
                proxy_http = x.get('http')

        # Ping test (always do if we have a host)
        if add:
            try:
                ping_stats = ping_host(add, count=ping_count, timeout_ms=max(200, int(timeout*1000)))
                node_res['ping'] = ping_stats
            except Exception:
                node_res['ping'] = {'sent': ping_count, 'received': 0, 'loss_percent': 100.0, 'rtts': []}
        else:
            node_res['ping'] = None
        if pbar_local:
            pbar_local.update(1)

        # TCP repeated test if port is known
        if add and port:
            try:
                tcp_stats = repeated_tcp_test(add, int(port), retries=tcp_retries, timeout=tcp_timeout)
                node_res['tcp'] = tcp_stats
                node_res['reachable'] = tcp_stats['successes'] > 0
            except Exception:
                node_res['tcp'] = None
                node_res['reachable'] = False
        else:
            node_res['tcp'] = None
            node_res['reachable'] = False
        if pbar_local:
            pbar_local.update(1)

        # Speed test
        if do_speed:
            try:
                proxy = proxy_http
                res = http_download_test(speed_url, proxy=proxy, duration=speed_duration, concurrency=speed_concurrency)
                node_res['speed'] = res
            except Exception:
                node_res['speed'] = None
            if pbar_local:
                pbar_local.update(1)

        # Game UDP test
        if do_game and udp_target:
            try:
                target_host, target_port = udp_target.split(':', 1)
                res = udp_game_test(target_host, int(target_port), duration=game_duration, psize=game_psize, interval_ms=game_interval_ms, expect_echo=expect_echo)
                node_res['game'] = res
            except Exception:
                node_res['game'] = None
            if pbar_local:
                pbar_local.update(1)

        # stop xray
        if x:
            try:
                stop_xray(x)
            except Exception:
                pass
        if pbar_local:
            pbar_local.close()

        return node_res

    # run with progress bar (if available)
    pbar = None
    if show_progress and tqdm:
        pbar = tqdm(total=len(nodes), desc='Checking nodes')

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(worker, n) for n in nodes]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception:
                pass
            if pbar:
                pbar.update(1)
    if pbar:
        pbar.close()
    return results


def generate_html_report(tested, out_html='report.html'):
    """Generate a simple HTML report with table and charts (Chart.js via CDN)."""
    rows = []
    charts_js = []
    for i, n in enumerate(tested):
        name = (n.get('ps') or n.get('raw'))[:60]
        host = n.get('add') or ''
        port = n.get('port') or ''
        reach = 'OK' if n.get('reachable') else 'DOWN'
        tcp = n.get('tcp') or {}
        p95 = tcp.get('p95')
        loss = tcp.get('loss_percent') if tcp else None
        ping = n.get('ping') or {}
        ping_p = ping.get('loss_percent') if ping else None
        speed = n.get('speed') or {}
        avg_bps = speed.get('avg_bps') if speed else None
        game = n.get('game') or {}
        pps = game.get('pps') if game else None
        rows.append((i, name, host, port, reach, loss, p95, ping_p, avg_bps, pps))

    html = ["""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>VPN Check Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}</style>
</head>
<body>
<h2>VPN Check Report</h2>
<table>
<thead><tr><th>#</th><th>Name</th><th>Host</th><th>Port</th><th>State</th><th>Loss%</th><th>p95 ms</th><th>PingLoss%</th><th>Speed MB/s</th><th>PPS</th></tr></thead>
<tbody>
"""
    ]
    for r in rows:
        html.append(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td><td>{r[5] or ''}</td><td>{r[6] or ''}</td><td>{r[7] or ''}</td><td>{(f'{(r[8]/1024/1024):.2f}' if r[8] is not None else '')}</td><td>{r[9] or ''}</td></tr>")

    html.append("</tbody></table>\n")

    # add per-node charts for ping rtts and speed if available
    html.append('<h3>Per-node charts</h3>')
    for i, n in enumerate(tested):
        ping = n.get('ping') or {}
        rtts = ping.get('rtts') or []
        speed = n.get('speed') or {}
        avg = speed.get('avg_bps') or 0
        html.append(f'<div style="margin-bottom:24px"><h4>{i} - {(n.get("ps") or n.get("raw")[:40])}</h4>')
        if rtts:
            html.append(f'<canvas id="c_ping_{i}" width="400" height="100"></canvas>')
            charts_js.append((f'c_ping_{i}', rtts, 'RTT (ms)'))
        if avg:
            html.append(f'<canvas id="c_speed_{i}" width="400" height="80"></canvas>')
            charts_js.append((f'c_speed_{i}', [avg], 'Avg Bps'))
        html.append('</div>')

    # script
    html.append('<script>')
    html.append('const labels = (n) => n.map((_,i)=> i+1);')
    for cid, data, lab in charts_js:
        data_json = json.dumps(data)
        html.append(f"new Chart(document.getElementById('{cid}').getContext('2d'), {{type: 'line', data: {{labels: labels({data_json}), datasets:[{{label:'{lab}', data:{data_json}, borderColor:'rgb(75, 192, 192)', tension:0.2}}]}}, options:{{responsive:true}}}});")
    html.append('</script>')
    html.append('</body></html>')

    with open(out_html, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(html))


def main():
    parser = argparse.ArgumentParser(description='VPN subscription parser + basic tests')
    parser.add_argument('--url', '-u', help='Subscription URL')
    parser.add_argument('--file', '-f', help='File with subscription content')
    parser.add_argument('--output', '-o', help='Output JSON file', default='nodes.json')
    parser.add_argument('--timeout', type=int, default=5, help='Socket timeout seconds')
    parser.add_argument('--workers', type=int, default=10, help='Parallel workers for tests')
    parser.add_argument('--ping-count', type=int, default=4, help='ICMP ping count')
    parser.add_argument('--tcp-retries', type=int, default=10, help='Number of TCP connect attempts per node')
    parser.add_argument('--tcp-timeout', type=int, default=3, help='TCP connect timeout seconds per attempt')
    parser.add_argument('--detailed', action='store_true', help='Write more detailed JSON output')
    parser.add_argument('--do-speed', action='store_true', help='Run HTTP download speed test to --speed-url')
    parser.add_argument('--speed-url', default='http://speedtest.tele2.net/5MB.zip', help='URL for download speed test')
    parser.add_argument('--speed-duration', type=int, default=10, help='Duration sec for speed test')
    parser.add_argument('--speed-concurrency', type=int, default=1, help='Concurrent workers for speed test')
    parser.add_argument('--do-game', action='store_true', help='Run UDP gaming simulation (requires --udp-target host:port)')
    parser.add_argument('--udp-target', help='UDP target host:port for gaming test')
    parser.add_argument('--game-duration', type=int, default=5, help='Duration sec for game test')
    parser.add_argument('--game-psize', type=int, default=60, help='Packet size for game test (bytes)')
    parser.add_argument('--game-interval', type=int, default=20, help='Interval ms between game packets')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bar output')
    parser.add_argument('--start-xray', action='store_true', help='Start xray locally and proxy tests through it (requires --xray-path)')
    parser.add_argument('--xray-path', default='xray', help='Path to xray binary')
    parser.add_argument('--html-output', help='Generate HTML report (path)', default=None)
    parser.add_argument('--reports-dir', default='reports', help='Directory to save timestamped reports when --html-output is not provided')
    parser.add_argument('--open-report', action='store_true', help='Open generated HTML report in the default browser')
    parser.add_argument('--no-html', action='store_true', help='Do not generate an HTML report')
    args = parser.parse_args()

    text = ''
    if args.url:
        print(f'Fetching {args.url}...')
        text = fetch_url(args.url, timeout=max(15, args.timeout))
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as fh:
            text = fh.read()
    else:
        print('Please provide --url or --file', file=sys.stderr)
        sys.exit(1)

    nodes = gather_nodes_from_text(text)
    print(f'Found {len(nodes)} nodes')

    # run tests
    tested = test_nodes(
        nodes,
        timeout=args.timeout,
        workers=args.workers,
        ping_count=args.ping_count,
        tcp_retries=args.tcp_retries,
        tcp_timeout=args.tcp_timeout,
        do_speed=args.do_speed,
        speed_url=args.speed_url,
        speed_duration=args.speed_duration,
        speed_concurrency=args.speed_concurrency,
        do_game=args.do_game,
        udp_target=args.udp_target,
        game_duration=args.game_duration,
        game_psize=args.game_psize,
        game_interval_ms=args.game_interval,
        expect_echo=False,
        start_xray=args.start_xray,
        xray_path=args.xray_path,
        show_progress=not args.no_progress,
    )

    # generate html report unless disabled
    if not args.no_html:
        # determine html output path
        if args.html_output:
            html_path = args.html_output
        else:
            reports_dir = Path(args.reports_dir)
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            html_path = str(reports_dir / f"report-{ts}.html")
        try:
            generate_html_report(tested, html_path)
            abs_path = os.path.abspath(html_path)
            print(f'Wrote HTML report to {abs_path}')
            if args.open_report:
                try:
                    webbrowser.open('file://' + abs_path)
                except Exception as oe:
                    print(f'Failed to open report in browser: {oe}')
        except Exception as e:
            print(f'Failed to write HTML report: {e}')

    # write results (include report path if available)
    report_path = locals().get('abs_path', None)
    meta = {'generated_at': datetime.utcnow().isoformat(), 'report': report_path, 'nodes': tested}
    with open(args.output, 'w', encoding='utf-8') as fo:
        json.dump(meta, fo, ensure_ascii=False, indent=2)

    # print summary table
    for n in tested:
        name = n.get('ps') or n.get('raw')[:60]
        host = n.get('add')
        port = n.get('port')
        reach = 'OK' if n.get('reachable') else 'DOWN'
        tcp = n.get('tcp') or {}
        p95 = tcp.get('p95')
        succ = tcp.get('successes') if tcp else None
        attempts = tcp.get('attempts') if tcp else None
        ratio = f"{succ}/{attempts}" if succ is not None else '-'
        p95s = f"{p95:.1f} ms" if p95 else '-'
        loss = f"{tcp.get('loss_percent', 0):.1f}%" if tcp else '-'
        ping_loss = n.get('ping', {}).get('loss_percent') if n.get('ping') else None
        ping_summary = f"{ping_loss:.0f}%" if ping_loss is not None else '-'
        speed = n.get('speed') or {}
        avg_bps = speed.get('avg_bps')
        avg_speed = f"{avg_bps/1024/1024:.2f} MB/s" if (avg_bps is not None) else '-'
        game = n.get('game') or {}
        pps = f"{game.get('pps', 0):.1f}" if game and (game.get('pps') is not None) else '-'
        print(f"{name:40.40} {host:20} {str(port):6} {reach:6} loss:{loss:6} tcp:{ratio:8} p95:{p95s:10} ping:{ping_summary:6} speed:{avg_speed:10} pps:{pps:6}")


if __name__ == '__main__':
    main()
