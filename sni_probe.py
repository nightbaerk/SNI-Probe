"""
sni_probe.py — Active SNI probe for VLESS+TCP+REALITY style fronting research.
USAGE:
  python sni_probe.py --server-ip 111.111.111.111 --server-port 443 --domains whitelist.txt --out results.csv --isp "Rostelecom" --where "Moscow"
What it does:
  1) Control: optional direct TCP:443 and TLS handshake to each domain (to see if the domain itself is reachable from your ISP).
  2) Test: TLS handshake to YOUR SERVER IP, but with SNI set to each domain. If the ISP blocks based on SNI, you'll observe resets/timeouts.
Notes:
  - This does NOT perform any VLESS auth; it only performs a TLS ClientHello with SNI (like a browser) and checks if the ServerHello arrives.
  - Use responsibly and lawfully. Respect your hosting provider, local law, and target sites' policies.
"""
import argparse, csv, socket, ssl, sys, time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

def tcp_check(host, port, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.time()
    try:
        s.connect((host, port))
        s.close()
        elapsed = time.time() - start
        return True, None, round(elapsed * 1000, 2)
    except Exception as e:
        elapsed = time.time() - start
        return False, str(e), round(elapsed * 1000, 2)

def tls_handshake(host, port, sni, timeout=6.0, tls_min=ssl.TLSVersion.TLSv1_2, tls_max=ssl.TLSVersion.TLSv1_3):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = tls_min
    ctx.maximum_version = tls_max
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    start = time.time()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw, server_hostname=sni)
        proto = tls_sock.version()
        cert = tls_sock.getpeercert(binary_form=False)
        tls_sock.close()
        elapsed = time.time() - start
        return True, {"protocol": proto, "subject": cert.get("subject") if cert else None, "latency_ms": round(elapsed * 1000, 2)}
    except Exception as e:
        elapsed = time.time() - start
        return False, {"error": str(e), "latency_ms": round(elapsed * 1000, 2)}

def classify_failure(errmsg: str, ok_on_wrong_version: bool, ok_on_alert: bool):
    """Return ('ok'|'fail', normalized_error) according to relaxed rules."""
    e = (errmsg or "").strip()
    el = e.lower()

    reality_ok_patterns = [
        "wrong version number",
        "wrong_version_number",
        "protocol version",
        "unrecognized name",
        "certificate unknown",
        "bad certificate"
    ]

    blocking_patterns = [
        "connection reset",
        "reset by peer",
        "connection refused",
        "timed out",
        "timeout",
        "network unreachable"
    ]

    if any(p in el for p in blocking_patterns):
        return ("fail", e)

    if ok_on_wrong_version and any(p in el for p in reality_ok_patterns):
        return ("ok", e)

    if "alert" in el:
        if "handshake failure" in el or "internal error" in el:
            return ("fail", e) if not ok_on_alert else ("ok", e)
        return ("ok", e) if ok_on_alert else ("fail", e)
    
    return ("fail", e)

def probe_domain(d, args, stats):
    """Проверка одного домена с полной логикой control + probe"""
    now = datetime.utcnow().isoformat() + "Z"
    ctrl_tcp = ""
    ctrl_tls = ""
    notes = ""

    if not args.no_control:
        ok_tcp, err_tcp, tcp_lat = tcp_check(d, 443, timeout=args.timeout)
        ctrl_tcp = f"ok:{tcp_lat}ms" if ok_tcp else f"fail:{(err_tcp or '').replace(chr(10),' ').replace(chr(13),' ')}"
        
        ok_tls, info_tls = tls_handshake(d, 443, d, timeout=args.timeout)
        if ok_tls:
            ctrl_tls = f"ok:{info_tls.get('protocol','?')}:{info_tls.get('latency_ms')}ms"
        else:
            err_str = info_tls.get('error', str(info_tls)) if isinstance(info_tls, dict) else str(info_tls)
            clean = err_str.replace("\n"," ").replace("\r"," ")
            lat = info_tls.get('latency_ms', 0) if isinstance(info_tls, dict) else 0
            ctrl_tls = f"fail:{clean}:{lat}ms"

    ok_probe, info_probe = tls_handshake(args.server_ip, args.server_port, d, timeout=args.timeout)
    if ok_probe:
        probe = "ok"
        lat = info_probe.get('latency_ms', 0)
        notes = f"proto={info_probe.get('protocol')},subject={info_probe.get('subject')},lat={lat}ms"
        err = ""
        stats["ok"] += 1
    else:
        err_str = info_probe.get('error', str(info_probe)) if isinstance(info_probe, dict) else str(info_probe)
        lat = info_probe.get('latency_ms', 0) if isinstance(info_probe, dict) else 0
        cls, clean = classify_failure(err_str, args.ok_on_wrong_version, args.ok_on_alert)
        probe = cls
        err = clean
        notes = f"lat={lat}ms"
        if cls == "ok":
            stats["ok"] += 1
        else:
            stats["fail"] += 1
    
    stats["total"] += 1

    if not args.quiet:
        print(f"\r[{stats['total']}/{stats['total_domains']}] ✓ {stats['ok']} | ✗ {stats['fail']} | Current: {d[:40]}", end="", flush=True)
    
    return [now, args.isp, args.where, args.server_ip, args.server_port, d, d, 
            ctrl_tcp, ctrl_tls, probe, err, notes]

def main():
    ap = argparse.ArgumentParser(description="SNI probe tool for VLESS+REALITY analysis")
    ap.add_argument("--server-ip", required=True, help="Your REALITY server IP")
    ap.add_argument("--server-port", type=int, default=443, help="Server port")
    ap.add_argument("--domains", required=True, help="File with domain list")
    ap.add_argument("--out", default="results.csv", help="Output CSV file")
    ap.add_argument("--isp", default="", help="ISP name (e.g., Beeline, Rostelecom)")
    ap.add_argument("--where", default="", help="Location (e.g., Moscow, SPb)")
    ap.add_argument("--no-control", action="store_true", help="Skip control checks")
    ap.add_argument("--delimiter", default=";", help="CSV delimiter")
    ap.add_argument("--timeout", type=float, default=6.0, help="Per-try timeout seconds")
    ap.add_argument("--ok-on-wrong-version", action="store_true", help="Treat WRONG_VERSION_NUMBER as ok")
    ap.add_argument("--ok-on-alert", action="store_true", help="Treat TLS alerts as ok")
    ap.add_argument("--workers", type=int, default=10, help="Parallel workers count")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = ap.parse_args()

    with open(args.domains, "r", encoding="utf-8") as f:
        candidates = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    
    if not candidates:
        print("Error: No domains found in file")
        sys.exit(1)

    stats = {"ok": 0, "fail": 0, "total": 0, "total_domains": len(candidates)}

    new_file = not Path(args.out).exists()
    fp = open(args.out, "a", encoding="utf-8", newline="")
    writer = csv.writer(fp, delimiter=args.delimiter, quoting=csv.QUOTE_ALL)
    if new_file:
        writer.writerow(["timestamp","isp_name","probe_location","server_ip","server_port","domain","sni",
                         "control_tcp_443","control_tls_handshake","probe_tls_to_server_with_sni","probe_error","notes"])
    
    if not args.quiet:
        print(f"Starting probe: {len(candidates)} domains, {args.workers} workers")
        print(f"Target: {args.server_ip}:{args.server_port}")
        print(f"Settings: timeout={args.timeout}s, ok_on_wrong_version={args.ok_on_wrong_version}, ok_on_alert={args.ok_on_alert}\n")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(probe_domain, d, args, stats): d for d in candidates}
        
        for future in as_completed(futures):
            try:
                result = future.result()
                writer.writerow(result)
                fp.flush()
                time.sleep(0.01)
            except Exception as e:
                domain = futures[future]
                if not args.quiet:
                    print(f"\nError processing {domain}: {e}")
    
    fp.close()
    
    if not args.quiet:
        print(f"\n\n{'='*60}")
        print(f"✅ COMPLETED")
        print(f"{'='*60}")
        print(f"Total domains:     {stats['total']}")
        print(f"Successful (ok):   {stats['ok']} ({stats['ok']/stats['total']*100:.1f}%)")
        print(f"Failed:            {stats['fail']} ({stats['fail']/stats['total']*100:.1f}%)")
        print(f"Results saved to:  {args.out}")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
