#!/usr/bin/env python3
"""secstatus - host intrusion detection daemon feeding the Conky SEC//STATUS panel.

Run with no arguments as the daemon (systemd does this).
Management commands (run with sudo):
  secstatus approve [NAME ...]   trust flagged outbound programs (all if no names)
  secstatus pending              show outbound programs waiting for approval
  secstatus known                list programs trusted to make outbound connections
  secstatus relearn              forget outbound baseline; learn again for 30 min
  secstatus log [N]              show the last N events (default 20)
  secstatus geoip-update         download the DB-IP country database
  secstatus sensor               show whether the eBPF sensor is running

Sensors:
  - journal     UFW blocks, auth failures, sudo (live, last 24h)
  - ss polling  listening sockets + established connections, every 5s
  - eBPF        every outbound TCP connect via the kernel tracepoint
                sock:inet_sock_set_state (needs bpftrace; falls back to polling)

IP geolocation by DB-IP.com (https://db-ip.com), CC BY 4.0.
"""
import gzip, ipaddress, json, os, re, shutil, subprocess, sys, threading, time
import urllib.request
from collections import Counter, deque
from datetime import date, timedelta

RUN_DIR = "/run/secstatus"
STATE_DIR = "/var/lib/secstatus"
BASELINE = os.path.join(STATE_DIR, "listeners.baseline")
OUT_BASELINE = os.path.join(STATE_DIR, "outbound.baseline")
EVENTS = os.path.join(STATE_DIR, "events.log")
GEO_DB = os.path.join(STATE_DIR, "country.mmdb")
STATUS = os.path.join(RUN_DIR, "status")
WINDOW = 600       # seconds that count as "recent" for auth fails
RED_FAILS = 5      # recent fails that trigger RED
LEARN_SECS = 1800  # outbound learning period on first run / relearn
EVENTS_MAX = 512 * 1024
COLORS = {"GREEN": "#50FA7B", "YELLOW": "#F1FA8C", "RED": "#FF4444"}  # match security.conf palette
SPARK = "▂▃▄▅▆▇█"  # nonzero levels; zero is drawn as ▁

AUTH_FAIL = re.compile(r"Failed password|authentication failure|Invalid user|FAILED SU", re.I)
IP_RE = re.compile(r"(?:from|rhost=|SRC=)\s*([0-9a-fA-F:.]{7,})")
SRC_RE = re.compile(r"SRC=([0-9a-fA-F:.]+)")
PROC_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')

lock = threading.Lock()
state = {"day": date.today(), "ufw": 0, "fails": 0, "sudo": 0, "last_fail": "none",
         "recent": deque(), "block_cc": Counter(), "hourly": Counter()}
flagged = {}  # outbound program name -> peer it was first seen talking to
logged = set()  # events currently active, so each is logged once per appearance


# ---------- GeoIP ----------

_geo = {"reader": None, "mtime": 0}


def geo_reload():
    """(Re)open the country database if it appeared or changed."""
    try:
        mtime = os.path.getmtime(GEO_DB)
    except OSError:
        _geo["reader"] = None
        return
    if mtime == _geo["mtime"] and _geo["reader"] is not None:
        return
    try:
        import maxminddb
        _geo["reader"] = maxminddb.open_database(GEO_DB)
        _geo["mtime"] = mtime
    except Exception as e:
        print(f"geoip unavailable: {e}", flush=True)
        _geo["reader"] = None


def country(ip):
    """Two-letter country code, 'LAN' for private addresses, '' if unknown."""
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return ""
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "LAN"
    reader = _geo["reader"]
    if reader is None:
        return ""
    try:
        rec = reader.get(str(addr)) or {}
        return rec.get("country", {}).get("iso_code", "") or ""
    except Exception:
        return ""


def peer_country(peer):
    """Country for an 'ip:port' or '[ipv6]:port' peer."""
    return country(peer.rsplit(":", 1)[0])


# ---------- journal: UFW blocks, auth fails, sudo ----------

def reset_if_new_day():
    if state["day"] != date.today():
        state.update(day=date.today(), ufw=0, fails=0, sudo=0, last_fail="none",
                     block_cc=Counter())


def handle(entry):
    msg = entry.get("MESSAGE")
    if not isinstance(msg, str):
        return
    ident = entry.get("SYSLOG_IDENTIFIER", "")
    ts = int(entry.get("__REALTIME_TIMESTAMP", "0")) / 1e6
    # sshd logs each failure twice (PAM + its own line); keep only one
    if ident.startswith("sshd") and "pam_unix" in msg:
        return
    is_today = date.fromtimestamp(ts) == date.today()
    with lock:
        reset_if_new_day()
        if "[UFW BLOCK]" in msg:
            state["hourly"][int(ts // 3600)] += 1
            if is_today:
                state["ufw"] += 1
                m = SRC_RE.search(msg)
                state["block_cc"][country(m.group(1)) if m else ""] += 1
        elif AUTH_FAIL.search(msg):
            state["recent"].append(ts)
            if is_today:
                state["fails"] += 1
                m = IP_RE.search(msg)
                src = m.group(1) if m else "local"
                state["last_fail"] = f"{time.strftime('%H:%M', time.localtime(ts))} {src}"
        elif ident == "sudo" and "COMMAND=" in msg and is_today:
            state["sudo"] += 1


def follow_journal():
    proc = subprocess.Popen(
        ["journalctl", "--since", "-24h", "-f", "-o", "json", "--no-pager"],
        stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        try:
            handle(json.loads(line))
        except json.JSONDecodeError:
            continue
    os._exit(1)  # journalctl died; let systemd restart us


def sparkline(now):
    """12 characters, each one 2 hours of UFW blocks, oldest first."""
    hour = int(now // 3600)
    with lock:
        for h in [h for h in state["hourly"] if h <= hour - 24]:
            del state["hourly"][h]
        buckets = [state["hourly"][hour - 2 * i - 1] + state["hourly"][hour - 2 * i]
                   for i in range(11, -1, -1)]
    peak = max(buckets)
    if peak == 0:
        return "▁" * 12, 0
    chars = "".join("▁" if b == 0 else SPARK[min(len(SPARK) - 1, (b * len(SPARK) - 1) // peak)]
                    for b in buckets)
    return chars, peak


# ---------- process context: who ran what ----------

SECRET_FLAGS = {"-H", "--header", "-u", "--user", "--password", "--pass", "--token",
                "--api-key", "--oauth2-bearer", "-b", "--cookie"}
SECRET_KV = re.compile(r"(?i)((?:token|key|secret|pass(?:word|wd)?|auth\w*|sig\w*|session)=)[^&\s]+")
BEARER = re.compile(r"(?i)\b(bearer|basic)\s+\S+")
URL_CREDS = re.compile(r"://[^/@\s]+@")


def redact(args):
    """Hide credentials in a command line before it is written anywhere."""
    out, hide_next = [], False
    for a in args:
        if hide_next:
            out.append("<redacted>")
            hide_next = False
            continue
        flag, eq, _ = a.partition("=")
        if flag in SECRET_FLAGS:
            if eq:
                out.append(flag + "=<redacted>")
            else:
                out.append(a)
                hide_next = True
            continue
        a = URL_CREDS.sub("://<redacted>@", a)
        a = SECRET_KV.sub(r"\1<redacted>", a)
        a = BEARER.sub(r"\1 <redacted>", a)
        out.append(a)
    return out


def parent_of(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return int(f.read().rsplit(")", 1)[1].split()[1])  # comm may contain ')'
    except (OSError, IndexError, ValueError):
        return 0


def context(pid, depth=3):
    """'wget -q https://…  <- fish <- ptyxis' for a pid, or '' if it already exited."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            args = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
    except (OSError, ValueError):
        return ""
    cmd = " ".join(redact(args))
    if len(cmd) > 110:
        cmd = cmd[:107] + "..."
    chain, p = [], pid
    for _ in range(depth):
        p = parent_of(p)
        if p <= 1:
            break
        chain.append(proc_name(p, "?"))
    ctx = cmd + ("  <- " + " <- ".join(chain) if chain else "")
    return ctx.replace(";", ",").replace("\n", " ").replace("|", "/")


def fmt_ctx(ctx):
    return f"\n                    cmd: {ctx}" if ctx else ""


# ---------- eBPF: every outbound TCP connect ----------

# Fires when a TCP socket enters SYN_SENT (state 2): the moment a program
# calls connect(). Runs in the connecting process's context, so pid is right.
BPF_PROG = r"""
tracepoint:sock:inet_sock_set_state
/args.newstate == 2 && args.protocol == 6/
{
  if (args.family == 2) {
    printf("C|%d|%s|%s|%d\n", pid, comm, ntop(args.daddr), args.dport);
  } else {
    printf("C|%d|%s|%s|%d\n", pid, comm, ntop(args.daddr_v6), args.dport);
  }
}
"""
ebpf = {"status": "off", "events": {}, "count": 0}


def proc_name(pid, fallback):
    """Main-process name (comm in eBPF is the *thread*, e.g. 'Socket Thread')."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip() or fallback
    except OSError:
        return fallback  # process already exited


def parse_bpf_line(line):
    """'C|pid|comm|ip|port' -> (name, peer, pid) or None for loopback/garbage."""
    parts = line.rstrip("\n").split("|")
    if len(parts) != 5 or parts[0] != "C":
        return None
    _, pid, comm, ip, port = parts
    try:
        addr = ipaddress.ip_address(ip)
        pid = int(pid)
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        if addr.ipv4_mapped.is_loopback:
            return None
        ip = str(addr.ipv4_mapped)
    peer = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    return proc_name(pid, comm), peer, pid


def follow_ebpf():
    if not shutil.which("bpftrace"):
        ebpf["status"] = "not installed"
        return
    while True:
        ebpf["status"] = "starting"
        proc = subprocess.Popen(["bpftrace", "-B", "line", "-e", BPF_PROG],
                                stdout=subprocess.PIPE, text=True)  # stderr -> journal

        def mark_on_if_alive(p=proc):
            # newer bpftrace prints "Attaching..." to stderr, so also treat
            # "still running after a few seconds" as successfully attached
            if p.poll() is None and ebpf["status"] == "starting":
                ebpf["status"] = "on"
        threading.Timer(5, mark_on_if_alive).start()

        for line in proc.stdout:
            if line.startswith("Attaching"):
                ebpf["status"] = "on"
                continue
            hit = parse_bpf_line(line)
            if hit:
                ebpf["status"] = "on"
                name, peer, pid = hit
                with lock:
                    ebpf["count"] += 1
                    seen = name in ebpf["events"]
                if not seen:
                    # read the command line NOW: short-lived programs vanish in milliseconds
                    ctx = context(pid)
                    with lock:
                        ebpf["events"].setdefault(name, (peer, pid, ctx))
        proc.wait()
        ebpf["status"] = f"exited ({proc.returncode}), retrying"
        print(f"bpftrace exited with {proc.returncode}; retrying in 30s", flush=True)
        time.sleep(30)


# ---------- listening ports ----------

def listeners():
    """Map 'proto addr:port' -> (process name, pid) for every listening socket."""
    out = subprocess.run(["ss", "-tulpnH"], capture_output=True, text=True).stdout
    socks = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        m = PROC_RE.search(line)
        socks[f"{p[0]} {p[4]}"] = (m.group(1), int(m.group(2))) if m else ("?", 0)
    return socks


def ephemeral_range():
    """The kernel's range for automatically assigned client ports."""
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            lo, hi = map(int, f.read().split())
            return lo, hi
    except (OSError, ValueError):
        return 32768, 60999


EPHEMERAL = ephemeral_range()


def is_client_udp(sock):
    """UDP on an auto-assigned port is a client socket (QUIC, WebRTC, DNS), not a server."""
    proto, addr = sock.split(" ", 1)
    if proto != "udp":
        return False
    try:
        port = int(addr.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return False
    return EPHEMERAL[0] <= port <= EPHEMERAL[1]


def is_local_only(sock):
    """True if the socket is bound to loopback (unreachable from the network)."""
    addr = sock.split(" ", 1)[1].rsplit(":", 1)[0].strip("[]").split("%")[0]
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False  # '*' and similar wildcards are exposed


def load_baseline(current):
    if not os.path.exists(BASELINE):
        with open(BASELINE, "w") as f:
            f.write("\n".join(sorted(current)) + "\n")
    with open(BASELINE) as f:
        return {l.strip() for l in f if l.strip()}


# ---------- outbound connections (polling) ----------

def outbound():
    """Map program name -> (peer, pid) for every established non-loopback connection."""
    out = subprocess.run(["ss", "-tunpH", "state", "established"],
                         capture_output=True, text=True).stdout
    conns = {}
    for line in out.splitlines():
        m = PROC_RE.search(line)
        if not m:
            continue
        before = line[:m.start()].split()
        if not before:
            continue
        peer = before[-1]
        host = peer.rsplit(":", 1)[0].strip("[]").split("%")[0]
        if host.startswith("::ffff:"):
            host = host[7:]
        try:
            if ipaddress.ip_address(host).is_loopback:
                continue
        except ValueError:
            continue
        conns.setdefault(m.group(1), (peer, int(m.group(2))))
    return conns


def load_outbound_baseline():
    """Returns (known program names, learn-until timestamp)."""
    if not os.path.exists(OUT_BASELINE):
        learn_until = int(time.time()) + LEARN_SECS
        with open(OUT_BASELINE, "w") as f:
            f.write(f"#learn-until {learn_until}\n")
        return set(), learn_until
    names, learn_until = set(), 0
    with open(OUT_BASELINE) as f:
        for l in f:
            l = l.strip()
            if l.startswith("#learn-until"):
                learn_until = int(l.split()[1])
            elif l and not l.startswith("#"):
                names.add(l)
    return names, learn_until


def add_outbound_baseline(names):
    with open(OUT_BASELINE, "a") as f:
        for n in names:
            f.write(n + "\n")


# ---------- event log ----------

def log_event(key, text):
    """Log once per appearance. text may be a function, so costly context is only
    gathered for events that will actually be written."""
    if key in logged:
        return
    logged.add(key)
    if callable(text):
        text = text()
    try:
        if os.path.exists(EVENTS) and os.path.getsize(EVENTS) > EVENTS_MAX:
            os.replace(EVENTS, EVENTS + ".1")
        fresh = not os.path.exists(EVENTS)
        with open(EVENTS, "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + text + "\n")
        if fresh:
            os.chmod(EVENTS, 0o600)  # command lines belong to root's eyes only
    except OSError as e:
        print(f"event log error: {e}", flush=True)


def forget_gone(prefix, active_keys):
    """Drop logged events of this kind that are no longer active."""
    for k in [k for k in logged if k.startswith(prefix) and k not in active_keys]:
        logged.discard(k)


# ---------- output ----------

def write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def tag(peer):
    cc = peer_country(peer)
    return f"{peer} [{cc}]" if cc else peer


def render():
    now = time.time()
    geo_reload()

    # listeners
    current = {s: p for s, p in listeners().items() if not is_client_udp(s)}
    baseline = load_baseline(set(current))
    new_all = {s: v for s, v in current.items() if s not in baseline}
    listen_keys = set()
    for s, (proc, pid) in new_all.items():
        key = f"L|{s}"
        listen_keys.add(key)
        scope = "local-only" if is_local_only(s) else "EXPOSED"
        log_event(key, lambda s=s, proc=proc, pid=pid, scope=scope:
                  f"LISTEN   {s} ({proc}) {scope}{fmt_ctx(context(pid))}")
    forget_gone("L|", listen_keys)
    # only network-exposed listeners raise the threat level
    new = sorted(f"{s} ({proc})" for s, (proc, _) in new_all.items() if not is_local_only(s))

    # outbound: polling snapshot + everything eBPF saw since the last render.
    # values are (peer, pid, ctx); ctx is None when it hasn't been read yet
    conns = {n: (p, pid, None) for n, (p, pid) in outbound().items()}
    with lock:
        caught, ebpf["events"] = ebpf["events"], {}
    for n, v in caught.items():
        if n not in conns or conns[n][2] is None:
            conns[n] = v  # eBPF's copy carries the command line captured at connect time

    def ctx_of(v):
        return v[2] if v[2] is not None else context(v[1])

    known, learn_until = load_outbound_baseline()
    unknown = {n: v for n, v in conns.items() if n not in known}
    learning = now < learn_until
    if learning:
        if unknown:
            add_outbound_baseline(sorted(unknown))
            for n, v in unknown.items():
                log_event(f"learned|{n}", lambda n=n, v=v:
                          f"LEARNED  {n} -> {tag(v[0])}{fmt_ctx(ctx_of(v))}")
    else:
        for n, v in unknown.items():
            if n not in flagged:
                flagged[n] = (v[0], ctx_of(v))
            log_event(f"O|{n}", lambda n=n: f"OUTBOUND {n} -> {tag(flagged[n][0])} "
                                            f"(not in baseline){fmt_ctx(flagged[n][1])}")
    for n in list(flagged):
        if n in known:
            del flagged[n]  # approved since it was flagged
            log_event(f"approved|{n}|{now}", f"APPROVED {n}")
    forget_gone("O|", {f"O|{n}" for n in flagged})

    # journal-derived numbers
    with lock:
        reset_if_new_day()
        while state["recent"] and now - state["recent"][0] > WINDOW:
            state["recent"].popleft()
        recent = len(state["recent"])
        ufw, fails, sudo, last = state["ufw"], state["fails"], state["sudo"], state["last_fail"]
        top_cc = [(cc or "??", n) for cc, n in state["block_cc"].most_common(2)]
    spark, peak = sparkline(now)

    if recent >= RED_FAILS:
        level = "RED"
    elif recent or new or flagged:
        level = "YELLOW"
    else:
        level = "GREEN"

    sensor = "eBPF" if ebpf["status"] == "on" else "poll"
    yellow = "${color " + COLORS["YELLOW"] + "}"
    new_txt = "none" if not new else f"{len(new)} (:{new[0].rsplit(':', 1)[-1].split()[0]})"
    if learning:
        out_txt = f"learning {int((learn_until - now) // 60) + 1}m"
    elif flagged:
        first = sorted(flagged)[0]
        cc = peer_country(flagged[first][0])
        out_txt = f"{yellow}{len(flagged)} ({first[:16]}{' ' + cc if cc else ''})"
    else:
        out_txt = f"none ({sensor})"
    cc_txt = "  " + " ".join(f"{cc}{n}" for cc, n in top_cc) if top_cc else ""

    c = COLORS[level]
    conky = "\n".join([
        f"THREAT      ${{color {c}}}{level}${{color}}",
        f"UFW BLOCKS  {ufw}{cc_txt}",
        f"UFW 24H     {spark}",
        f"AUTH FAILS  {fails}  ({recent} in 10m)",
        f"LAST FAIL   {last}",
        f"SUDO EVENTS {sudo}",
        f"NEW LISTEN  {yellow if new else ''}{new_txt}${{color}}",
        f"OUTBOUND    {out_txt}${{color}}",
    ]) + "\n"
    outbound_field = ";".join(f"{n}@{tag(p)}" + (f" | {ctx}" if ctx else "")
                              for n, (p, ctx) in sorted(flagged.items()))
    status = (f"LEVEL={level}\nUFW={ufw}\nFAILS={fails}\nRECENT={recent}\n"
              f"LAST_FAIL={last}\nSUDO={sudo}\nNEW={';'.join(new)}\n"
              f"OUTBOUND={outbound_field}\nLEARNING={int(learning)}\n"
              f"SENSOR={sensor}\nEBPF_STATUS={ebpf['status']}\nEBPF_COUNT={ebpf['count']}\n"
              f"SPARK_PEAK={peak}\n")
    write_atomic(os.path.join(RUN_DIR, "conky.txt"), conky)
    write_atomic(STATUS, status)


# ---------- command line ----------

def status_field(key):
    try:
        with open(STATUS) as f:
            for l in f:
                if l.startswith(key + "="):
                    return l.rstrip("\n")[len(key) + 1:]
    except OSError:
        pass
    return None


def pending():
    return [e for e in (status_field("OUTBOUND") or "").split(";") if e]


def geoip_update():
    first = date.today().replace(day=1)
    months = [first.strftime("%Y-%m"), (first - timedelta(days=1)).strftime("%Y-%m")]
    for m in months:  # this month's file can lag a day or two; fall back to last month
        url = f"https://download.db-ip.com/free/dbip-country-lite-{m}.mmdb.gz"
        print(f"Downloading {url} ...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "secstatus"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = gzip.decompress(r.read())
        except Exception as e:
            print(f"  failed: {e}")
            continue
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = GEO_DB + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, GEO_DB)
        print(f"Installed DB-IP country database {m} ({len(data) // 1024 // 1024} MB).")
        print("The daemon picks it up within 5 seconds. Geolocation by DB-IP.com, CC BY 4.0.")
        return
    sys.exit("Could not download the database.")


def cli(args):
    cmd = args[0]
    if cmd == "pending":
        items = pending()
        print("\n".join(i.replace(" | ", "\n    cmd: ") for i in items)
              if items else "Nothing waiting for approval.")
    elif cmd == "known":
        known, learn_until = load_outbound_baseline()
        print("\n".join(sorted(known)) or "(none yet)")
        if time.time() < learn_until:
            print(f"-- still learning for {int((learn_until - time.time()) // 60) + 1} more min")
    elif cmd == "approve":
        names = args[1:] or [e.split("@", 1)[0] for e in pending()]
        known, _ = load_outbound_baseline()
        add = [n for n in names if n not in known]
        add_outbound_baseline(add)
        print("Approved: " + ", ".join(add) if add else "Nothing to approve.")
    elif cmd == "log":
        n = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
        try:
            with open(EVENTS) as f:
                lines = f.readlines()[-n:]
            print("".join(lines).rstrip() or "(no events yet)")
        except OSError:
            print("(no events yet)")
    elif cmd == "relearn":
        if os.path.exists(OUT_BASELINE):
            os.remove(OUT_BASELINE)
        print(f"Outbound baseline cleared; learning for {LEARN_SECS // 60} min from next check.")
    elif cmd == "geoip-update":
        geoip_update()
    elif cmd == "sensor":
        print(f"eBPF sensor: {status_field('EBPF_STATUS') or 'unknown (daemon not running?)'}")
        print(f"connects seen by eBPF since start: {status_field('EBPF_COUNT') or 0}")
        print(f"GeoIP database: {'installed' if os.path.exists(GEO_DB) else 'missing (run: sudo secstatus geoip-update)'}")
    else:
        print(__doc__)
        sys.exit(1)


def main():
    geo_reload()  # before the journal replay, so today's blocks get countries
    threading.Thread(target=follow_journal, daemon=True).start()
    threading.Thread(target=follow_ebpf, daemon=True).start()
    time.sleep(2)  # let the last 24h of journal load
    while True:
        try:
            render()
        except Exception as e:
            print(f"render error: {e}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
    else:
        main()
