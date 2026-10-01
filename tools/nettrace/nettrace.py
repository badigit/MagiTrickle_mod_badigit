#!/usr/bin/env python3
"""nettrace — per-process network diagnostic for MagiTrickle routing verification.

Captures ALL outbound connections of a process — TCP *and UDP* — via the ETW
Kernel-Network provider, so UDP destinations are visible (Windows socket tables
expose only local UDP endpoints; the old network_watch.ps1 was TCP-only and blind
to where UDP actually went). Each destination is annotated against MagiTrickle
(/api/v1/lookup: rule/ipset membership = "should be tunneled") plus ASN/country.

Requires Administrator (ETW kernel session). Run from an elevated shell:
    python nettrace.py -n RocketLeague
    python nettrace.py -n chrome -n RocketLeague --for 60 --tsv out.tsv
    python nettrace.py --pid 12345 --debug-fields   # dump raw ETW field names

V1 is a live monitor. Router path cross-check (conntrack/mihomo TUNNEL vs DIRECT)
and test-case mode are tracked separately (see README / beads mt-wf4).
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import ipaddress
import json
import os
import pathlib
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait
from queue import Queue, Empty

import requests
import colorama

try:
    from etw import ETW, ProviderInfo
    from etw.etw import TraceProperties
    from etw.GUID import GUID
    from etw.common import RETURN_RAW_UNFORMATTED_DATA
except ImportError:
    print("FATAL: pywintrace not installed. Run:  pip install pywintrace", file=sys.stderr)
    sys.exit(2)

colorama.init()

KERNEL_NETWORK_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
# Microsoft-Windows-Kernel-Network event ids — outbound ("datasent") only.
# direction "out" — remote endpoint sits in daddr/dport; "in" — in saddr/sport.
EVT = {
    10: ("TCP", 4, "out"), 12: ("TCP", 4, "out"),   # IPv4 datasent / connect
    11: ("TCP", 4, "in"),  15: ("TCP", 4, "in"),    # IPv4 datarecv / accept
    42: ("UDP", 4, "out"), 43: ("UDP", 4, "in"),    # IPv4 UDP send / recv
    26: ("TCP", 6, "out"), 28: ("TCP", 6, "out"),   # IPv6 datasent / connect
    27: ("TCP", 6, "in"),  31: ("TCP", 6, "in"),    # IPv6 datarecv / accept
    58: ("UDP", 6, "out"), 59: ("UDP", 6, "in"),    # IPv6 UDP send / recv
}

# ANSI colors
C_GREEN = "\033[32m"; C_YELLOW = "\033[33m"; C_GRAY = "\033[90m"; C_RESET = "\033[0m"


# ---------------------------------------------------------------- process names
class ProcResolver:
    """PID -> process image name, via ctypes (no psutil dependency)."""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    def __init__(self):
        self._cache = {}
        self._k = ctypes.windll.kernel32
        self._k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        self._k.OpenProcess.restype = wt.HANDLE
        self._k.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
        self._k.QueryFullProcessImageNameW.restype = wt.BOOL
        self._k.CloseHandle.argtypes = [wt.HANDLE]
        self._k.CloseHandle.restype = wt.BOOL

    def name(self, pid):
        cached = self._cache.get(pid)
        if cached and time.monotonic() < cached[1]:
            return cached[0]
        n = self._query(pid)
        # Retry failures and expire names too: Windows can reuse a PID.
        self._cache[pid] = (n, time.monotonic() + (2 if n else 0.5))
        return n

    def _query(self, pid):
        h = self._k.OpenProcess(self.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wt.DWORD(1024)
            if self._k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                path = buf.value
                base = path.rsplit("\\", 1)[-1]
                if base.lower().endswith(".exe"):
                    base = base[:-4]
                return base
            return None
        finally:
            self._k.CloseHandle(h)


# ------------------------------------------------------------------- MT lookup
class MTClient:
    def __init__(self, url, check_ipset):
        self.url = url
        self.base = url.rsplit("/", 1)[0]  # .../api/v1/lookup -> .../api/v1
        self.check_ipset = check_ipset
        self._cache = {}  # ip -> dict(groups, in_ipset, has_hits)
        self._failed_until = {}

    def needs_lookup(self, ip):
        return (self._cache.get(ip) is None
                and time.monotonic() >= self._failed_until.get(ip, 0))

    def annotate(self, ips):
        """Batch-resolve unknown ips; results land in cache."""
        todo = [ip for ip in ips if self.needs_lookup(ip)]
        if not todo:
            return
        try:
            r = requests.post(self.url, json={"queries": todo, "check_ipset": self.check_ipset}, timeout=8)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise ValueError("invalid MT lookup response")
        except Exception:
            for ip in todo:
                self._cache[ip] = None
                self._failed_until[ip] = time.monotonic() + 5
            return
        seen = set()
        for item in data.get("results", []):
            q = item.get("query")
            seen.add(q)
            rule_hits = item.get("rule_hits") or []
            ipset_hits = item.get("ipset_hits") or []
            groups = sorted({h.get("group_name", "") for h in rule_hits if h.get("group_name")})
            in_ipset = None if not self.check_ipset else (len(ipset_hits) > 0)
            self._cache[q] = {
                "groups": ", ".join(groups),
                "in_ipset": in_ipset,
                "has_hits": bool(rule_hits) or in_ipset is True,
            }
        for ip in todo:
            self._cache.setdefault(ip, None)
            if self._cache[ip] is None:
                self._failed_until[ip] = time.monotonic() + 5

    def tag(self, ip):
        mt = self._cache.get(ip)
        if not mt:
            return "[MT:?]", False
        if mt["groups"]:
            return f"[MT:{mt['groups']}]", True
        if mt["in_ipset"]:
            return "[MT:ipset]", True
        return "[MT:--]", False

    def is_covered(self, ip):
        """True/False for known coverage, None when the lookup failed/is pending."""
        mt = self._cache.get(ip)
        return bool(mt["has_hits"]) if mt is not None else None

    # ---- write API (push step) ----
    def get_groups(self):
        r = requests.get(f"{self.base}/groups", timeout=8)
        return r.json().get("groups", []) or []

    def resolve_group(self, name_or_id):
        """Match by id first, then exact name. Raises KeyError with a hint on miss."""
        groups = self.get_groups()
        for g in groups:
            if str(g.get("id")) == str(name_or_id):
                return g.get("id"), g.get("name")
        for g in groups:
            if g.get("name") == name_or_id:
                return g.get("id"), g.get("name")
        names = ", ".join(f"{g.get('name')}({g.get('id')})" for g in groups)
        raise KeyError(f"group '{name_or_id}' not found. available: {names}")

    def get_rules(self, gid):
        r = requests.get(f"{self.base}/groups/{gid}/rules", timeout=8)
        r.raise_for_status()
        return r.json().get("rules", []) or []

    def add_subnet_rules(self, gid, existing, additions):
        """Append all additions with one replacement request and one MT sync/save."""
        new_rules = list(existing)
        for cidr, name in additions:
            rtype = "subnet6" if ":" in cidr else "subnet"
            new_rules.append({"name": name, "type": rtype, "rule": cidr, "enable": True})
        r = requests.put(f"{self.base}/groups/{gid}/rules?save=true",
                         json={"rules": new_rules}, timeout=30)
        r.raise_for_status()
        result = r.json().get("rules", []) or []
        if len(result) != len(new_rules):
            raise RuntimeError(f"batch rule update returned {len(result)}/{len(new_rules)} rules")
        return result


# ------------------------------------------------------------------- AWS ranges
class AWSRanges:
    """Official AWS ip-ranges.json — maps an IP to its real regional prefix.
    Cached locally with a TTL so we don't re-download every run."""
    URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

    def __init__(self, cache_path, ttl_days=7, ec2_only=False, regions=None, refresh=False):
        self.ec2_only = ec2_only
        self.regions = set(regions) if regions else None
        self._nets = []  # (ip_network, region, service)
        self.loaded = False
        self._load(cache_path, ttl_days, refresh)

    def _load(self, path, ttl_days, refresh):
        data = None
        fresh = (path and os.path.exists(path)
                 and (time.time() - os.path.getmtime(path) < ttl_days * 86400))
        if fresh and not refresh:
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = None
        if data is None:
            try:
                data = requests.get(self.URL, timeout=20).json()
                if path:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(data, f)
            except Exception:
                if path and os.path.exists(path):  # fall back to stale cache
                    try:
                        with open(path, encoding="utf-8") as f:
                            data = json.load(f)
                    except Exception:
                        data = {"prefixes": []}
                else:
                    data = {"prefixes": []}
        for p in data.get("prefixes", []):
            try:
                self._nets.append((ipaddress.ip_network(p["ip_prefix"]),
                                   p.get("region", ""), p.get("service", "")))
            except ValueError:
                pass
        self.loaded = bool(self._nets)

    def lookup(self, ip):
        """Most-specific covering prefix -> (cidr, region, service), or None."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best = None
        for net, region, service in self._nets:
            if a.version != net.version or a not in net:
                continue
            if self.ec2_only and service != "EC2":
                continue
            if self.regions and region not in self.regions:
                continue
            if best is None or net.prefixlen > best[0].prefixlen:
                best = (net, region, service)
        if not best:
            return None
        return str(best[0]), best[1], best[2]


# ------------------------------------------------------------------- geo / ASN
class GeoResolver:
    def __init__(self, token, enabled):
        self.token = token
        self.enabled = enabled
        self._cache = {}

    def info(self, ip):
        if not self.enabled:
            return {"summary": "", "country": "", "asn": "", "prefix": ""}
        if ip in self._cache:
            return self._cache[ip]
        out = {"summary": "", "country": "", "asn": "", "prefix": ""}
        parts = []
        asn = ""
        cc = ""
        # ipinfo: org / asn / country
        try:
            if self.token:
                u = f"https://api.ipinfo.io/lite/{ip}?token={self.token}"
            else:
                u = f"https://ipinfo.io/{ip}/json"
            d = requests.get(u, timeout=6).json()
            if d.get("org"): parts.append(str(d["org"]))
            a = d.get("asn"); asname = d.get("as_name")
            if a or asname:
                asn = str(a) if a else ""
                parts.append(" | ".join(str(x) for x in (a, asname) if x))
            cc = d.get("country_code") or d.get("country") or ""
            if cc: parts.append(cc)
        except Exception:
            pass
        # bgpkit: real announced prefix (better CIDR than /24 guess) + asn/cc fallback
        prefix = ""
        try:
            b = requests.get(f"https://api.bgpkit.com/v3/utils/ip?ip={ip}", timeout=6).json()
            asninfo = b.get("asn") or {}
            prefix = str(asninfo.get("prefix") or "")
            if not asn and asninfo.get("asn"):
                asn = f"AS{asninfo['asn']}"
            if not cc:
                cc = str(b.get("country") or "")
            if prefix:
                parts.append(f"CIDR {prefix}")
        except Exception:
            pass
        out = {"summary": " | ".join(parts), "country": cc, "asn": asn, "prefix": prefix}
        self._cache[ip] = out
        return out


# ------------------------------------------------------------------- reverse DNS
class HostResolver:
    def __init__(self, enabled):
        self.enabled = enabled
        self._cache = {}

    def name(self, ip):
        if not self.enabled:
            return ""
        if ip in self._cache:
            return self._cache[ip]
        host = ""
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            pass
        self._cache[ip] = host
        return host


# ------------------------------------------------------------------- ETW capture
class Capture:
    """Runs an ETW session in a background thread, pushes normalized events."""
    def __init__(self, out_queue, want_tcp, want_udp, swap_ports, debug, want_in=False, match_pid=None):
        self.q = out_queue
        self.debug = debug
        self.swap_ports = swap_ports
        self.match_pid = match_pid
        self.received = 0
        self.unsupported = 0
        self.max_lag = 0.0
        ids = [eid for eid, (proto, _, direction) in EVT.items()
               if ((proto == "TCP" and want_tcp) or (proto == "UDP" and want_udp))
               and (direction == "out" or want_in)]
        self._ids = set(ids)
        provider = ProviderInfo("Microsoft-Windows-Kernel-Network", GUID(KERNEL_NETWORK_GUID))
        # pywintrace defaults to 1 MB buffers and leaves FlushTimer at 0, so a
        # real-time session only delivers when a buffer fills up — with tiny
        # network events that is tens of seconds of apparent "lag". Small
        # buffers + a 1 s flush timer make delivery near-live.
        self.props = TraceProperties(ring_buf_size=64, min_buffers=16, max_buffers=64)
        self.props.get().contents.FlushTimer = 1
        self._etw = ETW(
            session_name=f"MagiTrickle-nettrace-{os.getpid()}",
            providers=[provider],
            event_id_filters=list(ids),
            # Stock TDH decoding performs metadata/property calls for every packet
            # of every process. Use the SDK's raw mode and the provider's fixed
            # version-0 network prefix; filter PID before copying/decoding addresses.
            event_callback=self._on_raw,
            callback_data_flag=RETURN_RAW_UNFORMATTED_DATA,
            properties=self.props,
        )
        self._debugged = False

    def _on_raw(self, event):
        _, pointer = event
        record = pointer.contents
        descriptor = record.EventHeader.EventDescriptor
        eid = descriptor.Id
        if eid not in self._ids:
            return
        self.received += 1
        proto, fam, direction = EVT[eid]
        length = 20 if fam == 4 else 44
        if descriptor.Version != 0 or record.UserDataLength < length or not record.UserData:
            self.unsupported += 1
            return
        pid = ctypes.c_uint32.from_address(record.UserData).value
        if self.match_pid and not self.match_pid(pid):
            return
        payload = ctypes.string_at(record.UserData, length)
        width = 4 if fam == 4 else 16
        addr_offset = 8 if direction == "out" else 8 + width
        port_offset = 8 + 2 * width + (0 if direction == "out" else 2)
        ip = socket.inet_ntop(socket.AF_INET if fam == 4 else socket.AF_INET6,
                              payload[addr_offset:addr_offset + width])
        port = struct.unpack_from("!H", payload, port_offset)[0]
        port = _norm_port(port, self.swap_ports)
        size = struct.unpack_from("<I", payload, 4)[0]
        # ProcessTrace converts timestamps to FILETIME unless RAW_TIMESTAMP is set.
        event_time = (record.EventHeader.TimeStamp - 116444736000000000) / 10000000
        now = time.time()
        if not 0 < event_time <= now + 60:
            self.unsupported += 1
            return
        self.max_lag = max(self.max_lag, now - event_time)
        stamp = datetime.fromtimestamp(event_time)
        if self.debug and not self._debugged:
            self._debugged = True
            print(f"[debug] raw id={eid} version={descriptor.Version} pid={pid} "
                  f"remote={ip}:{port} bytes={payload.hex()} lag={now-event_time:.3f}s", file=sys.stderr)
        self.q.put((proto, pid, ip, port, size, stamp))

    def _on_event(self, event):
        # pywintrace hands (event_id, {field: value})
        try:
            event_id, data = event
        except (TypeError, ValueError):
            return
        if event_id not in self._ids:
            return
        if self.debug and not self._debugged:
            self._debugged = True
            sys.stderr.write(f"[debug] event_id={event_id} fields={list(data.keys())}\n")
            sys.stderr.write(f"[debug] raw={data}\n")
            sys.stderr.flush()
        proto, fam, direction = EVT[event_id]
        pid = _first(data, "PID", "ProcessId", "EventHeader.ProcessId")
        if direction == "out":
            raddr = _first(data, "daddr", "DestAddr", "destination")
            rport = _first(data, "dport", "DestPort")
        else:  # datarecv/accept: the remote side is the source
            raddr = _first(data, "saddr", "SourceAddr", "source")
            rport = _first(data, "sport", "SourcePort")
        size = _first(data, "size", "Size", default=0)
        if pid is None or raddr is None:
            return
        ip = _norm_ip(raddr, fam)
        port = _norm_port(rport, self.swap_ports)
        if ip is None:
            return
        self.q.put((proto, int(pid), ip, port, int(size or 0)))

    def events_lost(self):
        try:
            return int(self._etw.query().EventsLost)
        except Exception:
            return None

    def start(self):
        self._etw.start()

    def stop(self):
        try:
            self._etw.stop()
            return True
        except Exception:
            return False


def _first(d, *keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _norm_ip(v, fam):
    # v may be dotted string, int, or bytes depending on TDH decoding
    if isinstance(v, str):
        v = v.strip()
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        try:  # hex string?
            return _norm_ip(int(v, 0), fam)
        except (ValueError, TypeError):
            return None
    if isinstance(v, int):
        try:
            if fam == 4:
                return socket.inet_ntop(socket.AF_INET, v.to_bytes(4, "little"))
            return socket.inet_ntop(socket.AF_INET6, v.to_bytes(16, "big"))
        except (OSError, OverflowError):
            return None
    if isinstance(v, (bytes, bytearray)):
        try:
            fam_c = socket.AF_INET if fam == 4 else socket.AF_INET6
            return socket.inet_ntop(fam_c, bytes(v))
        except OSError:
            return None
    return None


def _norm_port(v, swap):
    try:
        p = int(v)
    except (TypeError, ValueError):
        return 0
    if swap:
        p = socket.ntohs(p & 0xFFFF)
    return p


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_unspecified or a.is_reserved)


# ------------------------------------------------------------------- main loop
def _stop_capture(cap, timeout=6):
    """ETW ProcessTrace can lag after CloseTrace (real-time buffer flush) — join it
    off-thread with a deadline and hard-exit if it overruns, so Ctrl+C never hangs."""
    done = threading.Event()
    success = []

    def _worker():
        try:
            success.append(cap.stop() is not False)
        except Exception:
            success.append(False)
        done.set()

    threading.Thread(target=_worker, daemon=True).start()
    if not done.wait(timeout):
        sys.stderr.write(f"{C_GRAY}(ETW stop timed out — saving received events){C_RESET}\n")
        sys.stderr.flush()
        sys.stdout.flush()
        return False
    return success[0]


def run(args):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(f"{C_YELLOW}WARNING: not elevated — ETW kernel session needs Administrator. "
              f"Re-run from an elevated shell.{C_RESET}", file=sys.stderr)

    name_filters = [n.lower() for n in (args.name or [])]
    pid_filters = set(args.pid or [])
    procs = ProcResolver()
    mt = MTClient(args.mt_url, args.check_ipset) if args.mt_url else None
    geo = GeoResolver(args.ipinfo_token, not args.no_geo)

    def match(pid):
        if not name_filters and not pid_filters:
            return True
        if pid in pid_filters:
            return True
        nm = procs.name(pid)
        if nm and any(f in nm.lower() for f in name_filters):
            return True
        return False

    q = Queue()
    cap = Capture(q, args.tcp, args.udp, args.port_swap, args.debug_fields, args.recv, match)

    hostres = HostResolver(args.resolve_hostnames)

    tsv = None
    if args.tsv:
        append = args.append and os.path.exists(args.tsv) and os.path.getsize(args.tsv) > 0
        tsv = open(args.tsv, "a" if append else "w", encoding="utf-8")
        if not append:
            tsv.write("Timestamp\tProtocol\tProcess\tPID\tAddress\tPort\tMT_Groups\tMT_Ipset\tDetails\n")

    counts = defaultdict(int)          # key -> hit count
    seen = set()
    enricher = Enricher(geo, hostres, tsv, mt, workers=args.geo_workers, hold=args.geo_hold)
    mt_pool = ThreadPoolExecutor(max_workers=1) if mt else None
    mt_jobs = {}
    mt_queued = set()

    def process_batch(batch):
        for f in list(mt_jobs):
            if f.done():
                mt_queued.difference_update(mt_jobs.pop(f))
        new_ips = []
        rows = []
        for event in batch:
            proto, pid, ip, port, size, *timing = event
            stamp = timing[0] if timing else None
            if not is_public(ip) or not match(pid):
                continue
            if mt and mt.needs_lookup(ip) and ip not in mt_queued:
                new_ips.append(ip)
            key = (proto, pid, ip, port)
            counts[key] += 1
            if key in seen:
                every = args.repeat_every
                if every and (counts[key] == 2 or counts[key] % every == 0):
                    rows.append((proto, pid, ip, port, counts[key], False, stamp))
                continue
            seen.add(key)
            rows.append((proto, pid, ip, port, counts[key], True, stamp))

        # Router lookup must not block capture processing or output deadlines.
        if mt and new_ips:
            ips = list(dict.fromkeys(new_ips))
            mt_queued.update(ips)
            mt_jobs[mt_pool.submit(mt.annotate, ips)] = ips
        for proto, pid, ip, port, hits, is_new, stamp in rows:
            _emit(proto, pid, ip, port, hits, is_new, procs, mt, geo, hostres, tsv, enricher, stamp)
        enricher.flush()

    print(f"Watching: name={name_filters or '*'} pid={sorted(pid_filters) or '*'}  "
          f"proto={'TCP' if args.tcp else ''}{'/' if args.tcp and args.udp else ''}{'UDP' if args.udp else ''}")
    print(f"MagiTrickle: {args.mt_url}  (ipset={args.check_ipset})")
    print(f"Duration: {'until Ctrl+C' if args.duration == 0 else str(args.duration)+'s'}\n")

    try:
        cap.start()
    except PermissionError:
        print(f"{C_YELLOW}FATAL: access denied opening the ETW session. Run from an "
              f"elevated shell (right-click terminal -> Run as administrator).{C_RESET}",
              file=sys.stderr)
        sys.exit(1)
    deadline = None if args.duration == 0 else time.time() + args.duration
    try:
        while True:
            if deadline and time.time() >= deadline:
                break
            # drain a batch
            batch = []
            try:
                batch.append(q.get(timeout=0.2))
                while len(batch) < 500:
                    batch.append(q.get_nowait())
            except Empty:
                pass

            process_batch(batch)
    except KeyboardInterrupt:
        print(f"\n{C_GRAY}Ctrl+C — stopping...{C_RESET}")
    finally:
        # Stop the producer, then consume its final flush before summary/learn.
        lost = cap.events_lost()
        stopped = _stop_capture(cap)
        remaining = q.qsize()
        while remaining:
            batch = []
            try:
                while len(batch) < min(500, remaining):
                    batch.append(q.get_nowait())
            except Empty:
                pass
            if not batch:
                break
            remaining -= len(batch)
            process_batch(batch)
        if mt_pool:
            wait(mt_jobs, timeout=args.geo_wait)
            mt_pool.shutdown(wait=False, cancel_futures=True)
        enricher.drain(args.geo_wait)
        enricher.shutdown()
        if tsv:
            tsv.close()
        _summary(counts, mt, geo)
        if hasattr(cap, "received"):
            print(f"  ETW events: {cap.received}; unsupported: {cap.unsupported}; "
                  f"max delivery lag: {cap.max_lag:.3f}s")

        if args.learn or args.push_to_group:
            recs = build_records(counts, mt, geo)
            if args.learn:
                save_learn(args.learn, recs)
                print(f"\nlearn store updated: {args.learn} (+{len(recs)} ips this run)")
            if args.push_to_group:
                if mt is None:
                    print(f"{C_YELLOW}--push-to-group needs MagiTrickle URL{C_RESET}")
                else:
                    aws = make_aws(args)
                    subnet_map, labels = aggregate(recs, args.agg, args.min_count, args.promote16, aws)
                    push_subnets(mt, args.push_to_group, subnet_map, args.confirm, args.allow_wide, labels)

        if lost is None:
            print(f"{C_YELLOW}ETW loss statistics unavailable{C_RESET}")
        else:
            print(f"{C_YELLOW}ETW dropped {lost} events{C_RESET}")
        if not stopped:
            print(f"{C_YELLOW}Capture incomplete: ETW did not stop within the deadline{C_RESET}")
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(1)


_print_lock = threading.Lock()


def _color(country, mt, mt_hit):
    if country == "RU":
        return C_GRAY
    if mt and mt_hit:
        return C_GREEN
    if mt:
        return C_YELLOW
    return C_RESET


def _tsv_row(tsv, proto, pname, pid, ip, port, mt, detail, stamp=None):
    m = mt._cache.get(ip) if mt else None
    groups = (m or {}).get("groups", "")
    if not mt:
        ipset = ""
    elif not m:
        ipset = "unknown"
    elif m["in_ipset"] is None:
        ipset = "n/a"
    else:
        ipset = "yes" if m["in_ipset"] else "no"
    tsv.write(f"{stamp or datetime.now():%Y-%m-%d %H:%M:%S}\t{proto}\t{pname}\t{pid}\t{ip}\t{port}\t{groups}\t{ipset}\t{detail}\n")
    tsv.flush()


class Enricher:
    """ASN/country/PTR lookups are 1-3 blocking network round-trips per IP.

    Done inline before printing they stalled the whole capture for seconds per
    new endpoint. So the lookup runs off-thread and the line waits for it in an
    ordered buffer instead: output stays chronological and every endpoint still
    prints as ONE complete line. A lookup that overruns `hold` seconds stops
    holding the queue and its line goes out unenriched — one dead lookup must
    never freeze the live view. Repeat hits of a known IP never wait at all.
    """

    def __init__(self, geo, hostres, tsv, mt, workers=8, hold=5.0):
        self.geo = geo
        self.hostres = hostres
        self.tsv = tsv
        self.mt = mt
        self.hold = hold
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self._pending = set()
        self._claimed = set()
        self._queue = deque()
        self._lk = threading.Lock()

    @property
    def enabled(self):
        return self.geo.enabled or (self.hostres and self.hostres.enabled)

    def _claim(self, ip):
        """True if this ip still needs a lookup, and nobody else took it."""
        if not self.enabled:
            return False
        with self._lk:
            if ip in self._claimed or ip in self.geo._cache:
                return False
            self._claimed.add(ip)
            return True

    def add(self, entry):
        """Queue one output line. Enrichment (if needed) starts here."""
        entry["deadline"] = time.time() + self.hold
        with self._lk:
            self._queue.append(entry)
        if entry["ready"]:
            return
        f = self.pool.submit(self._work, entry)
        with self._lk:
            self._pending.add(f)
        f.add_done_callback(self._retire)

    def _retire(self, f):
        with self._lk:
            self._pending.discard(f)

    def _work(self, entry):
        ip = entry["ip"]
        try:
            meta = self.geo.info(ip)
            detail = meta["summary"]
            host = self.hostres.name(ip) if self.hostres else ""
            if host:
                detail = f"{host} | {detail}" if detail else host
            entry["detail"] = detail
            entry["country"] = meta.get("country", "")
        except Exception:
            pass
        finally:
            entry["ready"] = True

    def flush(self, force=False):
        """Print every line from the head of the queue that is ready or expired.
        Head-of-line only — a later line never overtakes an earlier one."""
        now = time.time()
        out = []
        with self._lk:
            while self._queue:
                e = self._queue[0]
                mt_ready = not self.mt or self.mt._cache.get(e["ip"]) is not None
                if not (force or (e["ready"] and mt_ready) or now >= e["deadline"]):
                    break
                out.append(self._queue.popleft())
        for e in out:
            self._print(e)

    def _print(self, e):
        if self.mt:
            e["mt_tag"], e["mt_hit"] = self.mt.tag(e["ip"])
        detail = e["detail"]
        tail = f" [x{e['hits']}]" if e["hits"] > 1 else ""
        line = f"[{e['ts']}] [{e['pname']}] {e['proto']} {e['ip']}:{e['port']} {e['mt_tag']}{tail}"
        if detail:
            line += f"  {detail}"
        color = C_GRAY if e["mt_tag"] == "[MT:?]" else _color(e["country"], self.mt, e["mt_hit"])
        with _print_lock:
            print(f"{color}{line}{C_RESET}")
        if self.tsv and e["is_new"]:
            _tsv_row(self.tsv, e["proto"], e["pname"], e["pid"], e["ip"], e["port"], self.mt, detail, e.get("observed_at"))

    def drain(self, timeout=15):
        """Wait for in-flight lookups, then print what is left — the summary and
        the learn store read the geo cache, so bailing early loses ASN/CIDR."""
        with self._lk:
            pend = list(self._pending)
        if pend:
            print(f"{C_GRAY}(waiting for {len(pend)} pending geo lookups, max {timeout}s){C_RESET}")
            deadline = time.time() + timeout
            for f in pend:
                left = deadline - time.time()
                if left <= 0:
                    break
                try:
                    f.result(timeout=left)
                except Exception:
                    pass
        self.flush(force=True)

    def shutdown(self):
        self.pool.shutdown(wait=False, cancel_futures=True)


def _emit(proto, pid, ip, port, hits, is_new, procs, mt, geo, hostres, tsv, enricher, observed_at=None):
    mt_tag, mt_hit = (mt.tag(ip) if mt else ("", False))
    meta = geo._cache.get(ip) or {}
    detail = meta.get("summary", "")
    host = hostres._cache.get(ip) if hostres else ""
    if host:
        detail = f"{host} | {detail}" if detail else host

    needs_lookup = is_new and enricher._claim(ip)
    enricher.add({
        "ts": (observed_at or datetime.now()).strftime("%H:%M:%S"),
        "observed_at": observed_at,
        "proto": proto, "pid": pid, "pname": procs.name(pid) or f"pid{pid}",
        "ip": ip, "port": port, "hits": hits, "is_new": is_new,
        "mt_tag": mt_tag, "mt_hit": mt_hit,
        "detail": detail, "country": meta.get("country", ""),
        "ready": not needs_lookup,
    })


def _summary(counts, mt, geo):
    if not counts:
        print("\nNo matching outbound traffic captured.")
        return
    print("\nSummary:")
    uniq = len(counts)
    print(f"  unique endpoints: {uniq}")
    if mt:
        missing = []
        unknown = []
        for (proto, pid, ip, port) in counts:
            if geo._cache.get(ip, {}).get("country") == "RU":
                continue
            tag, hit = mt.tag(ip)
            if tag == "[MT:?]":
                unknown.append(ip)
                continue
            if not hit:
                missing.append(ip)
        miss_u = sorted(set(missing))
        if miss_u:
            print(f"  {C_YELLOW}NOT in MagiTrickle ({len(miss_u)} ips):{C_RESET}")
            for ip in miss_u:
                print(f"    [--] {ip}")
        elif not unknown:
            print(f"  {C_GREEN}all non-RU endpoints covered by MagiTrickle.{C_RESET}")
        if unknown:
            print(f"  {C_GRAY}MT coverage unknown ({len(set(unknown))} ips):{C_RESET}")
            for ip in sorted(set(unknown)):
                print(f"    [?] {ip}")


# ------------------------------------------------------------------- learn / push
def build_records(counts, mt, geo):
    """Collapse per-(proto,pid,ip,port) counts into per-ip records with geo/ASN/BGP."""
    recs = {}
    for (proto, pid, ip, port), n in counts.items():
        e = recs.setdefault(ip, {"count": 0, "protos": [], "dports": []})
        e["count"] += n
        if proto not in e["protos"]:
            e["protos"].append(proto)
        if port and port not in e["dports"]:
            e["dports"].append(port)
        m = geo._cache.get(ip, {}) if geo else {}
        e["asn"] = m.get("asn", "")
        e["prefix"] = m.get("prefix", "")
        e["cc"] = m.get("country", "")
        e["covered"] = mt.is_covered(ip) if mt else False
    return recs


def load_learn(path):
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_learn(path, recs):
    """Merge this run's records into the accumulator file (counts add up)."""
    store = load_learn(path)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for ip, e in recs.items():
        old = store.get(ip)
        if old:
            old["count"] = old.get("count", 0) + e["count"]
            old["protos"] = sorted(set(old.get("protos", []) + e["protos"]))
            old["dports"] = sorted(set(old.get("dports", []) + e["dports"]))[:32]
            old["asn"] = e.get("asn") or old.get("asn", "")
            old["prefix"] = e.get("prefix") or old.get("prefix", "")
            old["cc"] = e.get("cc") or old.get("cc", "")
            old["covered"] = e.get("covered", False)
            old["last"] = now
        else:
            rec = dict(e)
            rec["first"] = rec["last"] = now
            store[ip] = rec
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    return store


def aggregate(records, mode="cidr", min_count=1, promote16_at=0, aws=None):
    """records: dict ip->{count,prefix,cc,covered}. Returns (subnet_map, labels):
    subnet->[ips] and subnet->rule-name (labels may be empty) for uncovered,
    non-RU, IPv4 candidates seen >= min_count times."""
    cands = []
    for ip, e in records.items():
        if (("covered" in e and e["covered"] is None) or e.get("covered")
                or e.get("count", 0) < min_count or e.get("cc") == "RU"):
            continue
        try:
            if ipaddress.ip_address(ip).version != 4:
                continue  # v1: IPv4 only
        except ValueError:
            continue
        cands.append((ip, e))

    out = defaultdict(list)
    labels = {}

    if mode == "aws":
        for ip, e in cands:
            m = aws.lookup(ip) if aws else None
            if m:
                pfx, region, svc = m
                out[pfx].append(ip)
                labels[pfx] = f"AWS {region}" + (f" {svc}" if svc and svc != "AMAZON" else "")
            else:  # non-AWS -> fall back to /24
                out[str(ipaddress.ip_network(ip + "/24", strict=False))].append(ip)
        return dict(out), labels

    if mode == "cidr":
        for ip, e in cands:
            pfx = e.get("prefix") or str(ipaddress.ip_network(ip + "/24", strict=False))
            try:
                net = ipaddress.ip_network(pfx, strict=False)
            except ValueError:
                net = ipaddress.ip_network(ip + "/24", strict=False)
            out[str(net)].append(ip)
        return dict(out), labels
    if mode == "32":
        for ip, _ in cands:
            out[f"{ip}/32"].append(ip)
        return dict(out), labels

    mask = 16 if mode == "16" else 24
    for ip, _ in cands:
        out[str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))].append(ip)
    if mask == 24 and promote16_at > 0:
        by16 = defaultdict(list)
        for n24 in out:
            net = ipaddress.ip_network(n24)
            by16[str(ipaddress.ip_network(f"{net.network_address}/16", strict=False))].append(n24)
        result, used = {}, set()
        for s16, members in by16.items():
            if len(members) >= promote16_at:
                collected = []
                for m in members:
                    collected += out[m]
                    used.add(m)
                result[s16] = collected
        for n24, ipl in out.items():
            if n24 not in used:
                result[n24] = ipl
        return result, labels
    return dict(out), labels


def push_subnets(mt, group, subnet_map, confirm, allow_wide=False, labels=None):
    labels = labels or {}
    if not subnet_map:
        print("nothing to add (no uncovered candidates).")
        return
    gid, gname = mt.resolve_group(group)
    current_rules = mt.get_rules(gid)
    existing = {rule.get("rule") for rule in current_rules}
    print(f"\nGroup: {gname} (id={gid})  existing rules: {len(current_rules)}")

    wide = [s for s in subnet_map if ipaddress.ip_network(s).prefixlen < 16]
    if wide and not allow_wide:
        print(f"  {C_YELLOW}refusing subnets wider than /16 without --allow-wide "
              f"(AWS regions are wide by design): {', '.join(wide)}{C_RESET}")
        subnet_map = {s: v for s, v in subnet_map.items() if s not in wide}

    to_add = [s for s in sorted(subnet_map) if s not in existing]
    skipped = len(subnet_map) - len(to_add)
    if not to_add:
        print("  nothing to add (all subnets already present).")
        return
    print(f"  {len(to_add)} new subnet(s){'' if confirm else ' (dry-run)'}:")
    for s in to_add:
        lbl = labels.get(s)
        print(f"    {'+ ' if confirm else '  '}{s:20} ({len(subnet_map[s])} ip){'  ' + lbl if lbl else ''}")
    if skipped:
        print(f"  ({skipped} already present, skipped)")
    if not confirm:
        print(f"\n  {C_YELLOW}dry-run — add --confirm to actually push.{C_RESET}")
        return
    additions = [(s, labels.get(s) or f"nettrace {s}") for s in to_add]
    try:
        mt.add_subnet_rules(gid, current_rules, additions)
    except Exception as ex:
        print(f"    {C_YELLOW}FAILED batch update: {ex}{C_RESET}")
        return
    print(f"\n  {C_GREEN}added {len(to_add)}/{len(to_add)} subnets to '{gname}' "
          f"with one batch request. ipset synced.{C_RESET}")


def _aws_cache_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "aws-ip-ranges.cache.json")


def make_aws(args):
    """Build an AWSRanges instance if --agg aws, else None."""
    if args.agg != "aws":
        return None
    regions = [r.strip() for r in args.aws_regions.split(",")] if args.aws_regions else None
    aws = AWSRanges(_aws_cache_path(), ec2_only=args.aws_ec2_only,
                    regions=regions, refresh=args.aws_refresh)
    if not aws.loaded:
        print(f"{C_YELLOW}AWS ranges unavailable (download failed, no cache) — "
              f"'aws' mode falls back to /24.{C_RESET}")
    return aws


def do_import(args):
    """Push mode: read a learn store, refresh coverage, aggregate, push. No capture."""
    if not args.mt_url:
        print("FATAL: --import needs MagiTrickle URL", file=sys.stderr)
        return
    data = load_learn(args.import_file)
    if not data:
        print(f"empty/unreadable learn store: {args.import_file}", file=sys.stderr)
        return
    mt = MTClient(args.mt_url, args.check_ipset)
    ips = [ip for ip in data if is_public(ip)]
    for i in range(0, len(ips), 100):
        mt.annotate(ips[i:i + 100])
    for ip in data:
        data[ip]["covered"] = mt.is_covered(ip)
    aws = make_aws(args)
    subnet_map, labels = aggregate(data, args.agg, args.min_count, args.promote16, aws)
    if not args.push_to_group:
        print(f"Aggregated {sum(len(v) for v in subnet_map.values())} uncovered ip -> "
              f"{len(subnet_map)} subnet(s) (mode={args.agg}). No --push-to-group given:")
        for s in sorted(subnet_map):
            lbl = labels.get(s)
            print(f"  {s:20} ({len(subnet_map[s])} ip){'  ' + lbl if lbl else ''}")
        return
    push_subnets(mt, args.push_to_group, subnet_map, args.confirm, args.allow_wide, labels)


def _router_env(key, default=None):
    """Router address is never stored in the repo: env var or .router.env at the
    repo root (see .router.env.example; the file itself is gitignored)."""
    val = os.environ.get(key)
    if val:
        return val
    cfg = pathlib.Path(__file__).resolve().parents[2] / ".router.env"
    if cfg.exists():
        for line in cfg.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() == key:
                return v.strip().strip('"').strip("'")
    return default


def _default_mt_url():
    ip = _router_env("ROUTER_IP")
    return f"http://{ip}:8080/api/v1/lookup" if ip else ""


def build_parser():
    p = argparse.ArgumentParser(description="Per-process TCP+UDP network diagnostic (ETW) with MagiTrickle annotation.")
    p.add_argument("-n", "--name", action="append", help="process name substring (repeatable)")
    p.add_argument("--pid", action="append", type=int, help="filter by PID (repeatable)")
    p.add_argument("--for", "--duration", dest="duration", type=int, default=0, help="seconds (0=until Ctrl+C)")
    p.add_argument("--mt-url", default=_default_mt_url(), help="MagiTrickle lookup endpoint ('' to disable; default from ROUTER_IP / .router.env)")
    p.add_argument("--check-ipset", dest="check_ipset", action="store_true", default=True, help="query live ipset membership (default on)")
    p.add_argument("--no-check-ipset", dest="check_ipset", action="store_false")
    p.add_argument("--no-geo", action="store_true", help="disable ASN/country lookup")
    p.add_argument("--geo-workers", type=int, default=8, help="parallel ASN/PTR lookup threads (default 8)")
    p.add_argument("--geo-hold", type=float, default=5.0, help="max seconds a line waits for its ASN/PTR lookup before printing unenriched (default 5)")
    p.add_argument("--geo-wait", type=int, default=15, help="seconds to wait on exit for pending ASN/PTR lookups (default 15)")
    # Токен только из окружения: захардкоженный ключ утекает вместе с репозиторием
    # и его квоту жгут все, кто склонировал. Без токена скрипт работает по
    # анонимному ipinfo.io (лимит ниже, ASN и страна те же).
    p.add_argument("--ipinfo-token", default=os.environ.get("IPINFO_TOKEN", ""),
                   help="ipinfo.io API token (default: $IPINFO_TOKEN; empty = anonymous endpoint)")
    p.add_argument("--tcp", dest="tcp", action="store_true", default=True)
    p.add_argument("--no-tcp", dest="tcp", action="store_false")
    p.add_argument("--udp", dest="udp", action="store_true", default=True)
    p.add_argument("--no-udp", dest="udp", action="store_false")
    p.add_argument("--recv", action="store_true", help="also capture inbound events (datarecv/accept) — reveals endpoints that never receive a send from us")
    p.add_argument("--repeat-every", type=int, default=25, metavar="N",
                   help="reprint a repeating endpoint every N hits (1=every hit, 0=never; default 25)")
    p.add_argument("--tsv", help="also write TSV to this path")
    p.add_argument("--append", action="store_true", help="append to existing --tsv instead of overwriting")
    p.add_argument("--resolve-hostnames", action="store_true", help="reverse-DNS each destination IP (PTR)")
    p.add_argument("--port-swap", action="store_true",
                   help="ntohs() ETW ports — only if ports look byte-swapped (443 shown as 47873)")
    p.add_argument("--no-port-swap", action="store_true", help=argparse.SUPPRESS)  # kept: was the old default-off switch
    p.add_argument("--debug-fields", action="store_true", help="print raw ETW field names of first event and exit-safe")
    # --- learn / push ---
    g = p.add_argument_group("learn / push to MagiTrickle")
    g.add_argument("--learn", metavar="FILE", help="accumulate captured endpoints (with ASN + BGP-CIDR) into a JSON store for later push")
    g.add_argument("--import", dest="import_file", metavar="FILE", help="PUSH MODE: read a learn store and add uncovered subnets to MT (no capture)")
    g.add_argument("--push-to-group", metavar="GROUP", help="add uncovered subnets to this MT group (name or id); with capture = one-shot, with --import = from file")
    g.add_argument("--confirm", action="store_true", help="actually push (default is dry-run)")
    g.add_argument("--agg", choices=["cidr", "aws", "24", "16", "32"], default="cidr", help="aggregation: cidr=BGP prefix (default), aws=official AWS regional prefix, or /24 /16 /32")
    g.add_argument("--min-count", type=int, default=1, help="ignore endpoints seen fewer than N times")
    g.add_argument("--promote16", type=int, default=0, metavar="N", help="with --agg 24: collapse a /16 when >=N distinct /24 seen")
    g.add_argument("--allow-wide", action="store_true", help="permit subnets wider than /16 (needed for --agg aws/cidr)")
    g.add_argument("--aws-ec2-only", action="store_true", help="--agg aws: only EC2-service prefixes (skip S3/CloudFront ranges)")
    g.add_argument("--aws-regions", metavar="R1,R2", help="--agg aws: restrict to these AWS regions (e.g. eu-central-1,us-east-1)")
    g.add_argument("--aws-refresh", action="store_true", help="--agg aws: force re-download of the AWS ip-ranges cache")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if not args.mt_url:
        args.mt_url = None
    if args.import_file:
        do_import(args)
    else:
        run(args)
