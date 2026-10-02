# nettrace

Per-process network diagnostic for verifying MagiTrickle routing — captures
**all outbound connections of a process, TCP _and_ UDP**, and annotates each
destination against MagiTrickle (`/api/v1/lookup`) plus ASN/country.

## Why not the PowerShell script

`network_watch.ps1` reads socket tables (`Get-NetTCPConnection` /
`Get-NetUDPEndpoint`). That works for TCP, but **UDP has no connection state** —
the endpoint table exposes only the *local* socket, never the remote address.
So the old script showed UDP as `local endpoint only` and was blind to where UDP
actually went (games, QUIC, etc.).

`nettrace` instead subscribes to the **ETW `Microsoft-Windows-Kernel-Network`
provider**, which emits a per-packet event carrying **PID + destination IP:port**
for both TCP and UDP. This is the only Windows source that ties a UDP datagram to
both its process and its destination.

## Requirements

- Windows 10 1809+ / 11
- Python 3.9+
- **Administrator** — ETW kernel sessions require elevation. Run from an elevated
  shell.

```powershell
pip install -r requirements.txt
```

## Usage

```powershell
# watch Rocket League, TCP+UDP, until Ctrl+C, with MT + ASN annotation
python nettrace.py -n RocketLeague

# multiple processes, 60 seconds, also write TSV
python nettrace.py -n chrome -n RocketLeague --for 60 --tsv out.tsv

# by PID, UDP only
python nettrace.py --pid 12345 --no-tcp

# first elevated run — dump raw ETW field names (to validate field mapping)
python nettrace.py -n RocketLeague --debug-fields
```

### One coordinated ETW + router DNS session

`--dns-capture` starts MagiTrickle's DNS capture immediately after ETW starts and
stops it in the same cleanup path on timeout, Ctrl+C, or a startup error. It
refuses to overwrite a DNS capture that is already active. The client LAN address
is detected from the Windows route to MagiTrickle; override it with `--client-ip`.

```powershell
python nettrace.py -n RocketLeague --for 600 --recv `
  --tsv rl-session.tsv --learn rlgame.json --dns-capture
```

The final domain list is written to `rl-session.dns.json`. Use `--dns-out FILE`
when no TSV is needed or a different path is desired. DNS capture records queried
names and counts; the current MT API does not retain DNS answers or per-query
timestamps, so this proves which domains were queried during the same window but
cannot by itself map every domain to a captured destination IP.

### Output

```
[02:41:59] [RocketLeague] UDP 18.156.229.255:8097 [MT:--]        AS16509 | Amazon | DE
[02:41:59] [RocketLeague] TCP 104.18.2.64:443     [MT:CF] [x1]   AS13335 | Cloudflare | US
```

Color = MagiTrickle intent (not actual path — see limitation):
- **green** — destination matches an MT rule / is in an ipset → *should* be tunneled
- **yellow** — not covered by MT → will go DIRECT
- **gray** — RU (excluded from tunneling by convention)

`[MT:<group>]` = matched rule group · `[MT:ipset]` = in live ipset only ·
`[MT:--]` = not in MagiTrickle · `[MT:?]` = lookup pending or failed (gray).
Failed lookups can be retried after 5 seconds; unknown coverage is excluded from
push candidates and written as `unknown` in the TSV ipset column.

## Key flags

| flag | meaning |
|------|---------|
| `-n NAME` | process-name substring (repeatable) |
| `--pid N` | filter by PID (repeatable) |
| `--for N` | run N seconds (0 = until Ctrl+C) |
| `--mt-url URL` | MagiTrickle lookup endpoint (default from `ROUTER_IP` / `.router.env`; `''` disables) |
| `--no-check-ipset` | rule-match only, skip live ipset query |
| `--no-udp` / `--no-tcp` | restrict protocol |
| `--no-geo` | skip ASN/country lookup |
| `--ipinfo-token TOKEN` | ipinfo.io token; defaults to `$IPINFO_TOKEN`, empty = anonymous endpoint |
| `--dns-capture` | start and stop MT DNS capture with this ETW session |
| `--client-ip IP` | LAN client filter for DNS capture (default: auto-detect) |
| `--dns-out FILE` | final DNS JSON (default: TSV name with `.dns.json`) |
| `--tsv PATH` | also write TSV log |
| `--append` | append to existing `--tsv` instead of overwriting |
| `--resolve-hostnames` | reverse-DNS (PTR) each destination IP |
| `--port-swap` | `ntohs()` ports — only if they look byte-swapped (443 shown as 47873) |
| `--repeat-every N` | reprint a repeating endpoint every N hits (1=every hit, 0=never; default 25) |
| `--debug-fields` | print raw ETW field names of the first event |

## Learn & push to MagiTrickle

Instead of eyeballing the miss-list and adding rules by hand, `nettrace` can collect
uncovered destinations (with **real BGP-announced CIDR** + ASN, not a `/24` guess) and
push them into an MT group. Two workflows:

### Two-step (recommended): learn, then push

```powershell
# 1) play a few sessions — accumulate candidates (counts add up across runs)
python nettrace.py -n RocketLeague --learn game.json
python nettrace.py -n RocketLeague --learn game.json   # again next match

# 2) review the plan (dry-run — nothing is written)
python nettrace.py --import game.json --push-to-group RL

# 3) actually add
python nettrace.py --import game.json --push-to-group RL --confirm
```

`--import` is **push mode**: no capture, just read the store, refresh coverage against
live MT, aggregate uncovered IPs into subnets, and add the ones not already present.

### One-shot (capture + push in a single run)

```powershell
python nettrace.py -n RocketLeague --for 120 --push-to-group RL --confirm
```

### Aggregation & safety

| flag | meaning |
|------|---------|
| `--learn FILE` | accumulate captured endpoints (ASN + BGP-CIDR) into a JSON store |
| `--import FILE` | push mode: add uncovered subnets from a store to MT (no capture) |
| `--push-to-group G` | target MT group (name or id) |
| `--confirm` | actually push (default is **dry-run**) |
| `--agg cidr\|aws\|24\|16\|32` | `cidr` = BGP prefix (default), `aws` = official AWS regional prefix, or fixed mask |
| `--min-count N` | ignore endpoints seen fewer than N times (drop noise) |
| `--promote16 N` | with `--agg 24`: collapse a /16 when ≥N distinct /24 seen |
| `--allow-wide` | permit subnets wider than /16 (needed for `aws`/`cidr`) |
| `--aws-ec2-only` | `--agg aws`: only EC2 prefixes (skip S3/CloudFront) |
| `--aws-regions R1,R2` | `--agg aws`: restrict to these regions |
| `--aws-refresh` | `--agg aws`: force re-download of the cached ip-ranges |

### Aggregation modes

- **`cidr`** (default) — the IP's real BGP-announced prefix (via bgpkit). Accurate to
  how the owner routes it, but can be wide (`/14` for AWS).
- **`aws`** — looks the IP up in AWS's official `ip-ranges.json` and uses the **regional
  prefix**, naming the rule after the region (`AWS eu-central-1`). The file is cached
  locally (`aws-ip-ranges.cache.json`, 7-day TTL). Best when you want to tunnel whole
  AWS game regions reliably — pair with `--allow-wide` (regions are large by design) and
  optionally `--aws-ec2-only` / `--aws-regions`. Non-AWS IPs fall back to `/24`.
- **`24` / `16` / `32`** — fixed mask. `--agg 24 --promote16 2` is the narrow-but-adaptive
  middle ground (see below).

Only **uncovered** (not already in MT), **non-RU**, IPv4 candidates are pushed; existing
rules are deduped; subnets wider than `/16` are refused unless `--allow-wide`. This
replaces `mt_add_missing.ps1`.

Confirmed pushes replace the group's rule list once through the batch `PUT /rules`
API, preserving existing rule IDs. MT rebuilds ipsets and saves configuration once,
regardless of how many new subnets are added.

This fully replaces `network_watch.ps1` + `mt_add_missing.ps1` (TCP-only, UDP-blind).

## Troubleshooting: "it lags" / "it captures nothing"

Four independent causes were found and fixed on 2026-08-31 while chasing an AnyDesk
capture that looked frozen. If output ever looks wrong again, check these in order.

### The capture itself is almost never the problem

`etw_probe.py` settles that in one elevated run. It opens three Kernel-Network
sessions — old event ids with stock pywintrace buffers, the extended id list, and
the extended list with nettrace's own buffers — filters nothing by process, and
just counts what arrives:

```
python etw_probe.py 15
```

Each phase runs as its own child process, because `ProcessTrace` can block for a
long time inside `stop()`; numbers are printed *before* the stop and the child then
hard-exits. It also prints a per-PID table with resolved process names, whether the
name you are filtering on was seen at all, and `EventsLost`. Set `PROBE_MATCH` to
look for something other than AnyDesk.

### Delivery lag: ETW buffers

pywintrace allocates 1 MB buffers and leaves `FlushTimer` at 0, so a real-time
session only hands events over once a buffer fills. Kernel-Network events are tiny,
so that is tens of seconds of apparent freeze. nettrace now uses 64 KB buffers with
`FlushTimer = 1`.

### Delivery lag and losses: decoder throughput

The stock pywintrace decoder calls TDH to decode every selected packet across
the machine before nettrace can apply a process filter. Under load this can use
a full CPU core, fall minutes behind, and lose ETW events. Increasing buffers
alone does not fix a consumer that cannot keep up.

nettrace uses pywintrace's `RETURN_RAW_UNFORMATTED_DATA` mode, filters on the
payload PID, and reads the fixed version-0 Kernel-Network prefix directly.
Addresses and ports follow the documented [IPv4 network event layout](https://learn.microsoft.com/en-us/windows/win32/etw/udpip-typegroup1)
and [IPv6 layout](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-sendipv6).
Unsupported versions/short payloads are counted explicitly. Summary includes
total events, unsupported payloads, delivery lag and ETW losses.

Console and TSV timestamps now use the ETW event time, not the print time. Each
run uses its own session name, and name filtering follows game restarts without
a fixed `--pid`. The ETW flush interval can still add around a second of latency.

### Delivery lag: enrichment

ASN/country/PTR are 1-3 blocking network round-trips per new IP. Inline they stalled
the print loop for seconds per endpoint and made the `[HH:MM:SS]` stamp the time of
*printing* rather than of the event. They now run off-thread; a line waits for its
lookup in an ordered buffer for at most `--geo-hold` seconds (default 5) and then
prints unenriched, so one dead lookup cannot freeze the live view. The result still
lands in the cache, so `--learn` and the summary keep ASN and CIDR either way.

MT lookup also runs off-thread. The same `--geo-hold` deadline bounds how long
output waits for both MT and geo; an unfinished MT lookup prints `[MT:?]`.
Use `--no-geo --geo-hold 0` for immediate output, with coverage shown once available
on subsequent lines. ETW delivery and output scheduling still add latency.

### "It only caught it once"

Repeat hits of the same `(protocol, PID, IP, port)` are suppressed — printed on the
2nd hit, then every Nth. On a long-lived connection that reads as "it stopped
tracking". Use `--repeat-every 1` to see every hit, `0` to silence repeats entirely.
Counts are event counts, not connection counts. Local ports are not part of the
key, and TSV records only the first occurrence of each endpoint.

### "It caught nothing at all"

An established, idle connection generates almost no `datasent` events — that is what
the event *means*. Two fixes:

- `connect`/`accept` events are captured now, so you see the moment a connection is
  established rather than the first payload. Start the capture *before* reconnecting.
- `--recv` adds inbound events. On an idle keepalive channel there is usually more
  inbound than outbound, so without it you see half the picture.

Filtering by `--pid` sidesteps process-name matching entirely. Beware that a service
gets a new PID whenever it restarts:

```powershell
$a = @(); foreach ($i in (Get-Process AnyDesk).Id) { $a += "--pid"; $a += "$i" }
python nettrace.py @a --recv --repeat-every 1 --for 20
```

Name lookup failures are retried after 0.5 seconds; successful names expire after
2 seconds to handle PID reuse. At shutdown nettrace stops ETW and consumes its
final queue before writing the summary and learn store. Loss statistics come from
the running ETW session; an unavailable statistic is reported explicitly.

### Ports looked byte-swapped

The port arrives from ETW already in host order. nettrace used to apply another
`ntohs()` on top by default, which printed port 443 as 47873 (`ntohs(443) = 47873`).
The swap is off by default now; `--port-swap` restores it if some build needs it.
Cross-check a live connection against `Get-NetTCPConnection -OwningProcess <pid>`
before believing a port.

## Limitations (v1)

- **Shows intent, not actual path.** MT annotation says whether a destination
  *should* be tunneled (rule/ipset). It does **not** prove the packet actually went
  through the tunnel — that only the router knows (conntrack `sport=5001` /
  mihomo `/connections`). Router path cross-check (TUNNEL vs DIRECT) and a
  test-case mode are planned — see beads `mt-wf4`.
- **ETW field names / byte order** for the Kernel-Network provider are validated
  at runtime; if IPs or ports look wrong on your build, run `--debug-fields` and
  adjust, and try `--port-swap`.
