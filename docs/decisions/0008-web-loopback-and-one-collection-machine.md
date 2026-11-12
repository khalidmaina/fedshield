# 0008. Web workload uses 127.0.0.1; all sessions are collected on one machine

- Status: accepted (testbed change after the collector freeze)
- Date: 2026-11-12
- Deciders: Hasib, Khalid

## Context

Khalid's first 120-second collection (Ubuntu 22.04, kernel 6.8) and the verification runs (Ubuntu 24.04) agreed on
everything except two things:

| Host | Khalid: execs / connections per window | Verification: execs / connections |
|---|---|---|
| fs-web-1 | 20 / 30 | 16 / 16 |
| fs-web-2 | 40 / 60 | 40 / 40 |
| fs-web-3 | 54 / 81 | 54 / 54 |
| fs-build-3 | 197 execs | 219 execs |

Each web loop runs two `curl`s: one to `localhost`, one to a peer. curl 8.5 resolves `localhost` itself to both
`127.0.0.1` and `::1` and tries both. Where the containers have IPv6 on their loopback (Khalid's machine), the `::1`
attempt is refused because the web server listens on IPv4 only, so the local request costs 2 connections:
3 connections per 2 curls, exactly the 1.5 ratio on all three web hosts. Where IPv6 is off (verification machine,
`/proc/net/if_inet6` empty), curl tries only `127.0.0.1`. The build difference comes from compile speed: the
workloads are paced by time, so a faster machine does more work per window.

## Decision

1. `testbed/host/roles/web.sh` requests `http://127.0.0.1:8080/` instead of `http://localhost:8080/`, so the web
   workload makes one connection per request whatever the machine's IPv6 setup.
2. **All collection sessions come from one machine** (recorded in `docs/data_protocol.md`). Absolute counts depend on
   CPU speed and network setup; mixing machines would add differences that are not about host behaviour.

## Consequences

- The testbed image must be rebuilt once (`make testbed-up` rebuilds it).
- No sessions had been collected yet, so no data is affected.
- After the change, web hosts should show `conn_count` equal to `exec_count` (each curl one connection) on any
  machine; check it in the pilot session.
