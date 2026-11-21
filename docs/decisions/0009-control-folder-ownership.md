# 0009. Control folders belong to the user; the session runner checks them first

- Status: accepted (testbed change after the collector freeze)
- Date: 2026-11-12
- Deciders: Hasib, Khalid

## Context

The first attack of Khalid's pilot session failed: `Cannot write to testbed/control/fs-db-3`. `make testbed-up`
created `testbed/control/` as the user, but each host's agent (root inside its container) created its own subfolder
`testbed/control/<host>/`, which therefore belonged to root on the host machine. The session runner, running as the
user, could not write attack requests into it. Every check so far had run as root, which can write anywhere, so the
problem never showed. Reproduced as a non-root user: the control folder belonged to the user, `fs-db-3/` to root, and
the request failed with the same error.

## Decision

- The agent gives its folder the owner of the control folder right after creating it
  (`chown --reference=/control /control/<host>`), once at start-up. This also repairs folders created as root
  earlier, at the next container start.
- `make testbed-up` creates all 12 host folders as the user before starting the containers.
- `run_session.py` refuses to start if any host folder is missing or not writable, and says how to fix it
  (`sudo chown -R $USER:$USER testbed/control`); `request_attack` gives the same fix in its error.

## Evidence (2026-11-12, non-root user)

With the old agent: control folder owned by the user, `fs-db-3/` by root, request refused. After rebuilding with the
fix and restarting the containers (root-owned folders left in place): all 12 folders owned by the user, `scan` on
`fs-db-3` started and finished with exit code 0, preflight reports no problems. Making one folder root-owned again
makes the preflight name it and the fix.

## Consequences

- The `chown` runs once when a host starts, before any session; the idle harness still adds no events (T5).
- The image must be rebuilt (`make testbed-up` rebuilds it).
