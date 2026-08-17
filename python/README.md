# Python bridge — `PostInterface.py`

**The one maintained copy is `python/RNS/Interfaces/PostInterface.py`.**

Install it by copying that file into your RNS installation's
`RNS/Interfaces/` directory (or the `interfaces/` directory of an rnsd config
dir), then reference it from the rnsd config:

```ini
[[PostInterface Bridge]]
  type = PostInterface
  enabled = yes
  node_url = "https://<your-node>/reticulum"
  wake_url = "http://<your-host>/v1/wake"
  wake_listen_host = 0.0.0.0
  wake_listen_port = 4371
```

## Why there is only one copy now

Until 2026-08-17 this file existed six times across the workspace in four
different versions — under `docker/bridge/interfaces/`, `python/bridge-conf/
interfaces/`, `python/RNS/Interfaces/`, dropped untracked into the
`Reticulum-master` upstream mirror, in `e2e-local/rnsd/interfaces/`, and
installed into `.venv`. Two of them dated from a commit named "BEFORE: snapshot
local state before pulling retichat.com server code" and were never touched
again.

Verified before removing them: the maintained copy is a strict superset — no
method and no config key existed in any duplicate that is missing here. The
duplicates' apparent extras were older, narrower forms of the same work (a
PROOF-only hop fix that this file now applies to every link packet with
`hops == 0`, and the 60-second wake fallback that commit f87b329 deliberately
removed in favour of an event-driven exchange).

`docker/docker-compose.yml` never used its neighbouring copy at all — it mounts
the interface directory from the host, so `docker/bridge/interfaces/` was pure
snapshot debris.

## Note on what actually runs in production

The live bridge on the OPNsense gateway is **not this file**. It is the Rust
implementation, `Reticulum-rust/src/interfaces/post_interface.rs`, built there
by `.tmp-gateway/build_rnsd.sh` (which needs `--features post-interface`,
because `--no-default-features` drops it). This Python file is the reference
and the path for a standard Python `rnsd`. The two are intentionally
behaviour-compatible: the Rust hop-fix comment cites this file's line numbers,
and f87b329's message is "Matches Rust post_interface.rs behaviour". Change one,
change the other.
