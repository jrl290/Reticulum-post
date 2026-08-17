# Reticulum Post

> **⚠️ Work in Progress** — This project is under active development. APIs, protocols, and the on-disk storage format may change.  
> **🤖 AI-Assisted Development** — A significant portion of this codebase was generated and refined with AI coding assistance (GitHub Copilot / Claude). All generated code has been reviewed and tested by a human developer.

HTTP exchange bridge for the [Reticulum Network Stack](https://reticulum.network/). Provides three components that work together to connect browser clients and Python nodes over standard HTTP — no raw sockets, no WebSockets, no special server modules required.

## Architecture

```
┌──────────────────┐     HTTP POST      ┌──────────────────────────┐
│  Retichat Web    │ ◄────exchange──────►│  Reticulum-post (PHP)    │
│  (Browser JS)    │                    │  ┌────────────────────┐  │
│                  │                    │  │  HTTP Exchange API │  │
│  Pull-poll       │                    │  │  POST /v1/register │  │
│  client          │                    │  │  POST /v1/exchange │  │
└──────────────────┘                    │  └────────┬───────────┘  │
                                        │           │              │
┌──────────────────┐     HTTP POST      │  ┌────────┴───────────┐  │
│  Python RNS Node │ ◄────exchange──────►│  │  Python Bridge     │  │
│  (rnsd)          │                    │  │  (PostInterface)   │  │
│                  │                    │  └────────┬───────────┘  │
│  Push-push       │                    └───────────┼──────────────┘
│  peer            │                                │
└──────────────────┘                        ┌───────┴───────┐
                                            │  Reticulum    │
                                            │  Backbone     │
                                            └───────────────┘
```

## Project Components

### Server: PHP (`php/`)
The HTTP exchange router daemon. Accepts POST requests from both browser clients and Python nodes, routes Reticulum packets between registered interfaces, and maintains path state in SQLite. Designed for shared hosting — runs on any PHP 8.1+ host with `ext-sqlite3` and write access to a `var/` directory.

- **Entry point**: `php/src/index.php`
- **API**: `POST /v1/interfaces/register`, `POST /v1/interfaces/exchange`
- **Storage**: SQLite (`var/reticulum.db`) — interface registry, packet queues, path cache

### Client: Browser JS
The browser-side RNS protocol stack used by [Retichat Web](https://github.com/jrl290/Retichat-js). Pure ES modules loaded via import maps — no npm, no build step. Implements identities, destinations, links, announces, LXMF messaging, and the HTTP exchange transport client. Lives in `js/`.

### Bridge: Python (`python/`)
A `PostInterface` extension for Python RNS nodes. Drop into `~/.reticulum/interfaces/` to connect a standard Python `rnsd` to a Reticulum-post router over HTTP. The Python node registers as an interface and exchanges packets via the same HTTP API as browser clients.

## Transport Mechanisms

### Pull-Poll (One-Way Initiation)

The pull-poll model is designed for **browser clients and firewalled nodes** that cannot accept inbound connections. The client initiates every exchange: it POSTs queued outbound packets and receives any queued inbound packets in the HTTP response.

```
Client                              PHP Router
  │                                     │
  │── POST /register ──────────────────►│  one-time setup
  │◄─ { interface_id, session_token } ─│
  │                                     │
  │── POST /exchange { pkts: [...] } ──►│  upload outbound
  │◄─ { pkts: [...] } ─────────────────│  receive inbound
  │                                     │
  │        ... poll interval ...        │
  │                                     │
  │── POST /exchange { pkts: [...] } ──►│
  │◄─ { pkts: [...] } ─────────────────│
```

- Single HTTP request per exchange cycle
- Client controls timing via poll interval
- No persistent connections, no server push
- Works through NAT, firewalls, proxies, CDNs
- Poll interval is adaptive — speeds up to ~1s when messages are flowing, backs off to ~5s when idle

### Push-Push (Two-Way Initiation)

When two nodes have **both** registered interfaces with the router **and** exchanged announces establishing a mutual path, either node can push packets at any time. This is the native Reticulum transport model adapted to HTTP.

```
Node A                               PHP Router                              Node B
  │                                     │                                      │
  │── POST /exchange {pkts:[announce]}─►│                                      │
  │                                     │── POST /exchange {pkts:[announce]}──►│
  │                                     │◄─ {pkts:[]} ────────────────────────│
  │◄─ {pkts:[]} ───────────────────────│                                      │
  │                                     │                                      │
  │         ╔════ Path Established ════╗│                                      │
  │         ║   (bidirectional)     ║   │                                      │
  │                                     │                                      │
  │── POST /exchange {pkts:[LXMF]} ────►│  A pushes to B                       │
  │                                     │◄─ {pkts:[LXMF]} ────────────────────│
  │                                     │── POST /exchange {pkts:[LXMF]} ─────►│  B pushes to A
  │◄─ {pkts:[LXMF]} ───────────────────│                                      │
```

- Both sides independently POST to the exchange endpoint on their own schedules
- The router maintains per-interface queues and delivers packets on the next exchange
- Enables real-time(-ish) bidirectional chat without WebSockets
- Falls back gracefully to pull-poll if one side goes offline

## Quick Start

### 1. Deploy the PHP router

```bash
cp php/src/config.template.toml php/src/config.toml
# Edit host_url to match your domain
# Point your web server to php/src/
```

### 2. Connect a Python node

```ini
# ~/.reticulum/config
[[PostInterface]]
    type = PostInterface
    enabled = yes
    node_url = https://your-node.example.com/reticulum
```

### 3. Connect from a browser

```javascript
import { Reticulum, PostInterface } from "./lib/rns/reticulum.js";

const rns = new Reticulum();
const iface = new PostInterface("My Client", "https://your-node.example.com/reticulum", myHash);
rns.addInterface(iface);
```

## Requirements

| Component | Requirements |
|-----------|-------------|
| **php/** | PHP 8.1+, ext-sqlite3, write access to `var/` |
| **js/** | Modern browser with ES module support |
| **python/** | Python 3.9+, RNS (`pip install rns`) |

## Deploying

```bash
source deploy.env        # see deploy.env.example
./deploy.sh              # test, deploy HEAD to both nodes, verify
./verify-deploy.sh       # just ask: do the nodes match HEAD?
```

`deploy.sh` refuses a dirty working tree, refuses a red test suite, deploys from
`git archive <ref>` rather than from your filesystem, syntax-checks what landed,
and hash-verifies every file afterwards. `./deploy.sh <old-ref>` is the rollback.

This exists because on 2026-08-17 the working tree held a copy of five lib files
that was `HEAD` with the newest commit's fixes surgically removed — content in no
commit and on no server. `scp`ing it would have silently reverted the
`last_seen_at` staleness fix, the orphaned-local-destination cleanup and the
path-request throttle. Three of this repo's own tests fail instantly against
those files; nothing ran them. The lesson is not "be more careful" — the defence
already existed. It is that **the checks have to be attached to the act of
deploying**, and that deploying from a directory instead of a ref is what makes
an unreviewed local edit shippable in the first place.

Corollary, learned the same day: `verify-deploy.sh` found both live nodes running
a `request_http_api_helper_trait.php` that returns exception message, file and
line to HTTP clients, while the hardened version had been sitting committed in
git. Drift runs in both directions — a fix that is committed but never deployed
is just as invisible as a regression that is deployed but never committed.

## Storage Budget

The router caps the total disk it occupies — every table it owns plus its log
files — at `maintenance.storage_max_bytes`, default **300 MB**. When the
footprint exceeds the budget, maintenance prunes oldest-first through tiers,
cheapest data before the most valuable:

1. `inbound_packets` — parse diagnostics (announces a live path entry still
   points at are exempt)
2. `outbound_packets` where `acked_at IS NOT NULL` — delivered history
3. `inbound_batches` / `outbound_batches` — processed envelopes
4. `outbound_packets` where `acked_at IS NULL` — queued traffic, only past
   `outbound_pending_max_age_seconds` (24h)
5. `known_destinations`, then expired `path_entries`

Nothing younger than `storage_prune_min_age_seconds` (300s) is ever pruned, at
any pressure. If every tier hits its floor and the node is still over budget, it
logs the shortfall rather than eating live traffic.

### Reclaiming space — no scheduler involved

**Pruning rows does not shrink the database.** With `innodb_file_per_table`, a
DELETE returns pages to the tablespace free list, not to the filesystem — the
`.ibd` file, and therefore the hosting account's disk usage, stays exactly where
it was. Only a table rebuild shrinks it.

A rebuild outlives a web request, so it cannot run inline. It is still the
node's own job, not a scheduler's: when maintenance sees enough reclaimable
space, it **spawns a detached `php index.php reclaim`** and returns immediately
— the same mechanism already used for wake dispatch. The throttle window is
claimed by the parent before spawning, so requests arriving during a rebuild do
not pile up more of them.

Every operation therefore polices its own storage:

| Where | What runs | Cost |
|---|---|---|
| Every exchange | Log trim; maintenance TTL expiry | stat() + bounded DELETEs |
| Every 60s (`storage_check_interval_seconds`) | `ANALYZE`, measure, prune tiers | one indexed pass per tier |
| When free space ≥ 64 MB, at most hourly | Detached rebuild | out of band |

`php index.php once` still does everything inline, including the rebuild, if you
ever want to force a pass by hand. Nothing requires it on a timer.

Check the current state at `/health`:

```
storage_bytes                 total footprint (database + logs)
storage_database_free_bytes   freed pages awaiting a rebuild
storage_budget_bytes          the configured cap
```

If `storage_database_free_bytes` stays large across several minutes, reclaim is
not completing — check `error_log` for a spawn failure. On a host where `exec()`
is disabled the budget records `storage_reclaim_deferred` and pruning still
bounds row growth, but the freed pages stay charged until a rebuild runs.

Two limitations worth knowing:

**An idle node does not police itself.** Enforcement rides on the exchange
prelude, so a node receiving no traffic never runs maintenance. That is mostly
benign — a node with no traffic is not accumulating either — but a node that was
busy, filled up, and then went quiet keeps everything until it is used again.
selectivesubconscious.com was in exactly that state: 686 MB of legacy data,
frozen counters, and `interfaces_online` still reporting 2 because
`markStaleInterfacesOffline()` had not run in days. Run `php index.php once` by
hand to clean up a node you have taken out of service.

**Convergence takes more than one pass.** InnoDB's purge is asynchronous, so
immediately after a large DELETE `data_free` still under-reports and the table
is not yet a reclaim candidate. The next pass picks it up. Driving
selectivesubconscious.com from 686 MB to 64.7 MB took three passes, after which
it holds steady as a no-op.

### Statistics must be refreshed before they are believed

`information_schema.TABLES` serves cached data-dictionary statistics, and with
`innodb_stats_on_metadata = 0` (the default since 8.0) nothing refreshes them on
read. They can be wrong by the entire size of a table. Measured here immediately
after an `OPTIMIZE` that really did shrink the tablespace from 1053 MB to
16.6 MB:

```
before ANALYZE:  outbound_packets  703.9 MB   <- the pre-rebuild figure
after  ANALYZE:  outbound_packets    0.2 MB   <- the truth
```

The budget therefore runs `ANALYZE TABLE` before every measurement it acts on.
Skipping it would have the pruner delete every tier down to its retention floor
to recover space that was already free.

> `maintenance.packet_storage_max_bytes` is a separate, older guard that caps the
> length of the base64 payload columns only. It ignores indexes, row overhead,
> and the batch/path/destination tables; on a production node it under-reported
> the real footprint by more than 7×. Keep it, but do not rely on it as the disk
> cap.

## HTTP Exchange Protocol

All three components speak the same HTTP exchange protocol:

1. **Register** — `POST /v1/interfaces/register` → `{ interface_id, session_token }`
2. **Exchange** — `POST /v1/interfaces/exchange` → upload queued packets, receive delivery packets
3. Packets are base64-encoded raw Reticulum frames transported in JSON

## Related Projects

- [Retichat Web](https://github.com/jrl290/Retichat-js) — Browser chat client using this exchange
- [Reticulum](https://github.com/markqvist/Reticulum) — Python reference implementation
- [Retichat Android](https://github.com/jrl290/Retichat-android) — Native Android client
- [Retichat iOS](https://github.com/jrl290/Retichat-ios) — Native iOS client

## License

MIT — see [LICENSE](LICENSE)
