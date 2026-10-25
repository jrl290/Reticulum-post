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
The browser-side RNS protocol stack lives in [Retichat-js](https://github.com/jrl290/Retichat-js) (`lib/rns/`) — pure ES modules loaded via import maps, no npm, no build step. It implements identities, destinations, links, resources, announces, LXMF messaging, and the HTTP exchange transport client (`lib/rns/interfaces/post_interface.js`), and it is the only maintained copy.

> A snapshot of that stack used to live in this repo under `js/`. It was removed
> on 2026-08-17: it had drifted six weeks behind (no `resource.js`, no link
> watchdog, pre-rework timeouts) while this README presented it as current —
> which made it a trap for exactly the kind of silent regression this project
> works hard to prevent. If you need the history, it is in git before this
> commit.

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
./verify-live-stamp.sh   # same question, no credentials: /health's build stamp
```

`deploy.sh` stamps each deploy: `build.json` (from `write-build-stamp.sh`)
names the commit, and `GET /health` publishes it as `build.commit`. Before any
code goes live the node's stamp is set to unknown (`{"commit":null}`), and the
new one is written only after `verify-deploy.sh` has proved the bytes, so a
deploy that stops part way leaves `build.commit: null`, never a commit the node
was not proven to run. `verify-live-stamp.sh [ref] [retichat|selectiv]` compares
the stamp with a ref from anywhere, with no SSH. It proves the last verified
deploy, not the bytes now; `verify-deploy.sh` is still the byte-for-byte check.

`deploy.sh` refuses a dirty working tree, refuses a red test suite, deploys from
`git archive <ref>` rather than from your filesystem, syntax-checks the code on
each node before and after it goes live, and hash-verifies every file
afterwards. Before anything is uploaded it reads each node's stamp over ssh and
refuses a ref that does not descend from the commit the node runs, so a deploy
never takes back what is live by accident; a stamp that names no commit stops
it too, for you to find out what the node runs. `DEPLOY_ROLLBACK=1 ./deploy.sh
<old-ref>` is the rollback; the deploy log records the override.

No node ever runs a mix of two releases. Every node first receives the ref in
`~/reticulum-incoming`, outside the web root, and lints it with its own
`php -l`, together with the php files the node keeps in the live directory
(`config.php`, `_test.php`, local tools), which the lint after the swap will
also meet; if any file fails on any node, the deploy stops with nothing changed
live anywhere. Only then does each node swap it in, with one ssh command that
renames every file over its live name (`lib/` first; each rename is atomic and
the set takes milliseconds) and removes the files listed in `RETIRED` in
`deploy.sh`. Before the swap the node's code and stamp are copied to
`~/reticulum-rollback`. If a rename or removal fails, the same command puts
the previous release back, stamp included, by renames out of that copy, which
need no free space (a full disk is the likeliest cause). It ignores a
hang-up, so a connection that drops part way leaves the node to finish the
swap. A failure after the swap prints the command that puts the copy back. A
commit that deletes a file under `php/src` adds it to `RETIRED`; an entry can
go once every node has deployed past that commit, and an empty list is fine.
`RETIRED` may never name a file the node owns (`config.php`, `_test.php`).

Between the lint and the swap, every node builds the ref's schema against its
live database: `php ~/reticulum-incoming/index.php migrate --project-root
<live directory>` (REGISTRATION-STAGE1.md §13). It prints each object it builds
and how long that took, records no schema version (the new code's first
request does), and ignores a hang-up, since a dropped connection would roll an
index build back. On MySQL and MariaDB each statement waits at most 2 s for its
table's lock (`lock_wait_timeout`, a day by default), so a busy table cannot
queue the live node's requests behind it for long, and asks for the online
algorithm (`ALGORITHM=INSTANT` to add columns, `ALGORITHM=INPLACE LOCK=NONE`
for an index), so a server that cannot do one refuses at once instead of
copying or locking the table. A statement that waits out the 2 s is not tried
again: the step stops and fails, saying so, and the deploy can be run again.
If it fails on any node, nothing is swapped anywhere; the code that is live
keeps serving and ignores the new objects. A ref whose `index.php` has no
migrate mode (any before Stage 1) skips the step.
`php/tests/deploy_never_mixes_releases_test.php` runs `deploy.sh` against two
stand-in nodes to hold all of this.

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

## Admin page

`<host_url>/admin` (on retichat.com, `https://retichat.com/reticulum/admin`) is
the node's operator console. It shows the connections, the configured peers,
traffic in and out, the queues and storage, live, and it has the peering
actions (Reconnect, Rotate) and the maintenance actions (flush stale sessions,
normal or forced, and the debug report). It answers 404, like any unknown path,
until someone on the host sets a username and password:

```bash
cd ~/public_html/reticulum && php index.php admin-setup <username>
```

It asks for the password twice without showing it (12 to 72 bytes), and keeps
only the username and a bcrypt hash, in `~/.reticulum-post/admin.json` (mode
0600, outside the web root). From this Mac, with the password piped in so it
is neither shown nor on a command line:

```bash
read -rs -p 'Password: ' P; echo; printf '%s\n' "$P" | test-harnesses/distro-pipeline/node.sh retichat "cd ~/public_html/reticulum && php index.php admin-setup <username>"; unset P
```

- `admin-setup` again changes the password, signs out every session and lifts
  a sign-in lockout. `php index.php admin-remove` closes the page (404).
- A session lasts two hours. While its tab is visible the page polls
  `/admin/data` every 5 s.
- Sign-in allows five attempts per address in 15 minutes, and a hundred per
  hour from all addresses together; past that, only an address that has
  signed in within 30 days may try.
- It answers over HTTPS only, sends no CORS headers, and every action needs
  this page's origin and a token from the session.
- If it still answers 404 after `admin-setup`, the web server does not see the
  home directory the command did (no posix extension, or another account): set
  `[admin] credentials_file` in the node's config to an absolute path outside
  `public_html` that the web server can read, and run `admin-setup` again.
- The page shares its origin with everything else the host serves, so a script
  injected into another page there could act as a signed-in admin. Sign out
  when done; sessions are short for this reason.

It replaced `/v1/monitor`, `/v1/monitor/data|json`, `POST /v1/monitor/clear`,
`POST /v1/maintenance/flush`, `/debug` and `monitor.php` on 2026-10-14. None of
them authenticated: every node answered them until 2026-09-30, then every node
with `debug.enabled`. The clear-all button did not come back. `debug.enabled`
now only turns on extra logging, and `debug.max_rows` sizes the debug report.
`php/tests/admin_console_test.php` pins all of this.

## Rotating a PHP peering's credentials

A PHP-to-PHP peering is two rows. The node with an `[interfaces]` block for the
other (the initiator) holds a row whose `interface_id` + `session_token` the
peer presents to *its* `/v1/interfaces/exchange`, and it registered those at
the peer, which keeps them as `peer_interface_id` + `peer_session_token`. The
peer's own row id and token travel back the same way. Until 2026-09-30 `/health`
published the peer's copy of the initiator's credential in the row metadata, and
`/v1/monitor` published the `peer_session_token` column, so both halves were
public.

`POST /v1/wake` handed them out too, from 606d800 (2026-07-10) until the fix
that added `canonicalPeerBaseUrl()` (2026-10-03). A wake sent a row's
`peer_interface_id` + `peer_session_token` to whatever `waker_url` the request
named, as long as the row lookup matched it, and on MySQL/MariaDB
`utf8mb4_unicode_ci` matches look-alikes such as `https://rétichat.com/reticulum`.
Nothing logged where they went. Treat the credentials in use when that fix goes
live as leaked, including the ones the 2026-10-01 rotation made, and rotate
again once it is live on both nodes.

Rotate only once every node runs code that closes both leaks, or the new tokens
leak too:

- **Publishes neither.** `curl -s https://<node>/reticulum/health | grep -c peer_session_token`
  must print 0. `/v1/monitor/data` was the other place until 2026-10-14; the
  admin page that replaced it is behind its sign-in and gets the same
  allowlist as `/health`.
- **Sends a peer's credentials only to the row's own URL.** Every node must be
  at the wake fix (✓) or "ahead of" it. Anything else ("behind", "diverged",
  no stamp, no answer) means the fix is not proven live there: do not rotate.

  ```bash
  FIX="$(git log --reverse --format=%H -S canonicalPeerBaseUrl -- php/src/lib/request_php_wake_trait.php | head -1)"
  ./verify-live-stamp.sh "${FIX:?the wake fix is not in this checkout}"
  ```

  The `:?` matters: given an empty ref, `verify-live-stamp.sh` compares
  against `HEAD`, and on a checkout without the fix that would pass a node
  that still leaks.

1. **Read, on both nodes.** Which one has the block, and the "before" state
   (fingerprints, never tokens):

   ```bash
   N=retichat   # then N=selectiv
   test-harnesses/distro-pipeline/node.sh $N "awk '/^\[interfaces\]/,0' ~/public_html/reticulum/config.toml | grep -viE 'pass|token|secret'"
   test-harnesses/distro-pipeline/node.sh sql-$N "SELECT interface_id, name, status, FROM_UNIXTIME(last_seen_at) seen, peer_url, peer_interface_id, LEFT(SHA2(session_token,256),12) sess_fp, LEFT(SHA2(COALESCE(peer_session_token,''),256),12) peer_fp FROM interfaces WHERE peer_url IS NOT NULL"
   ```

   Each node should hold one row for the other. If either holds two, stop: that
   needs a look before anything is deleted.

2. **Rotate, on one initiator.** Prefer retichat.com if it has the block: the
   initiator's row gets a new id, and selectiv's paths to the whole network hang
   off selectiv's row, which keeps its id. `<peer URL>` is that node's row
   `peer_url` exactly as step 1 printed it.

   ```bash
   test-harnesses/distro-pipeline/node.sh sql-retichat "DELETE FROM interfaces WHERE peer_url = '<peer URL>' AND peer_interface_id IS NOT NULL"
   test-harnesses/distro-pipeline/node.sh retichat "cd ~/public_html/reticulum && php index.php initialize"
   ```

   Delete, do not mark the row dead: the peer's next exchange authenticates with
   the old token and marks a merely-offline row online again, and then
   `initialize` reports `already_connected` and rotates nothing. With the row
   gone the old token is refused at once and nothing can revive it.
   `initialize` finds no row, makes a new id and token, and registers at the
   peer, which re-binds its row in place with a new session token of its own.
   Its output's `peers[]` must say `connected` (or `already_connected` with an
   id that differs from step 1, if the node's own maintenance got there first);
   it exits 1 otherwise, or when the schema migration it runs first reports an
   error. `register_failed` means the peer did not answer: the initiator's old
   token is already dead, but the peer's is live until a registration lands, so
   run `initialize` again once the peer answers.

   Or press **Rotate** beside the peer on the initiator's admin page: the
   `DELETE` and the registration in one action, refused with nothing deleted
   when step 1 would have stopped (two rows naming the peer). It answers with
   the new `interface_id` and the one it replaced, and the same statuses.

   `initialize` is a command on the host, not a URL. Until 2026-10-14
   `GET /v1/initialize` did the same for anyone. While a node's row for its
   peer sat offline after a quiet spell, one anonymous request rotated the
   peering, with every cost listed below. It now answers 404
   (`php/tests/initialize_is_operator_only_test.php`). The admin page's
   **Reconnect** is `initialize` for one peer, without the migration, so it
   rotates a row that is merely quiet in the same way.

3. **Verify.** Step 1's query again. The initiator's row has a new
   `interface_id`, and the old one is gone. The peer's row keeps its
   `interface_id`; its `peer_interface_id` is the initiator's new id, and both
   `sess_fp` and `peer_fp` differ from step 1. Both rows are online at once;
   within a minute their rx/tx move in `/health`, and a browser on selectiv
   receives announces and can send a DM.

What breaks meanwhile: between the `DELETE` and `initialize`, nothing is queued
across the peering and the peer's exchanges get 401. Afterwards, on the
initiator only, packets that were queued for the old row are lost, paths through
it are unusable until those destinations announce again, and links relayed
across the peering (a selectiv browser's rfed links, for example) are gone, so
those users should reload. The peer's row, its queue and its paths survive.

The gateway bridge needs none of this: the `peer_session_token` it registers is
never checked (Reticulum-rust `post_interface.rs` wake server), and the bridge's
real `session_token` was never published. A wake sends only the unchecked one.

`php/tests/peer_session_rotation_test.php` runs this procedure on two real
nodes, with a peer exchange between the two commands, and pins the gate above;
`php/tests/admin_console_test.php` runs the admin page's Rotate.

## Signed registration (operators)

The contract is `REGISTRATION-STAGE1.md`. Browsers (`client` `rns-js`) sign
their registration with their identity's key; every other client registers as
before.

- **The switch.** `[registration] enforce_signed_registration` in
  `config.toml` is off by default: signed registrations are taken, and legacy
  browser registrations still work, logged `[REG-LEGACY]`. On, every legacy
  browser registration gets `403 signature_required`, every legacy browser row
  `401`, and no legacy browser row may carry an announce. James turns it on,
  on a date he sets.
- **`/health`'s `registration` object:** `version` 1 (the node runs Stage 1),
  `schema_migrated` (the recorded schema is this code's and its objects are
  there), the switch as loaded, `browsers_online` (`signed`, `legacy`) and
  `hash_only_challenges`. A rise in the last is a prompt to run Retichat-js's
  `verify-deploy.sh`, never a gate: anyone can ask for such a challenge.
- **Checking a node from outside.** `.venv/bin/python
  Reticulum-post/tools/stage1_probe.py https://<host>/reticulum` (add
  `--enforced` once the switch is on) registers two test identities of its
  own, kept in `~/.reticulum-post-probe/`, and checks each answer of the
  challenge, the signed and legacy registrations, the exchange, `401`, `409`
  and the goodbye, each within 5 s. It prints no token, and exits non-zero
  naming the step that failed. It writes two rows to the node's database and
  re-binds the same two on every run.
- **The log.** `[REG-SIGNED]`, `[REG-LEGACY]`, `[REG-REFUSED]`, `[REG-RETIRE]`,
  `[REG-CLAIM-IGNORED]`, `[SESSION-SUPERSEDED]`, `[ANNOUNCE-FOREIGN]` and
  `[ANNOUNCE-LEGACY-REFUSED]` go to PHP's error log beside `index.php`, with
  identity hashes in full: they say who registered here and when. **The log
  files must not be served:** `https://<host>/reticulum/error_log` and
  `…/reticulum/var/router.log` must not answer `200`. `deploy.sh` never
  touches dotfiles, so this is set by hand, for example with
  `RedirectMatch 404 ^/reticulum/(error_log|var/)` in
  `~/public_html/reticulum/.htaccess`; both `curl`s must then answer `403` or
  `404`.
- **The count never goes back.** A signed row (`identity_hash IS NOT NULL`)
  is deleted only together with a rotation of the node secret, in the same
  session:

  ```sql
  DELETE FROM interfaces WHERE interface_id = '<id>' AND identity_hash IS NOT NULL;
  DELETE FROM transport_state WHERE state_key = 'registration_challenge_secret_hex';
  ```

  Otherwise its `registration_seq` would restart at 0 under the same secret,
  and a registration body already used at a low count would work once more.
  After the rotation every outstanding challenge fails once (`409
  stale_challenge`), and each browser asks for a new one and registers again.
  No route empties `interfaces` or `transport_state`: the admin page, which
  replaced `/v1/monitor/clear` and `monitor.php` on 2026-10-14, has no
  clear-all.
- **SQL.** Every value bound; no backslash in a SQL string literal; no named
  placeholder twice in one statement (MySQL's native prepares fail with
  `HY093` where SQLite accepts it: the 2026-09-23 outage); every statement
  runs on SQLite, MySQL 8.4 and MariaDB 11.4.
  `no_backslash_in_sql_literals_test.php` and
  `unique_named_placeholders_test.php` hold the second and third; only a run
  on each engine holds the last.

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
space, it **spawns a detached `php index.php reclaim`** and returns immediately.
It is the only process the node ever starts: wakes to peers go out inline,
fire-and-forget, at the end of an exchange. The throttle window is claimed by
the parent before spawning, so requests arriving during a rebuild do not pile
up more of them.

Each rebuild waits at most 2 s for its table's metadata lock, as the deploy's
schema step does: one queued behind a long transaction would hold every later
query on that table behind it. A table that gives up is logged as any reclaim
failure is (`OPTIMIZE TABLE failed on <table>: it waited 2 s …`), is not
retried, and waits for a later reclaim.

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

Reticulum Post is James LaFarge's work. Parts of the PHP router follow the transport behaviour of the Python reference implementation (`Transport.py`), so it is distributed under the Reticulum License, with Mark Qvist's notice for those parts. See [LICENSE](LICENSE).
