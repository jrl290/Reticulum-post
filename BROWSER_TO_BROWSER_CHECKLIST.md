# Browser-to-Browser Messaging Checklist

## Recent Fixes Checklist (This Session)

Use this list to confirm the exact fixes that were just made before running full E2E.

### A) Retichat-js proof/link ID compatibility

- [ ] `Retichat-js/lib/rns/link.js`: `setLinkId()` computes link ID from `packet.getHashablePart()`.
- [ ] `Retichat-js/lib/rns/link.js`: when `packet.data.length > Link.ECPUBSIZE`, strip the extra bytes from the hash input (`diff = len - ECPUBSIZE`) before truncated hash.
- [ ] `Retichat-js/lib/rns/link.js`: no temporary debug `console.log` remains in the final proof/hash code path.
- [ ] `Retichat-js/lib/rns/packet.js`: `getHashablePart()` behavior still mirrors Python (lower nibble of flags + payload after flags/hops).
- [ ] Browser bundle cache is hard-refreshed after deploying JS changes.

### B) PHP local-link/proof routing safeguards

- [ ] Local-delivered LINKREQUEST packets still create reverse-path state so LRPROOF has a valid return route.
- [ ] LRPROOF relay path does not artificially increment hops during relay.
- [ ] Proof relay packets appear in outbound queue with `queue_reason=proof_relay` and transition to `acked_at` after delivery.

### C) Local destination ownership correctness

- [ ] Browser-owned local destinations are not overwritten by bridge/transit announce registration.
- [ ] `deliverLocallyIfKnown` does not reject valid peer-origin packets due to incorrect local ownership.

### D) Minimal validation run (must pass in one clean run)

- [ ] Start with a clean runtime: one PHP process, one active browser interface, one active bridge interface, fresh DB/log state.
- [ ] Send browser -> browser message and confirm outbound `relay` on sender node.
- [ ] Confirm receiver node enqueues `local_delivery` for browser interface.
- [ ] Confirm LRPROOF path: proof seen, proof relayed/acked, pending link transitions to active.
- [ ] Final acceptance: `sent=OK`, `receipt=OK`, `reply=OK`.

### E) Chrome permission prompt hardening (dead transport imports)

- [ ] `Retichat-js/lib/rns/reticulum.js`: remove `DirectSocketsInterface` import.
- [ ] `Retichat-js/lib/rns/reticulum.js`: remove `WebsocketClientInterface` import.
- [ ] `Retichat-js/lib/rns/reticulum.js`: remove `TCPClientInterface` import if it is not used by any live exchange path.
- [ ] `Retichat-js/lib/rns/reticulum.js`: remove dead transport exports (`DirectSocketsInterface`, `WebsocketClientInterface`, and `TCPClientInterface` if unused).
- [ ] Repo grep check returns no reachable dead transport usage from browser app entrypoint:
  `grep -rn "DirectSockets\|WebsocketClient\|openTCPSocket\|TCPClientInterface" Retichat-js/lib Retichat-js/app.js`
- [ ] `Retichat-js/app.js` uses only `PostInterface` transport.
- [ ] Remove or quarantine dead interface files not referenced by exchange-only runtime:
  `direct_sockets_interface.js`, `websocket_client_interface.js`, and `tcp_client_interface.js` (if unused).
- [ ] Hard-reload in fresh Chrome profile on both nodes and confirm no permission prompt appears.
- [ ] Deploy cleaned build to both hosts and repeat smoke send/receive.
- [ ] Add README guardrail: exchange-only build must not import `navigator.openTCPSocket` or WebSocket transport modules.

### F) Wake-driven PHP peer connections

- [ ] `fireAndForgetWakeWithCurl` uses `CURLOPT_RETURNTRANSFER = true` — with `false`, curl dumps the wake response to stdout and concatenates it onto the exchange JSON (classic `Unexpected non-whitespace character after JSON at position N`).
- [ ] `dispatchWakes()` is `public` — it is called from `HttpApi` scope in the request epilogue; `private` throws `Call to private method ... from scope ReticulumPhp\HttpApi` on every request.
- [ ] `/v1/wake` is fire-and-forget for the caller and only triggers an inline `exchangeWithPhpPeer()` pull on the receiver. The waker has already dropped the connection; no response flag needed.
- [ ] `fireAndForgetWake` appends `/v1/wake` to `peer_url` only if not already present (peer_url is the base URL).
- [ ] Bidirectional registration happens in a single `/v1/interfaces/register`: the initiator pre-generates `peer_interface_id` + `peer_session_token` and sends them in metadata (`client: "reticulum-php"`); the receiver stores them and echoes them back.
- [ ] `dispatchWakes()` only wakes peers that have pending outbound packets, rate-limited by `min_wake_interval_ms` (default 1000ms) via `last_wake_sent_at` — wake is traffic-driven, not a heartbeat. Zero pending outbound = zero wakes (expected when idle).
- [ ] Wake HTTP call is truly fire-and-forget: `CURLOPT_TIMEOUT_MS` short (default 500ms), response ignored — a slow/down peer must not add latency to the triggering request.
- [ ] Stale peer credentials after a redeploy/wipe: `DELETE FROM interfaces WHERE peer_url IS NOT NULL` on both nodes, then re-run `/v1/initialize` to re-handshake fresh credentials.
- [ ] `dispatchWakes()` is wired into the request lifecycle via `register_shutdown_function(fn() => $this->dispatchWakes())` at the top of `handle()` — NOT called inline in `respond()` (curl output leaks into the JSON response body). The shutdown function runs after the response is fully sent, so wake dispatch latency and any curl errors never corrupt client-facing JSON.
- [ ] Verify zero output leak: `curl -sk https://host/reticulum/v1/monitor/data | python3 -c "import sys,json; json.load(sys.stdin); print('clean')"` — must parse without `JSONDecodeError: Extra data`.
- [ ] `peer_url` in the `interfaces` table must be the remote peer's **base URL** (`https://otherhost/reticulum`), NOT the wake URL (`.../v1/wake`). The exchange protocol calls `$peerUrl . '/v1/interfaces/exchange'` — if peer_url includes `/v1/wake`, the exchange URL becomes `.../v1/wake/v1/interfaces/exchange` which routes to the wrong host. Verify: `SELECT interface_id, name, peer_url FROM interfaces WHERE peer_url IS NOT NULL;` — no `/v1/wake` suffix.
- [ ] The exchange protocol is a **pull** model: the waker pulls from the woken. When node A has packets queued for node B (in A's outbound), A's `dispatchWakes()` fires a wake to B, then B calls A's exchange endpoint and A returns the packets. Verify direction: wake the node that needs to RECEIVE, not the node that HAS the packets.
- [ ] `decodeJson()` in `request_json_codec_trait.php` must NOT use `JSON_PARTIAL_OUTPUT_ON_ERROR` on `json_decode()` — that flag is only valid for `json_encode`. On `json_decode` it causes PHP 8.3 to throw `JsonException: Control character error, possibly incorrectly encoded` when decoding data containing certain byte sequences (e.g., binary RNS packet payloads stored in `payload_json`). Symptom: `/v1/wake` returns 500; `exchangeWithPhpPeer` crashes inside `decodeJson` → `drainPeerAckBatchIds` or `appendPeerAckBatchId` when reading `pending_ack_batch_ids_json` from the DB. Fix: remove `JSON_PARTIAL_OUTPUT_ON_ERROR` from all `json_decode` calls, add try-catch to both `decodeJson()` and `encodeJson()`, use `JSON_INVALID_UTF8_SUBSTITUTE` on `json_encode`. Grep check: `grep -rn "json_decode.*JSON_PARTIAL" lib/` must return nothing.
- [ ] `encodeJson()` in `request_json_codec_trait.php` wraps `json_encode` in try-catch with a UTF-8 cleaning fallback (`mb_convert_encoding`) — binary packet data can contain byte sequences that `json_encode` rejects even with `JSON_INVALID_UTF8_SUBSTITUTE`. Without the fallback, `ingestInboundBatchInline` throws when storing received peer packets as `payload_json`.

### G) Standard RNS relay (no custom filtering)

- [ ] Relay uses `allOtherInterfaceIds()` — announces flood to every interface except the source, no online/last-seen gating. PHP peer interfaces are wake-driven and must not be filtered out for being "offline".
- [ ] `shouldRelayAcceptedPacket()` handles announces (packet_type 1) FIRST — the old `destination_type === 3` (SINGLE) reject silently blocked ALL announces from relay.
- [ ] `pathEntry()` normalizes the destination hash with `strtolower()` before the DB lookup. Path entries are stored lowercase (via `upsertPathFromAnnounce`), but DATA packets from JavaScript may arrive with mixed/uppercase hex. Without normalization, `usablePathEntry` returns `null`, `relayTargetsForAcceptedPacket` returns `[]`, and DATA relay is silently dropped — only announces (which flood to all interfaces) work.

### H) PDO dual-backend (MySQL/SQLite) migration gotchas

- [ ] `$stmt->execute()` returns `true` in PDO, NOT a statement — split into `$stmt->execute(); ... $stmt->fetch(...)`. `execute()->fetch()` throws `Call to a member function fetch() on true`.
- [ ] `db->query()` DOES return a statement — `countByQuery` uses `$result = $this->db->query(...); $result->fetch(...)` (don't blindly sed this to `$stmt`).
- [ ] `ON CONFLICT(col) DO UPDATE SET` (SQLite) must go through `Database::upsertSql()` to become `ON DUPLICATE KEY UPDATE` for MySQL.
- [ ] `CREATE INDEX IF NOT EXISTS` is SQLite-only — use `ensureIndex()` (catches duplicate-index errors) with plain `CREATE INDEX` for MySQL compatibility.
- [ ] Traits that reference `PDO::` constants need `use PDO;` at the top (namespaced files resolve `PDO` to `ReticulumPhp\PDO` otherwise).
- [ ] SQLite `sqlite_path` must be absolute for web (SAPI) requests — relative paths resolve against the request CWD and silently open the wrong/empty DB.

### I) Deployment prerequisites (fresh host)

- [ ] `.htaccess` present in the reticulum dir with the `RewriteRule ^(.*)$ index.php/$1` front-controller rule — without it every `/v1/*` route returns Apache 404.
- [ ] `var/` directory exists and is writable (SQLite DB + router.log).
- [ ] Run schema migration once (`$s->migrate()`), then `/v1/initialize` to connect peers.

### J) `/v1/initialize` bootstrap endpoint

- [ ] `GET /v1/initialize` runs `migrate()`, resets opcache, and connects to every configured peer — one browser-callable call, no separate config section.
- [ ] Peer URLs come from the existing `[[Interfaces]]` config (`node_url`, falling back to `peer_url`) — do NOT add an `[initialize]` section.
- [ ] `connectToPeer()` is idempotent: returns `already_connected` if a row already exists for that `peer_url`; only registers when missing.
- [ ] Requires `host_url` set in config — without it the handshake can't tell the peer where to call back (`status: no_host_url`).

### K) `/v1/monitor` dashboard

- [ ] `GET /v1/monitor` renders a self-refreshing (5s) HTML page; `GET /v1/monitor/data` returns the same as JSON.
- [ ] Splits interfaces into **Connected Peers** (rows with `peer_url`) and **Active Clients** (online, non-peer) — stale/offline client rows are filtered out to cut noise.
- [ ] Packet tables are labeled by direction from the node's view: **Received** (inbound from clients/peers) and **Queued Outbound** — never label node-received packets as "inbound" in the operator UI.
- [ ] `exchangeWithPhpPeer()` calls `touchInterface(..., 'online')` after a successful exchange so the peer shows online on the monitor.

### L) Retichat-js exchange-only refactor

- [ ] `app.js` `connect()` uses `PostInterface` as the ONLY transport — no fallback chain, no `addedAny` flag (dangling `addedAny` reference throws `ReferenceError: addedAny is not defined`).
- [ ] `DEFAULT_CONFIG` has no `rnsEndpoint` / `tcpBackbones` keys; `loadConfig()` does not read them.
- [ ] `config.json` `exchangeUrl` is the clean base URL (`https://host/reticulum`) with NO `/index.php` suffix — stale localStorage creds keyed to the old URL cause a re-register on next load.
- [ ] Client-side `Unexpected non-whitespace character after JSON at position N` is almost always the server-side `CURLOPT_RETURNTRANSFER=false` wake bug (section F), not a client parse bug — verify the raw exchange response is clean JSON first.


## Victory Confirmations

1. **selectiv → retichat**: `RetichatTest.send()` delivered "Hello from selectiv! 10:53:45 AM" on retichat.com
2. **retichat → selectiv**: `RetichatTest.send()` delivered "Hello from retichat! 10:54:22 AM" on selectivesubconscious.com
3. **Manual wake recovery**: Forced wake pulled queued DATA across peer — "Test 3 from selectiv" delivered to retichat

## Preconditions

- Both PHP nodes configured with `host_url` pointing to their respective exchange endpoints
- Both nodes have the other's peer interface registered via `/v1/wake` handshake
- Retichat-js `config.json` points `exchangeUrl` to the correct PHP node
- DirectSockets and WebSocket imports removed from `reticulum.js`
- Delivery checkmarks (✓) removed from UI — they only confirm local ack, not end-to-end

## Checklist: All 10 Must Pass

| # | Condition | Verify |
|---|-----------|--------|
| 1 | Both PHP peer interfaces online | Monitor: "Selective Subconscious" `status=online` on both nodes |
| 2 | Both browsers connected and polling | Monitor: "Retichat Web" `last_seen` < 5s ago on both nodes |
| 3 | Cross-node paths exist through peer | `path_entries` has dest routed through peer interface (not bridge `0aca3724...`) |
| 4 | Browser announces reach other browser | `RetichatTest.contacts()` → `hasPublicKey: true` on both |
| 5 | DATA relay queued on peer interface | Peer `outbound_packets` has `queue_reason=relay` with remote dest hash |
| 6 | Wake fires and peer outbound is delivered | Manual `POST /v1/wake` returns `delivery_packets > 0` |
| 7 | Receiving PHP delivers locally to browser | Browser `outbound_packets` has `queue_reason=local_delivery` for remote dest |
| 8 | Browser picks up delivery and acks it | `local_delivery` packet gets `acked_at` timestamp set |
| 9 | **No SQLite lock errors on selectiv** | `router.log` clean of `database is locked` |
| 10 | **No MySQL syntax errors on retichat** | `router.log` clean of `SQLSTATE` errors |

## Quick Diagnostic Commands

```bash
# Check peer online status
ssh retichat@retichat.com 'echo "SELECT interface_id, status FROM interfaces WHERE peer_url IS NOT NULL;" | mysql ...'
ssh selectiv@selectivesubconscious.com 'sqlite3 ... "SELECT interface_id, status FROM interfaces WHERE peer_url IS NOT NULL;"'

# Check router log for errors (both nodes)
grep "ERROR" var/router.log | tail -10

# Manual wake delivery test
curl -sk -X POST "https://retichat.com/reticulum/v1/wake" \
  -H 'Content-Type: application/json' \
  -d '{"waker_url":"https://selectivesubconscious.com/reticulum"}'

# Browser console test helpers (after hard-reload)
RetichatTest.help()
RetichatTest.state()        # connection status, ownHash
RetichatTest.contacts()     # verify hasPublicKey: true
RetichatTest.send("destHash", "test message")
RetichatTest.messages("destHash")  # check delivery
```

## Known Failure Modes

### #9: SQLite `database is locked` (selectiv)
- **Symptom**: Outbound packets queued but never delivered. Manual wake works, automatic doesn't.
- **Cause**: SQLite single-writer limitation under concurrent browser polls + wake exchanges.
- **Fix**: Migrate to MySQL (same as retichat), or increase `busy_timeout` (currently 60s), or add retry-with-backoff in wake path.

### #5: DATA not relayed — path missing
- **Symptom**: Browser sends data but peer outbound stays 0.
- **Cause**: Path entry deleted by maintenance (peer was offline). `isInterfaceActive` must return `true` for peer interfaces regardless of online status.
- **Fix**: `isInterfaceActive` checks `isPhpPeerInterface()` before checking `status=online`. Maintenance excludes peer paths from dead-interface cleanup.

### #4: Public key never arrives
- **Symptom**: `hasPublicKey: false` in `RetichatTest.contacts()`.
- **Cause**: Announced not propagating cross-node. Peer offline, or `allOtherInterfaceIds` excludes peer.
- **Fix**: `allOtherInterfaceIds` includes peers via `peer_url IS NOT NULL AND peer_interface_id IS NOT NULL` filter.

### #3: Paths through dead bridge
- **Symptom**: Paths route through bridge interface `0aca3724...` instead of peer.
- **Cause**: Bridge interface stays `online` due to peer repair bug. Path learned through bridge takes priority.
- **Fix**: Peer repair checks `last_seen_at` (15min window). Dead-interface path cleanup excludes peers but removes bridge paths.

### ON CONFLICT → MySQL syntax error
- **Symptom**: `?-1 error` entries in monitor, router log shows `SQLSTATE[42000]`.
- **Cause**: Raw `ON CONFLICT` SQLite syntax without `Database::upsertSql()` wrapper.
- **Fix**: All `INSERT ... ON CONFLICT` queries must be wrapped in `Database::upsertSql($sql, $this->backend)`.

### LIMIT in subquery → MySQL syntax error
- **Symptom**: Outbound cap query crashes, creating storm of error entries.
- **Cause**: `LIMIT ... NOT IN (... LIMIT ...)` not supported in MySQL.
- **Fix**: Use `LIMIT 1 OFFSET N` to find threshold, then `DELETE WHERE packet_id < threshold`.

### Remote announces wrongly registered as local
- **Symptom**: Data packets silently dropped — `deliverLocallyIfKnown` rejects because source == local interface.
- **Cause**: `registerLocalDestinationIfOwnInterface` registers peer announces as local destinations.
- **Fix**: Skip `registerLocalDestinationIfOwnInterface` for peer interfaces (`isPhpPeerInterface` check).

### `/v1/wake` 500: Control character error
- **Symptom**: `POST /v1/wake` returns 500 or `{"error":"internal error"}`. Router log may show `JsonException: Control character error, possibly incorrectly encoded` at `request_json_codec_trait.php:48`.
- **Cause**: `decodeJson()` uses `JSON_PARTIAL_OUTPUT_ON_ERROR` on `json_decode()` — that flag is for `json_encode` only. On `json_decode` it makes PHP 8.3 throw on certain byte sequences found in stored JSON (e.g., `pending_ack_batch_ids_json` in the `interfaces` table). The exception propagates unhandled through `drainPeerAckBatchIds` → `exchangeWithPhpPeer` → wake handler.
- **Fix**: Remove `JSON_PARTIAL_OUTPUT_ON_ERROR` from ALL `json_decode` calls. Add try-catch to `decodeJson()` and `encodeJson()` in `request_json_codec_trait.php`. Use `JSON_INVALID_UTF8_SUBSTITUTE` on `json_encode` calls. See checklist item F.15.

### Ack cycle stalls
- **Symptom**: Outbound delivered but never acked, re-delivered on every wake.
- **Cause**: `dispatchWakes` only fires for peers with pending outbound, not pending acks.
- **Fix**: `dispatchWakes` also wakes peers with non-empty `pending_ack_batch_ids_json`.

### Chrome permission prompt: "use other apps on this device"
- **Symptom**: Chrome prompts for privileged local/network capability on page load.
- **Cause**: Dead transport modules (`DirectSockets`/WebSocket) remain statically imported or re-exported in `reticulum.js`, which pulls `navigator.openTCPSocket` into the module graph.
- **Fix**: Remove dead transport imports/exports from `reticulum.js`, verify by grep, and keep exchange-only runtime on `PostInterface`.
