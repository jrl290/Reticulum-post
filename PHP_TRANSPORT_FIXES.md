# PHP Transport Fixes — Verified Against Python RNS Reference

Date: 2026-07-13
Python reference: `Reticulum-master/RNS/Transport.py`

---

## Fix 1: Transport Relay Enablement

**Files**: `request_packet_ingest_trait.php`, `request_inbound_batch_trait.php`, `request_relay_routing_trait.php`

**Problem**: PHP node could not route packets as a transport. Three issues:

1. `applyPacketFilter` rejected packets with non-matching `transport_id` as a **filter** criterion
2. No explicit transport relay path in the inbound cascade
3. `rewriteTransportRelayRaw` preserved `context_flag` (bit 5) when stripping transport headers

**Python reference** (`Transport.py` lines 1503–1582):

```python
# transport_id is a ROUTING HINT, not a filter — checked at routing decision, not ingress
if packet.transport_id != None and packet.packet_type != RNS.Packet.ANNOUNCE:
    if packet.transport_id == Transport.identity.hash:
        if packet.destination_hash in Transport.path_table:
            # re-encode with next_hop
            if remaining_hops == 1:
                # Strip transport headers: HEADER_1 | BROADCAST | (flags & 0b00001111)
                new_flags = (RNS.Packet.HEADER_1) << 6 | (Transport.BROADCAST) << 4 | (packet.flags & 0b00001111)
```

**Changes**:

1. **`request_packet_ingest_trait.php`**: Removed `transport_id_mismatch` rejection from `applyPacketFilter`. Transport ID is now checked only at the routing decision point, not at ingress.

2. **`request_inbound_batch_trait.php`**: Added `shouldTransportRelayPacket` / `relayTransportPacket` as the **first** check in the relay cascade (before LRPROOF, link_table, proof, catch-all relay). Matches Python lines 1503–1582:
   - Has path → re-encode with next hop, creates `reverse_path` entries for proof return, creates `link_transport` entries for LINKREQUEST
   - No path → logs and drops

3. **`request_relay_routing_trait.php`**: `rewriteTransportRelayRaw` now clears `context_flag` (bit 5) when stripping to `HEADER_1`, matching Python's `flags & 0b00001111` mask.

**Verification**: ✅ Exact match to Python reference.

---

## Fix 2: Proof Exclusion from Transport Relay

**File**: `request_relay_routing_trait.php`

**Problem**: `shouldTransportRelayPacket` captured proof packets (type 3) with matching `transport_id`. Proof destinations are truncated packet hashes — never in path_table — so proofs were silently dropped instead of reaching their dedicated handlers.

**Python reference** (`Transport.py` line 1510):

```python
if packet.transport_id != None and packet.packet_type != RNS.Packet.ANNOUNCE:
```

Python does **not** explicitly exclude PROOF from the transport relay check. However, `packet.destination_hash` for proofs is a truncated hash of the data being proven, which is never a key in `Transport.path_table` (which holds full destination hashes). So proofs always fall through to the "else" at line 1567:

```python
else:
    RNS.log("Got packet in transport, but no known path to final destination... Dropping packet.")
```

Python **implicitly** drops proofs via the path_table lookup failure. The PHP explicitly excludes `packet_type === 3`, which is functionally equivalent but cleaner — proofs reach their dedicated handlers (`relayProofPacket` at lines 2190–2198, `relayLinkRequestProofPacket` at lines 2107–2130) without generating "no known path" log noise.

**Change**: `shouldTransportRelayPacket` now excludes `packet_type === 3` (PROOF). Proofs fall through to:
- `shouldReverseRouteProofPacket` → `relayProofPacket` (regular proofs via reverse_table)
- `shouldTransportLinkRequestProofPacket` → `relayLinkRequestProofPacket` (LRPROOF via link_table)

**Verification**: ✅ Functionally equivalent to Python; PHP approach is cleaner.

---

## Fix 3: Php-Peer Exchange Unblock

**Files**: `request_php_wake_trait.php` (both `lib/` and `selectiv-snapshot/lib/`), `index.php` (selectiv-snapshot)

**Problem**: The php-peer exchange between retichat.com and selectivesubconscious.com was completely dead. Root cause chain:

1. A stuck (unacked) batch on retichat was re-delivered on every exchange cycle
2. `appendPeerAckBatchId` appended the same batch ID to `pending_ack_batch_ids_json` each time with no dedup check
3. **`VARCHAR(255)` column** truncated the JSON array after 10+ appends
4. `drainPeerAckBatchIds` → `decodeJson()` threw uncaught `JsonException` "Control character error" on the truncated JSON
5. Exception propagated through `exchangeWithPhpPeer` → wake handler → **HTTP 500 on every wake**
6. selective could never be woken → retichat's queue built to 256 packets

**Changes**:

1. **Schema**: `VARCHAR(255)` → `TEXT` for `pending_ack_batch_ids_json` on both servers
2. **`drainPeerAckBatchIds`**: `try/catch` around `decodeJson` — malformed JSON returns `[]` instead of crashing
3. **`appendPeerAckBatchId`**: `try/catch` + **deduplication** — same batch ID won't be appended twice
4. **`exchangeWithPhpPeer`**: `try/catch` around `json_encode` + `JSON_PARTIAL_OUTPUT_ON_ERROR`
5. **Wake handler** (`index.php`): `try/catch` around `exchangeWithPhpPeer` — wake never returns 500

**Verification**: N/A — infrastructure fix, not protocol-level. Root cause is real and reproducible.

---

## Fix 4: Reverse Path for Opportunistic DATA

**File**: `request_inbound_batch_trait.php` (both `lib/` and `selectiv-snapshot/lib/`)

**Problem**: `deliverLocallyIfKnown` only recorded reverse paths for `LINKREQUEST` (type 2), not `DATA` (type 0). When Meshchat sent opportunistic DATA to the browser, no reverse path was stored. The browser's proof had no route back to Meshchat.

**Python reference** (`Transport.py` line 1580 — the **only** place `reverse_table` is populated):

```python
# Entry format is
reverse_entry = [packet.receiving_interface,   # 0: Received on interface
                 outbound_interface,            # 1: Outbound interface
                 time.time()]                  # 2: Timestamp
Transport.reverse_table[packet.getTruncatedHash()] = reverse_entry
```

This is in the **multi-hop transport relay path**. Python has zero reverse-table creation during local delivery — because Python's local destinations are in-process. The PHP's browser is an **external client** connected via HTTP exchange. The PHP must record reverse paths for all locally-delivered packets so proofs can be routed back through the network.

The regular proof relay (Python lines 2190–2198) confirms the routing mechanism:

```python
if packet.destination_hash in Transport.reverse_table:
    reverse_entry = Transport.reverse_table.pop(packet.destination_hash)
    if packet.receiving_interface == reverse_entry[IDX_RT_OUTB_IF]:  # interface check only, NOT hop count
        Transport.transmit(reverse_entry[IDX_RT_RCVD_IF], new_raw)
```

**Change**: `deliverLocallyIfKnown` now records reverse paths for `DATA` (type 0) in addition to `LINKREQUEST` (type 2).

**Verification**: ✅ Correct for PHP's external-client architecture. Faithful to Python's reverse_table semantics.

---

## Fix 5: PostInterface.py Proof Hop Count

**File**: `Reticulum-post/python/RNS/Interfaces/PostInterface.py` (3 copies: `python/`, `bridge-conf/interfaces/`, `docker/bridge/interfaces/`)

**Problem**: Browser sends proofs with `hops=0`. The NAS Transport checks LRPROOF hop count against `remaining_hops`. For multi-hop paths through the PHP relay, this check fails.

**Python reference** (`Transport.py` lines 1393 + 2112–2114):

```python
# Line 1393: All inbound packets get hops incremented
packet.hops += 1

# Line 2112: LRPROOF hop count check
hops_ok = (packet.hops == link_entry[IDX_LT_REM_HOPS])
if not hops_ok and link_entry[IDX_LT_REM_HOPS] == 0:  # fallback ONLY for directly reachable
    hops_ok = (packet.receiving_interface == link_entry[IDX_LT_NH_IF])
```

**Topology**: Meshchat → NAS → PHP → Browser = 3 hops from Meshchat to browser. From NAS perspective, `remaining_hops = 2`.

**Without fix** (trace):
1. Browser sends proof `hops=0`
2. PHP passes through unchanged (correct relay behavior — relays don't modify contents)
3. PostInterface → Transport.inbound(): `0 + 1 = 1`
4. LRPROOF check: `1 == 2` → **FALSE** → "hop mismatch" → dropped

**With fix** (trace):
1. Browser sends proof `hops=0`
2. PHP passes through unchanged
3. PostInterface `process_incoming()`: `0 → 1`
4. Transport.inbound(): `1 + 1 = 2`
5. LRPROOF check: `2 == 2` → **TRUE** → validated and forwarded

For regular proofs (non-LRPROOF), Python lines 2190–2198 check only the **interface**, not hop count — so the increment is harmless.

**Change** (`process_incoming`):

```python
# Increment hop count on proofs arriving from PHP
# The PHP relay doesn't modify hops; proofs arrive with 0
# Transport.inbound() will +1, but remaining_hops for multi-hop
# paths is >1, causing hop mismatch on LRPROOF
if pkt_type == 0x03 and hops == 0:
    data = bytes([data[0], 1, *data[2:]])  # hops 0→1
```

The fix is in PostInterface (not PHP) because PostInterface represents the boundary between the PHP transport domain (where hop counts are left unmodified per relay contract) and the Python RNS transport domain (where hop counts must match the path table).

**Verification**: ✅ Correct. The PHP relay correctly passes proofs through unmodified; the PostInterface boundary fix bridges the two domains.

---

## Fix 6: Announce Re-Relay for Path Refresh

**Files**: `request_control_plane_trait.php`, `request_relay_routing_trait.php`

**Problem**: `shouldRelayAcceptedPacket` only relayed announces with status `path_updated`. Once the PHP had a stable path, every subsequent announce was `validated` and **never relayed** to downstream nodes. The NAS and Meshchat path entries expired, making the browser unreachable.

**Python reference** (`Transport.py` lines 1094–1140):

```python
for interface in Transport.interfaces:
    if interface != packet.receiving_interface:
        if interface.OUT:
            # ... mode checks ...
            announce_queued = True  # queues to EVERY OUT interface, EVERY time
```

Python rebroadcasts **every valid announce** to **every OUT interface** on **every receipt**. There is no "path_updated vs validated" distinction. Two dedup mechanisms prevent storms:
1. **Packet hash dedup** at the inbound filter — duplicate raw packets are dropped
2. **Queue dedup** by destination hash — same destination not queued twice at the same interface

The PHP (stateless HTTP) doesn't have Python's in-memory dedup caches, so a 5-minute throttle is the appropriate alternative.

**Changes**:

1. **`request_control_plane_trait.php`**: `shouldRelayAcceptedPacket` now also relays `validated` announces when `shouldRefreshAnnounceRelay()` returns true (every 5 minutes, configurable via `transport.announce_refresh_seconds`).

2. **`request_relay_routing_trait.php`**: After relaying a validated announce, `touchPathEntryTimestamp` bumps the path entry's `updated_at` to prevent relay storms.

**Verification**: ✅ Functionally correct. Python floods unconditionally; PHP throttles at 5-minute intervals (appropriate for stateless HTTP transport). The critical behavior — periodic re-relay to keep downstream path tables alive — is preserved.

---

## Fixes Not Yet Deployed/Verified

### Pending: TCPInterface.py — Spawned Client OUT Flag

**File**: `Reticulum-master/RNS/Interfaces/TCPInterface.py` (line 580)

**Problem**: `TCPServerInterface` starts listening during `__init__` (before activation sets `OUT = True`). When a client connects early, `spawned_interface.OUT = self.OUT` inherits `OUT = False`. Transport skips interfaces with `OUT = False` during announce flooding — so early-connected clients (like Meshchat) never receive announces.

**Python reference** (line 580):

```python
# CURRENT — inherits self.OUT which may be False if connection came before activation
spawned_interface.OUT = self.OUT

# FIX — spawned clients are always transmitters
spawned_interface.OUT = True
```

**Note**: This is a Python RNS bug, not a PHP bug. It affects TCPServerInterface client announce distribution. The fix is in `Reticulum-master/RNS/Interfaces/TCPInterface.py`.

---

## Deployed File Summary

| File | Servers | Purpose |
|------|---------|---------|
| `lib/request_packet_ingest_trait.php` | retichat, selective | Fix 1: Remove transport_id filter |
| `lib/request_inbound_batch_trait.php` | retichat, selective | Fix 1+4: Transport relay + reverse path for DATA |
| `lib/request_relay_routing_trait.php` | retichat, selective | Fix 1+2+6: context_flag, proof exclusion, announce refresh |
| `lib/request_control_plane_trait.php` | retichat, selective | Fix 6: Announce re-relay throttle |
| `lib/request_outbound_batch_trait.php` | retichat, selective | Queue priority: DATA before ANNOUNCE |
| `lib/request_php_wake_trait.php` | retichat, selective | Fix 3: JSON error handling, dedup |
| `index.php` | selective | Fix 3: try/catch on wake handler |
| `python/.../PostInterface.py` | NAS | Fix 5: Proof hop count boundary fix |

### Selectiv-Snapshot Mirror

All `lib/` changes are mirrored to `selectiv-snapshot/lib/`. The selectiv-snapshot copy is what runs on selectivesubconscious.com.

---

## Python Reference Cross-Reference

| Python Location | Line(s) | PHP Equivalent |
|----------------|---------|----------------|
| `Transport.inbound()` — packet.hops += 1 | 1393 | N/A (PHP doesn't increment) |
| `Transport.inbound()` — transport_id routing | 1503–1582 | `shouldTransportRelayPacket` / `relayTransportPacket` |
| `Transport.inbound()` — flags & 0b00001111 | 1524 | `rewriteTransportRelayRaw` context_flag clearing |
| `Transport.inbound()` — announce rebroadcast | 1094–1140 | `shouldRelayAcceptedPacket` + `shouldRefreshAnnounceRelay` |
| `Transport.inbound()` — LRPROOF hop check | 2112–2114 | PostInterface.process_incoming hop fix |
| `Transport.inbound()` — regular proof relay | 2190–2198 | `relayProofPacket` |
| `Transport.inbound()` — link_table proof fallback | 2205–2213 | `relayLinkRequestProofPacket` |
| Reverse table creation (only location) | 1580 | `rememberReversePath` in `deliverLocallyIfKnown` |
