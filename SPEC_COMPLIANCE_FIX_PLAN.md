# Reticulum-Post — Spec Compliance Fix Plan

> Based on: `PHP_TRANSPORT_SPEC_AUDIT.md` (Leviculum spec audit, 2026-07-13)  
> Files to patch: `php/src/index.php`, `php/src/lib/request_relay_routing_trait.php`  
> Mirror files: `php/src/selectiv-snapshot/index.php`, `php/src/selectiv-snapshot/lib/request_relay_routing_trait.php`

---

## Fix #1 🔴→✅ HEADER_2 hashable part omits transport_id

**Severity:** Medium | **Files:** `index.php` (PacketParser), `request_relay_routing_trait.php` (`linkIdHex`)

### Root cause

`PacketParser::hashablePart()` and `linkIdHex()` both use `substr($raw, 18)` for HEADER_2, which starts at the destination_hash, skipping the 16-byte transport_id. The spec hashable part for HEADER_2 is `masked_flags || raw[2:]` which includes the transport_id.

### Fix (4 locations — 2 files × 2 mirrors)

**File A: `php/src/index.php` line ~848** — `PacketParser::hashablePart()`

```php
// BEFORE:
if ($headerType === self::HEADER_2) {
    return $hashablePart . substr($raw, self::DST_LEN + 2);
}

// AFTER:
if ($headerType === self::HEADER_2) {
    return $hashablePart . substr($raw, 2);
}
```

**File B: `php/src/lib/request_relay_routing_trait.php` line ~768** — `linkIdHex()`

```php
// BEFORE:
if ((int) ($packet['header_type'] ?? 0) === 1) {
    $hashablePart .= substr($raw, 18);

// AFTER:
if ((int) ($packet['header_type'] ?? 0) === 1) {
    $hashablePart .= substr($raw, 2);
```

**Mirrors:** Same changes in `php/src/selectiv-snapshot/index.php` and `php/src/selectiv-snapshot/lib/request_relay_routing_trait.php`.

### Impact

- `packet_hash` changes for HEADER_2 packets. This is used only for local dedup — no wire impact.
- `truncated_hash_hex` changes. Reverse path entries stored before the fix will become stale, but they have a TTL (default 480s) and will expire naturally.
- `linkIdHex` will now compute the correct hash including transport_id. This is needed for Fix #4.

---

## Fix #2 ℹ️ Path request tag uses 8 random bytes instead of 10

**Severity:** Low | **File:** `request_relay_routing_trait.php`

### Root cause

`queueRelayPathRequestIfNeeded()` uses `random_bytes(8)` for the request tag. Python's reference uses `get_random_hash()` = 10 bytes (5 random + 5-byte big-endian timestamp). The tag format is informative (not normative), but matching the Python format improves interop and lets receivers extract the timestamp.

### Fix (2 locations — 1 file × 2 mirrors)

**File: `php/src/lib/request_relay_routing_trait.php` line ~472**

```php
// BEFORE:
$payload = $destinationHash . random_bytes(8);

// AFTER:
// Match Python's get_random_hash(): 5 random bytes + 5-byte big-endian Unix timestamp.
// The timestamp lets receivers age-out stale requests.
$tag = random_bytes(5) . substr(pack('J', time()), 3, 5);
$payload = $destinationHash . $tag;
```

### Impact

- Payload grows from 24 to 26 bytes. The receiving `processAcceptedPathRequest` handles variable-length tags correctly (it already checks `strlen($payload) > 16` and `> 32`).
- No wire compatibility issue — the tag is opaque to receivers.

---

## Fix #3 ℹ️ Missing transport identity in relay path requests

**Severity:** Low | **File:** `request_relay_routing_trait.php`

### Root cause

`queueRelayPathRequestIfNeeded()` does not include the node's transport_identity_hash in the path request payload. The spec says it's included "when transport is enabled on the requesting node." Including it lets the responder route the path response back through the correct transport path.

### Fix (2 locations — 1 file × 2 mirrors)

**File: `php/src/lib/request_relay_routing_trait.php` line ~472-473**

```php
// BEFORE:
$payload = $destinationHash . random_bytes(8);
$raw = chr(0x08) . chr(0x00) . $controlHash . chr(0x00) . $payload;

// AFTER:
$transportIdentity = hex2bin($this->transportIdentityHashHex());
if (!is_string($transportIdentity) || strlen($transportIdentity) !== 16) {
    throw new RuntimeException('Transport identity hash must be 16 bytes');
}
$tag = random_bytes(5) . substr(pack('J', time()), 3, 5);
$payload = $destinationHash . $transportIdentity . $tag;
$raw = chr(0x08) . chr(0x00) . $controlHash . chr(0x00) . $payload;
```

### Impact

- Payload grows from 24→26 bytes to 42 bytes (16 target + 16 transport_id + 10 tag).
- `processAcceptedPathRequest` already handles `strlen($payload) > 32` (with transport identity) and `strlen($payload) > 16` (without). ✅
- The PHP's transport identity is a random 16-byte value (not derived from keys). This is OK per spec (informative section).

### Note

This fix is optional. The spec marks transport_identity_hash as optional. If the current behavior works in the existing ecosystem, this can be deferred. Apply it if you observe path responses not being routed back correctly.

---

## Fix #4 🔴 Link ID stored as destination_hash instead of true link_id

**Severity:** High | **File:** `request_relay_routing_trait.php`

### Root cause

`rememberLinkTransportRelay()` uses the LINKREQUEST packet's `destination_hash` as the link transport entry key. Per spec §7, the link_id is `truncated_hash(hashable_part_of_LINKREQUEST)` after stripping signalling bytes — a different value from the destination_hash. When the LRPROOF returns addressed to the true link_id, the lookup fails.

The correctly-implemented `linkIdHex()` function already exists in the file but is **never called**.

### Fix (2 locations — 1 file × 2 mirrors)

**File: `php/src/lib/request_relay_routing_trait.php` lines ~520-525**

```php
// BEFORE:
// Use the LINKREQUEST destination hash directly as the link ID.
// The returning LRPROOF carries this same hash as its destination.
$linkIdHex = $destinationHashHex;

// AFTER:
// Compute the spec link_id: truncated_hash of the LINKREQUEST hashable part
// with signalling bytes stripped (§7). The returning LRPROOF is addressed
// to this value, so the lookup in relayLinkRequestProofPacket will match.
$linkIdHex = $this->linkIdHex($rawBase64, $packet);
if ($linkIdHex === null || $linkIdHex === '') {
    // Fallback for malformed packets: use destination_hash.
    $linkIdHex = $destinationHashHex;
}
```

### Impact

- Link transport entries are now keyed by the spec-compliant link_id.
- `relayLinkRequestProofPacket` looks up LRPROOF by its `destination_hash_hex` (which IS the link_id per spec), so it will now find the entry. ✅
- `relayLinkTransportPacket` also uses the link_id for lookup — it will find entries for subsequent link packets (RTT, data, close). ✅
- The fallback to `$destinationHashHex` handles edge cases where `linkIdHex()` returns null (malformed packets).

### Dependency

This fix depends on Fix #1 being applied to `linkIdHex()` first. Without Fix #1, `linkIdHex()` has the HEADER_2 transport_id omission bug, which would produce incorrect link_ids for HEADER_2 LINKREQUEST packets (rare, but possible if a LINKREQUEST arrives via transport relay).

---

## Fix #5 🔴 LRPROOF validation uses wrong key + transport should not validate

**Severity:** High | **File:** `request_relay_routing_trait.php`

### Root cause

`relayLinkRequestProofPacket()` calls `validateLinkRequestProof()` which:
1. Uses the destination's **static** Ed25519 key to verify a signature that covers the responder's **ephemeral** Ed25519 key (which the transport relay doesn't have).
2. A transport relay should not cryptographically validate link proofs — that's the initiator's responsibility per spec §7. The Python reference transport routes LRPROOF by table lookup only.

### Fix (2 locations — 1 file × 2 mirrors)

**File: `php/src/lib/request_relay_routing_trait.php` lines ~630-633**

Remove the validation block:

```php
// BEFORE:
if (!$this->validateLinkRequestProof($packet, $linkEntry)) {
    return 0;
}

// AFTER:
// Transport relays route LRPROOF by link transport table, not by
// cryptographic validation. Link proof validation is the link initiator's
// responsibility per spec §7. The relaxed hop check above provides
// sufficient routing integrity for the relay.
```

### Impact

- LRPROOF packets from spec-compliant Python nodes will now be relayed (instead of dropped).
- The hop check (`observedHops` vs `expectedHops`) still prevents obviously-wrong routing.
- The `validateLinkRequestProof` function can be kept (it's not called from anywhere else) or removed. Keeping it is harmless.

### Security note

An attacker who knows a link_id could potentially spoof an LRPROOF and get it relayed. However:
1. Link IDs are 16-byte cryptographic hashes (unguessable).
2. The attacker must also route through the correct interface.
3. The Python reference transport also does not validate link proofs at the relay layer.
4. The endpoints (initiator/responder) perform their own cryptographic validation.

---

## Fix #6 ℹ️ Proof hop count not incremented (documented workaround)

**Severity:** Low | **File:** `request_relay_routing_trait.php`

### Status: No change needed

The `proofRelayPacketBase64()` function deliberately does not increment the hop count, with a documented rationale: "The proof carries the hop count set by the responder. The NAS Transport must accept proofs arriving on the correct interface regardless of hop count."

This is an intentional deviation with a valid reason. Leave as-is unless testing shows problems with Python peer interop.

---

## Implementation Order

| Order | Fix | Depends On | Risk |
|-------|-----|------------|------|
| 1 | #1 — HEADER_2 hashable part | — | Low |
| 2 | #4 — Link ID keying | #1 (linkIdHex fix) | Medium |
| 3 | #5 — Remove LRPROOF validation | #4 (so entries can be found) | Medium |
| 4 | #2 — Path request tag format | — | Low |
| 5 | #3 — Transport identity in path requests | — | Low |
| — | #6 — Proof hop count | — | No change |

**Recommended:** Apply #1, #4, and #5 together in one deployment since they form a connected chain for link relay. Apply #2 and #3 separately as low-risk improvements.

## Files Summary

```
php/src/index.php                              — Fix #1 (PacketParser::hashablePart)
php/src/lib/request_relay_routing_trait.php    — Fix #1 (linkIdHex), #2, #3, #4, #5
php/src/selectiv-snapshot/index.php            — Fix #1 (mirror)
php/src/selectiv-snapshot/lib/...trait.php     — Fix #1-#5 (mirror)
```
