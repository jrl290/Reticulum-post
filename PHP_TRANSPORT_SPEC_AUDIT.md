# Reticulum-Post PHP Transport Node — Leviculum Spec Audit

> **Audited against:** [Leviculum Reticulum Protocol Specification](https://lew-palm.de/reticulum/appendix/reticulum-specification.html) (RNS 1.3.5, commit `d5e62d4`)  
> **Date:** 2026-07-13  
> **Scope:** `Reticulum-post/php/src/`  
> **Key files:** `index.php` (PacketParser, AnnounceValidator, IfacCodec), `lib/request_*.php` (traits)

---

## Summary

| Section | Status | Issues Found |
|---------|--------|--------------|
| §5 Packet Format | ⚠️ Minor deviation | 1 (hashable part for HEADER_2 omits transport_id) |
| §6 Announce | ✅ Passes | 0 |
| §9 Transport / Path Request | ⚠️ Minor deviation | 2 (path request tag length, missing transport identity) |
| §7 Link | 🔴 Significant | 3 (link_id confusion, proof validation, link transport keying) |
| §10 IFAC / Framing | ✅ Passes | 0 |
| §3-4 Identity / Destination | ✅ Passes | 0 |
| §2 Cryptography | ✅ Passes | 0 |

---

## §5 — Packet Format

### Header Bitfield Parsing (`PacketParser::parseRaw`)

**File:** `php/src/index.php:784-842`

The bitfield is parsed as:

```php
$headerType     = ($flags & 0b01000000) >> 6;  // bit 6
$contextFlag    = ($flags & 0b00100000) >> 5;  // bit 5
$transportType  = ($flags & 0b00010000) >> 4;  // bit 4
$destinationType= ($flags & 0b00001100) >> 2;  // bits 3-2
$packetType     = ($flags & 0b00000011);       // bits 1-0
```

This exactly matches the spec:
```
bit 7   IFAC flag         (cleared by IfacCodec before PacketParser sees it)
bit 6   header type       0=HEADER_1, 1=HEADER_2
bit 5   context flag
bit 4   transport type    0=BROADCAST, 1=TRANSPORT
bits 3-2 destination type 00=SINGLE, 01=GROUP, 10=PLAIN, 11=LINK
bits 1-0 packet type      00=DATA, 01=ANNOUNCE, 10=LINKREQUEST, 11=PROOF
```

✅ **PASS** — Correct.

### HEADER_1 / HEADER_2 Layout

```php
private const HEADER_1 = 0;
private const HEADER_2 = 1;
private const DST_LEN = 16;           // matches spec's 16-byte hash
private const HEADER_1_LEN = 19;      // matches spec (1+1+16+1 = 19)
private const HEADER_2_LEN = 35;      // matches spec (1+1+16+16+1 = 35)
```

HEADER_1 extraction: `$destinationHash = substr($raw, 2, 16); $context = ord($raw[18]); $payload = substr($raw, 19);`  
HEADER_2 extraction: `$transportId = substr($raw, 2, 16); $destinationHash = substr($raw, 18, 16); $context = ord($raw[34]); $payload = substr($raw, 35);`

✅ **PASS** — Correct for both header types.

### ⚠️ ISSUE #1: Hashable Part Omits `transport_id` for HEADER_2

**File:** `php/src/index.php:844-853`

```php
private static function hashablePart(string $raw, int $headerType, int $flags): string
{
    $hashablePart = chr($flags & 0b00001111);  // masked flags (bits 3-0)
    if ($headerType === self::HEADER_2) {
        return $hashablePart . substr($raw, self::DST_LEN + 2);  // offset 18
    }
    return $hashablePart . substr($raw, 2);  // offset 2
}
```

| Header type | PHP hashable part | Spec hashable part | Match? |
|-------------|-------------------|-------------------|--------|
| HEADER_1 | `masked_flags ‖ raw[2:]` = `flags ‖ dest_hash ‖ ctx ‖ data` | `masked_flags ‖ raw[2:]` | ✅ |
| HEADER_2 | `masked_flags ‖ raw[18:]` = `flags ‖ dest_hash ‖ ctx ‖ data` | `masked_flags ‖ raw[2:]` = `flags ‖ transport_id ‖ dest_hash ‖ ctx ‖ data` | ❌ |

**The PHP omits the 16-byte `transport_id` from the HEADER_2 hashable part.**

**Impact:** The `packet_hash` (SHA-256 of hashable part) is used for deduplication in `packetHashExists()`. Two identical packets relayed through different transport paths (different `transport_id`) would hash to the same value, causing the second to be incorrectly rejected as a duplicate. The `truncated_hash_hex` would also differ from Python's value.

**Severity:** Low-Medium. In practice, the same packet traveling through two different transport paths simultaneously is rare. But it's a spec deviation that could cause dropped packets in multi-path topologies.

**Fix:** Change `substr($raw, self::DST_LEN + 2)` to `substr($raw, 2)` for HEADER_2.

---

## §6 — Announce

### Announce Data Layout (`AnnounceValidator::validate`)

**File:** `php/src/index.php:1000-1090`

Parses the announce payload as:
```
public_key(64) || name_hash(10) || random_hash(10) || [ratchet(32)] || signature(64) || app_data
```

✅ **PASS** — Matches spec exactly. Ratchet included only when `context_flag === 1`.

### Destination Hash Re-computation

```php
$identityHash = substr(hash('sha256', $publicKey, true), 0, 16);
$expectedHash = substr(hash('sha256', $nameHash . $identityHash, true), 0, 16);
```

This is: `truncated_hash(name_hash || identity_hash)` where `identity_hash = truncated_hash(X25519_pub || Ed25519_pub)`.

✅ **PASS** — Matches spec. `$publicKey` is 64 bytes (X25519 ‖ Ed25519), so SHA-256 of that truncated to 16 gives the correct identity_hash.

### Signed Data Construction

```php
$signedData = $destinationHash . $publicKey . $nameHash . $randomHash . $ratchet . $appData;
```

Order: `destination_hash ‖ public_key ‖ name_hash ‖ random_hash ‖ [ratchet] ‖ app_data`

✅ **PASS** — Matches spec exactly. `destination_hash` is signed but not transmitted (recomputed by receiver). When `$ratchet = ''` (no ratchet), concatenating an empty string is a no-op.

### Signature Verification

```php
$ed25519PublicKey = substr($publicKey, 32, 32);  // last 32 of 64 = Ed25519 pub
sodium_crypto_sign_verify_detached($signature, $signedData, $ed25519PublicKey);
```

✅ **PASS** — Correctly extracts Ed25519 public key (bytes 32-63 of the 64-byte combined key) and verifies detached signature.

### Random Hash Timestamp Extraction

```php
private static function announceEmitted(string $randomHash): int
{
    $timestampBytes = substr($randomHash, 5, 5);
    return unpack('J', "\x00\x00\x00" . $timestampBytes)[1];
}
```

Extracts 5-byte big-endian timestamp from bytes 5-9 of random_hash. The spec says `random_hash = random(5) || timestamp(5)`. This is correct.

✅ **PASS**

---

## §9 — Transport / Path Request

### Path Request Control Hash

**File:** `php/src/lib/request_path_state_trait.php:113-119`

```php
private function pathRequestControlHashHex(): string
{
    $expanded = 'rnstransport.path.request';
    $nameHash = substr(hash('sha256', $expanded, true), 0, 10);
    return bin2hex(substr(hash('sha256', $nameHash, true), 0, 16));
}
```

This computes: `truncated_hash(name_hash)` where `name_hash = full_hash("rnstransport.path.request")[:10]`.

The spec says path requests go to the PLAIN destination `rnstransport.path.request`. For PLAIN destinations, the destination hash is `truncated_hash(name_hash)` (no identity). ✅ **PASS**

### Path Request Payload Parsing

**File:** `php/src/lib/request_control_plane_trait.php:46-65`

```php
$destinationHashHex = bin2hex(substr($payload, 0, 16));     // target(16)
// Optionally: transport_identity_hash(16) then request_tag
```

Matches spec: `target_destination_hash(16) || [transport_identity_hash(16)] || request_tag`. ✅ **PASS**

### ⚠️ ISSUE #2: Path Request Tag Length

**File:** `php/src/lib/request_relay_routing_trait.php:470`

When the PHP generates relay path requests:
```php
$payload = $destinationHash . random_bytes(8);  // 16 + 8 = 24 bytes
```

The spec says the `request_tag` is a "random hash." Python uses `get_random_hash()` = 10 bytes (5 random + 5 timestamp). PHP uses 8 random bytes.

**Impact:** Low. The tag only needs to be unique for deduplication. 8 random bytes (64 bits) provides sufficient uniqueness.

**Severity:** Informative deviation — tag format is not standardized in the spec.

### ⚠️ ISSUE #3: Missing Transport Identity in Relay Path Requests

When the PHP forwards a path request, it does NOT include its `transport_identity_hash` in the payload. The spec says this is included "only when transport is enabled on the requesting node." The PHP transport node doesn't function as a full transport node (request-operated model), so omitting this is arguably correct.

**Severity:** Low. May affect how Python peers route path responses back.

### Path Response Construction

**File:** `php/src/lib/request_path_state_trait.php:162-182`

```php
private function buildPathResponsePacket(string $announceRaw, string $destinationHashHex, int $hops): string
{
    // newFlags: context_flag preserved, header_type=1 (HEADER_2), transport_type=1 (TRANSPORT)
    $newFlags = ($originalFlags & 0x20) | 0x40 | 0x10 | ($originalFlags & 0x0F);
    // ... HEADER_2 layout with transport_identity, destination_hash, context=0x0B (PATH_RESPONSE)
    return chr($newFlags) . chr($boundedHops) . $transportIdentity . $destinationHash . chr(0x0B) . $announcePayload;
}
```

Creates a HEADER_2 packet with context `0x0B` (PATH_RESPONSE), containing the original announce data. This matches the spec: "A node that holds a path answers by re-emitting the destination's cached announce with the packet context set to PATH_RESPONSE."

✅ **PASS**

---

## §7 — Link

### 🔴 ISSUE #4: Link ID Confusion — Destination Hash vs. True Link ID

**File:** `php/src/lib/request_relay_routing_trait.php:514-540`

In `rememberLinkTransportRelay`:
```php
$linkIdHex = $destinationHashHex;  // Uses LINKREQUEST's destination_hash as link_id
```

**The spec says** the link_id is `truncated_hash(hashable_part)` of the LINKREQUEST (after stripping signalling bytes), which is a **different value** from the destination_hash.

The destination_hash on a LINKREQUEST is the hash of the *target destination*. The link_id is the hash of the *LINKREQUEST packet itself*. These are completely independent values.

**Impact:** When the PHP relays a LINKREQUEST and stores a link transport entry keyed by `destination_hash`, and the responder returns an LRPROOF with `destination_hash = link_id` (per spec), the PHP cannot find the link transport entry because:

- Stored key: LINKREQUEST's `destination_hash` (e.g., hash of "some_app.some_aspect")
- Lookup key: LRPROOF's `destination_hash` (the spec-compliant `link_id`)

**The fallback** attempts reverse-path routing via `relayProofPacket`, which uses `truncated_hash_hex` as the key. But the PHP's `truncated_hash_hex` includes signalling bytes in the hash, while the spec `link_id` excludes them — so this fallback ALSO fails for spec-compliant LRPROOFs.

**However**, a `linkIdHex()` function IS defined at line 778+ that correctly computes the spec link_id (stripping signalling bytes). It appears to be **unused** — it's defined but never called in the code paths I traced. If it were used in `rememberLinkTransportRelay` instead of `$destinationHashHex`, the link transport lookup would work correctly.

**Severity:** High for interop with spec-compliant Python nodes. May work in practice if the ecosystem (rns-js, other PHP nodes) uses the same non-spec convention of link_id ≈ destination_hash.

**Fix:** Use `linkIdHex()` in `rememberLinkTransportRelay` instead of `$destinationHashHex`.

### 🔴 ISSUE #5: Link Request Proof Validation Uses Wrong Key

**File:** `php/src/lib/request_relay_routing_trait.php:813-835`

```php
private function validateLinkRequestProof(array $packet, array $linkEntry): bool
{
    $publicKeyHex = $this->knownDestinationPublicKey(...);  // destination's static key
    $publicKey = hex2bin($publicKeyHex);                     // 64 bytes
    $signature = substr($payload, 0, 64);
    $peerPublicKey = substr($payload, 64, 32);              // eph_X25519 from LRPROOF
    $signallingBytes = substr($payload, 96);
    $ed25519PublicKey = substr($publicKey, 32, 32);         // DESTINATION'S STATIC Ed25519
    
    return sodium_crypto_sign_verify_detached(
        $signature,
        $linkId . $peerPublicKey . $ed25519PublicKey . $signallingBytes,
        $ed25519PublicKey  // verifying against DESTINATION static key
    );
}
```

**Problems:**

1. **Signed data reconstruction is wrong.** The spec says the signed data is:
   ```
   link_id || responder_eph_X25519_pub || responder_eph_Ed25519_pub || signalling
   ```
   The PHP uses `$ed25519PublicKey` = destination's **static** Ed25519 key, not the responder's **ephemeral** Ed25519 key (which was sent in the original LINKREQUEST). The transport relay doesn't have access to the LINKREQUEST payload, so it cannot reconstruct the signed data correctly.

2. **A transport relay should not be cryptographically validating LRPROOFs.** Per the spec, link proof validation is the initiator's job, not the transport's. A transport node routes by next-hop tables, not by validating signatures it doesn't have the keys for.

**Impact:** LRPROOF packets from spec-compliant Python nodes will fail validation and be dropped by the PHP transport relay. Link establishment through the PHP node will fail.

**Severity:** High. Blocks link establishment across the PHP transport for spec-compliant peers.

**Fix:** Remove cryptographic validation from the transport relay path for LRPROOF. Route by link transport entry lookup only (once issue #4 is fixed). Optionally validate that the packet structure is well-formed (correct lengths), but skip signature verification.

### ⚠️ ISSUE #6: proofRelayPacketBase64 Does Not Increment Hops

**File:** `php/src/lib/request_relay_routing_trait.php:68-79`

```php
private function proofRelayPacketBase64(string $rawBase64, array $packet): string
{
    // Do NOT increment the hop count for proofs.
    return $rawBase64;
}
```

The comment explains the rationale (proof hop count set by responder, NAS must accept regardless). This is an intentional deviation with a documented reason.

**Severity:** Low. Documented workaround. The spec doesn't explicitly require hop increment on proof relay, but standard RNS behavior is to increment hops on all relayed packets.

---

## §10 — IFAC / Framing

### IFAC Unwrap (`IfacCodec::unwrapForInterface`)

**File:** `php/src/index.php:880-930`

1. Checks IFAC flag (bit 7 of byte 0) ✅
2. Extracts ifac tag from bytes 2..(2+ifacSize-1) ✅
3. Computes HKDF mask: `hash_hkdf('sha256', $ifac, $length, '', $ifacKey)` — matches `hkdf(len, derive_from=ifac, salt=ifac_key, context=None)` ✅
4. Unmasks all bytes EXCEPT the tag bytes (indices 2..ifacSize+1) ✅
5. Clears IFAC flag (bit 7) on normalized raw ✅
6. Verifies tag: `substr(signature($normalizedRaw, $ifacKey), -$ifacSize)` vs extracted tag ✅

### IFAC Wrap (`IfacCodec::wrapForInterface`)

1. Sets IFAC flag (bit 7) on byte 0 ✅
2. Computes Ed25519 signature of raw → last ifacSize bytes = tag ✅
3. HKDF mask over (len(raw) + ifacSize) ✅
4. Inserts tag after header bytes (offset 2) ✅
5. XOR masks everything EXCEPT tag bytes ✅
6. Bit 7 always set in masked byte 0 ✅

✅ **PASS** — The IFAC implementation matches the spec exactly. The HKDF derivation, masking pattern (tag bytes left unmasked), signature verification, and bit 7 handling are all correct.

### HDLC Framing

Not implemented in PHP (the PHP node communicates via HTTP/JSON, not raw byte streams). HDLC is handled by the interface layer (Python rnsd, browser rns-js).

**N/A** — Not applicable to this implementation.

---

## §3-4 — Identity / Destination

### Identity Hash Computation

The `AnnounceValidator` computes identity_hash as `SHA-256(public_key_64_bytes)[:16]`, which is `truncated_hash(X25519_pub || Ed25519_pub)`. ✅

### Destination Hash Computation

For announces: `truncated_hash(name_hash || identity_hash)` ✅  
For PLAIN (path request): `truncated_hash(name_hash)` (no identity) ✅

### Transport Identity

**File:** `php/src/lib/request_interface_runtime_trait.php:20-38`

The PHP generates a random 16-byte transport identity hash (`random_bytes(16)`), not derived from any key material. The spec describes transport identity as a full RNS Identity with X25519+Ed25519 keys, but this is in the **informative** section — an implementation MAY diverge.

**Severity:** Informative deviation. The transport identity is used only for HEADER_2 transport_id matching within the PHP ecosystem. It cannot be cryptographically proven to peers.

---

## §2 — Cryptographic Primitives

| Primitive | PHP Implementation | Spec | Match? |
|-----------|-------------------|------|--------|
| SHA-256 | `hash('sha256', ..., true)` | SHA-256 | ✅ |
| Truncated hash | `substr(hash(...), 0, 16)` | Leading 16 bytes | ✅ |
| Ed25519 sign | `sodium_crypto_sign_detached` | Ed25519 | ✅ |
| Ed25519 verify | `sodium_crypto_sign_verify_detached` | Ed25519 | ✅ |
| HKDF | `hash_hkdf('sha256', ...)` | HKDF-SHA256 | ✅ |
| AES-CBC | Not directly used (relies on endpoints) | — | N/A |
| Token (Fernet) | Not directly used (relies on endpoints) | — | N/A |

✅ **PASS** — Cryptographic primitives used correctly.

---

## Additional Observations

### Packet Filter Logic (`applyPacketFilter`)

**File:** `php/src/lib/request_packet_ingest_trait.php:17-72`

The filter implements several RNS transport rules:
- Rejects packets with mismatched `transport_id` (unless announce)
- Accepts resource/channel/cache packets (contexts 0x01, 0x05, 0x08, 0x0E)
- Rejects PLAIN packets with hops > 1 (local-only)
- Rejects GROUP packets with hops > 1 (local-only)
- Deduplicates by packet hash, with special handling for SINGLE announces

This generally aligns with spec intent, though the specific rules are informative (each transport MAY implement its own filter). ✅

### Announce Relay Logic

Announces are relayed to all other interfaces (standard RNS flood). Path entries track `random_blobs` for loop prevention and freshness. The PHP implements `LOCAL_REBROADCASTS_MAX` equivalent via hash deduplication rather than explicit counting.

### Request-Operated Model

The entire PHP transport is "request-operated" — packets only move during authenticated HTTP request/response exchanges. This is a significant architectural deviation from the always-on Python reference transport, but it's in the informative domain (transport internals MAY diverge).

---

## Issue Severity Summary

| # | Section | Issue | Severity | Fix Complexity |
|---|---------|-------|----------|----------------|
| 1 | §5 | HEADER_2 hashable part omits transport_id | Low-Medium | 1 line |
| 2 | §9 | Path request tag is 8 bytes vs spec's 10 | Low | 1 line |
| 3 | §9 | Missing transport identity in relay path requests | Low | Few lines |
| 4 | §7 | Link ID stored as destination_hash, not true link_id | **High** | Use `linkIdHex()` |
| 5 | §7 | LRPROOF validation uses wrong key + shouldn't validate | **High** | Remove validation |
| 6 | §7 | Proof hop count not incremented on relay | Low | Documented |

### Critical Path

Issues #4 and #5 combined mean that **link establishment through the PHP transport node will fail** for spec-compliant Python peers. The LRPROOF cannot be routed back because:
1. The stored link transport entry is keyed by the wrong value (#4)
2. Even if found, validation fails because the PHP doesn't have the ephemeral Ed25519 key from the LINKREQUEST (#5)
3. The fallback reverse-path lookup uses truncated_hash which also doesn't match the spec link_id

**Recommendation:** Fix issues #4 and #5 first. They block link interoperability with Python RNS nodes.
