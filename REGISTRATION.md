# Signed registration (protocol v1)

> Read [`../DESIGN_PRINCIPLES.md`](../DESIGN_PRINCIPLES.md) first. Every rule
> below follows it: events, not timers; no retries; no timeouts as a fix;
> strict ordering; §1's 5 seconds.

**Status:** specification, revision 7, 2026-10-04. Not implemented.

Revision 7 applies James's answers of 2026-10-04 to revision 6's four
questions (§16.2). Each time he chose the recommended answer:

- **The relay's transport id becomes its identity's hash** (question 1).
  The 16 bytes a PHP relay writes as the transport id into the packets it
  relays are now the hash of its persistent identity (§10.2). That is RNS
  parity, and the id no longer changes when the database is reset. The
  random id the relay had before stays its own as well, so packets on paths
  that neighbours learned before the switch are still forwarded. The switch
  happens in Phase 1, when a relay first runs this code (§11.2).
- **The rule for two-way configs stands** (question 2). Both relays
  register, and the later-sorted one stands down while it holds the earlier
  relay's registration, confirmed or pending (§10.3). Applying it showed that
  revision 6 counted anyone's pending registration for the earlier relay's
  URL. Revision 7 counts a pending one only for an identity that has already
  proven that URL here (A16).
- **A confirmed wake URL belongs to one identity** (question 3), gateways
  included (§9.8).
- **A dead runner is found by asking the OS, not by waiting for an
  operator** (question 4). Every detached runner that holds a claim holds a
  file lock for as long as it runs. The kernel releases the lock when the
  runner ends, however it ends, and the next request that finds the lock
  free knows the runner is gone (§10.10). That replaces revision 6's wait for
  `GET /v1/initialize` and the clock in the exchange runner's spawn rule
  (§10.5). It also frees the confirm records of dead runners (A17).

§18 lists what these decisions required that James did not decide. §16.2
asks about the choices among them.

Revision 6 (a738bde, 2026-10-04) applied James's decisions of that day:

- **A PHP relay peer registers at another relay exactly like the gateway.**
  This replaces revisions 2 to 5's one-time-nonce handoff. Each relay gets
  its own persistent Reticulum identity, kept in a file outside the database
  (§10.2). A peering is one relay's signed registration at the other (§10.4):
  - the server confirms the client's wake URL (§9.8) and wakes it;
  - the client pushes and pulls in one exchange, as the gateway does (§10.5);
  - it backs off without a timer under `DESIGN_PRINCIPLES.md` §3 (§10.6).

  Every relay registers at every relay in its `[interfaces]`. When two
  relays list each other, the later-sorted one stands down, so a pair has
  exactly one link (§10.3). That also closed revision 4's one-sided-peering
  gap. Gone: the nonce handoff, its two tables, `/v1/peers/confirm`, the
  `confirmed` proof and the wake-back. Phase 3b moves the live legacy peering
  over (§11.2).
- **The session token stays encrypted to the registrant** (§5). §10.4
  specifies the PHP client's decrypt, and vectors cover it (§14).

Revision 5 (d828e0a, 2026-10-03) applied James's answer to revision 4's one
question, "Re-confirm every time" (§16.2). Every signed gateway registration
starts a new wake-URL confirm, even with the URL unchanged. The bind clears the row's confirmation,
and the row is not woken until the new confirm succeeds (§4.4, §9.8). §9.8
now also says what ends wakes to a gateway that stops altogether: nothing in
the row's lifetime does, so a signed gateway row gets at most one wake
between two of its own exchanges.

Revision 4 (8272c09), earlier the same day, applied James's answers to
revision 3's questions:

- **Confirm a gateway's wake URL first.** James: "Confirm it first." Before a
  relay wakes a signed gateway row, the gateway's own wake server answers a
  one-time nonce at that URL, signed with its transport identity (§9.8,
  vectors `gateway_confirm`). This closes A15.
- **The initiator rule stays.** James: "Keep it, revisit later." The
  one-sided-peering gap was a known limit, to revisit with POST Reticulum
  hosting. *(Revision 6 replaced the rule and closed the gap.)*
- **§8.5's routing cost.** James: "Leave it, watch it." §11.2 watches for it,
  and RNS 1.5.2's gravity is the fix if it ever matters (§16.1.13).
- `[post_interface_peers]` stays open: the live configs are checked before
  Phase 3c (§11.2, §16.2).

Revision 3 (62f5369), earlier the same day, applied James's answers to
revision 2's questions:

- **No audience.** James: "Don't we have ssl to prevent spoofing?" The relay's
  host is no longer signed, the signed bytes are twelve fields again, and
  `403 audience_mismatch` is gone. A12 is an accepted risk (§0, §3.2).
- **Peering stays open.** James chose "Keep peering open" over an accept-list.
  `accepted_peer_urls`, `transit_identities`, `403 peer_not_accepted` and
  `403 transit_identity_not_allowed` are gone. A row is transit when it is
  proven (§8.1). Because anyone can now hold a transit row, a random blob
  already seen never creates or replaces a path on any row (§8.5): A4 is
  closed for transit rows too.
- **The gateway backs off.** After a failed registration it registers again
  at 2 s, doubling, capped at 5 min, under James's decided exception to §3 of
  the principles (§9.6).
- **Wake-back only between configured relays.** Credentials go only to a
  row's stored canonical URL, as d3a0eb5 already does live (§0.1, §10.1).
  *(Revision 6 removed the wake-back, which it no longer needs.)*
- The newest registration still wins (`409 session_superseded`, §6.1), and
  the two enforcement switches stand (§11.1).

§18 maps every decision of revisions 3 to 7 to the sections it changed.
Revision 2 (a5abab7) answered the adversarial review of revision 1 (26a8fef),
and §17 records that. Reticulum-post's code is at bae739a; the spec commits
since then change no code. The §0.1 hotfix shipped as d3a0eb5 and is deployed.

**Normative for:**

- Reticulum-post (PHP relay): `registerInterface()`, the new endpoints, the
  schema, the announce guard, PHP-to-PHP peering, the `/v1/wake` handler's
  peer lookup, the relay's transport id (§10.2) and its detached runners
  (§10.10).
- Retichat-js (browser): `lib/rns/interfaces/post_interface.js`.
- Reticulum-rust `PostInterface` (gateway), and the Python
  `RNS/Interfaces/PostInterface.py` in this repository, including their wake
  servers' confirm handler (§9.8).

**Byte-exact vectors:** [`php/tests/vectors/registration_vectors.json`](php/tests/vectors/registration_vectors.json),
generated by [`tools/registration_vectors.py`](tools/registration_vectors.py)
from RNS 1.5.2 and checked independently by
[`tools/check_registration_vectors.php`](tools/check_registration_vectors.php).
Each tool carries its own reference verifier for §4.3, and they share no
code. If this text and the vectors ever disagree, that is a bug. Fix the text
and regenerate the vectors in the same commit.

MUST, MUST NOT, SHOULD and MAY carry their RFC 2119 meanings.

---

## 0. Why

Before this change, `POST /v1/interfaces/register` took ownership claims on
trust. The design pass (workflow wf_73a89cca-022) and the review of
revision 1 found these attacks:

| # | Attack | Evidence | Closed by |
|---|---|---|---|
| A1 | Re-bind any browser row by POSTing its `identity_hash`, which any `lxmf.delivery` announce reveals. The same `interface_id` comes back, the victim's token is rotated so its next exchange gets 401, and the metadata is overwritten (mode set to 6). | `rebind_probe.php` on 35314f4 | §2–§4 and §7 for signed rows. A `none` row stays open to it until `enforce_signed_registration` (§16.1). |
| A2 | `identity_hash = '%'` or `'_%'` was a LIKE wildcard that re-bound an arbitrary browser row with no knowledge at all. | same probe; hotfix 3281ad5 (live) | hotfix; §7 deletes the metadata lookup |
| A3 | Interception with no re-bind: register your own identity, then replay a victim's signed announce through your row. The victim's `local_destinations` binding moves to you (endpoint→endpoint overwrite), and a third party's DATA to the victim is queued to you. | `probe2/announce_replay_probe.py` on a real `php -S` node at 35314f4 | §8.2 for every signed row. For legacy rows, §8.3 narrows it from Phase 1 and enforcement closes it (§16.1). |
| A4 | A replay with the unsigned hop count lowered to 0 pulls the path to any destination 2 or more hops away. `upsertPathFromAnnounce`'s `shorter_path_replaced` branch accepts a random blob it has already seen when the hop count is lower. Revision 1 kept that exception for every row whose `client` string said `reticulum-php` or `rns-post-interface`, and anyone can register such a row. Revision 2 kept it for proven transit rows, and with open peering anyone can prove one. | code reading at 35314f4 and 3281ad5 (not probed) | §8.5: a seen random blob never creates or replaces a path, whatever its hop count, on every row, legacy included, from Phase 1. RNS parity. |
| A5 | Any `client = reticulum-php` registration re-binds the row whose `peer_url` matches the claim (or the claim ± `/v1/wake`). That includes the relay's own initiator row for a PHP peer and the production gateway's wake-mode row (8d2a523d, mode 6, `peer_url http://jrl290.ddns.net`). | design map, lane 2 | §9 and §10. Legacy rows stay open until `enforce_signed_transit`. |
| A6 | During any transition, an unsigned row with a made-up claim replays a victim's announces (A3 through a legacy row). This includes every native-app user, who never registers on a relay. | critique; review of revision 1 | §8.3 narrows it from Phase 1, and enforcement closes it (§16.1). |
| A7 | The first signed registration inherits an attacker's squatted row, with its bindings, paths, links and queued batches. | critique | §4.5 |
| A8 | Identity claims reach rows through other client strings (`rns-post-interface`, or a `reticulum-php` that falls through). | critique | §7 |
| A9 | **Look-alike URLs.** On MySQL and MariaDB the tables use `utf8mb4_unicode_ci`, which ignores case and accents, so `peer_url = 'https://rétichat.com/…'` finds the row stored as `https://retichat.com/…`. That was live in the `/v1/wake` handler until d3a0eb5 (§0.1). Revision 1 also sent the peer confirm to the URL in the request body, uncanonicalised. | code reading; collation checked with ICU at UCA primary strength, not on a MySQL server | §0.1 hotfix (d3a0eb5); §10.1 (ASCII canonical URL, SHA-256 key; credentials go only to a row's stored canonical URL) |
| A10 | **Transit by label.** The `client` string chose whether a row was treated as transit, so an unsigned row that said `reticulum-php` got transit privileges. A browser row carrying `peer_*` fields counted as a PHP peer: always active and woken at any URL. Revision 2 also counted a fresh key, or a peering from a URL the attacker controls, as this attack. With open peering (James, 2026-10-03) those are allowed (§8.1). | review of revision 1 | §4.3.1, §8.1, §10: a row is transit only by proof (a signature whose signed `client` is a gateway client, made by a gateway or a PHP relay) or as this relay's own client row toward a relay in its config, or as legacy under the transit switch. A browser row never is. |
| A11 | **Unauthenticated outbound calls.** Revision 1 confirmed at a URL the registrant named from inside the request handler (a tarpit holds a PHP worker for up to curl's 10 s) and woke back any URL. Its nested confirm deadlocks two relays that connect to each other at the same time. | review of revision 1; tarpit test locally | §9.8 and §10: no request handler waits on another relay. Registrations, exchanges and confirms run in detached runners; pending confirms are bounded (§9.8); there is no wake-back (revision 6); credentials go only to a row's stored canonical URL (§10.1). |
| A12 | **A relay as a challenge oracle.** A relay the user chose fetches another relay's challenge for the user's identity, has the browser sign it, and forwards the body there. | review of revision 1 | **Accepted risk, James 2026-10-03.** Revision 2's signed `audience` is dropped. TLS does not stop this, because the forwarding relay is a real relay the user chose. What bounds it is that nobody can choose another relay: the web client's CSP `connect-src` allows only retichat.com and selectivesubconscious.com, both James's; gateways connect only to their configured node URL; and PHP relays, which sign since revision 6, register only at the relays in their own `[interfaces]`. Revisit if the web ever lets users choose other relays (§3.2). |
| A13 | **Activity oracle.** Revision 1's challenge showed `registration_seq`, which goes up on every registration, so polling it revealed when an identity used Retichat Web on that relay. | review of revision 1 | §2 (opaque challenge) |
| A14 | **Unbounded rows.** Every registration with a fresh key adds a permanent row. Legacy registrations already do this today, and nothing deletes `interfaces` rows. | review of revision 1; code reading | §12.4. What stays open is in §16.1. |
| A15 | **Wakes aimed by a registrant.** With open peering, anyone with a key registers a signed gateway row naming any host and port as its `peer_url`, and the relay's wakes go there, once per `min_wake_interval_ms` per row. | revision 3 (§16.1.10 there) | §9.8: no wake until the gateway's own wake server has answered a one-time nonce at that URL, signed with the row's key (James, 2026-10-03: "Confirm it first"). |
| A16 | **A pending confirm as a lever.** Anyone can register a signed `reticulum-php` row that names a peer relay's URL as its `peer_url`. Revision 6 counted any pending confirm for that URL as the peer's own registration (§10.3, condition 2). So each such registration made the later-sorted relay stand down its link to that peer (§10.7) until the confirm failed at the peer, and then register again: link churn on demand, with moments of no link at all. | review for revision 7, reading revision 6's §10.3 and §10.7 (nothing is implemented, so not probed) | §10.3: a pending confirm counts only for an identity whose signature the server at that URL has already returned on this relay (`wake_url_proven_key`, §9.8 step 5). |
| A17 | **Dead runners hold state for good.** A detached runner can end without writing its outcome: a PHP fatal error, an out-of-memory kill, a host reboot. A confirm runner reads whatever the URL a registrant named sends back, so that URL can choose to kill it. Revision 6 left a dead registration runner's client row `registering` until an operator called `GET /v1/initialize`, and a dead confirm runner's record in place for good: counted toward §9.8's 64, and as a pending confirm by §10.3. Sixty-four keys whose URLs kill their confirm runners would stop every later confirm until a DB reset. Its exchange-runner spawn rule used a clock (`min_wake_interval_ms`) to get past a runner that died before its POST. | James's question 4 of revision 6; review for revision 7 | §10.10: every runner that holds a claim holds an OS file lock for as long as it runs. The kernel releases the lock when the process ends, however it ends, and that release is the event that the runner is gone. No clock, and no process id. |

What a captured row gave an attacker: the session (eviction and DoS, repeatable),
delivery of the victim's inbound packets (payloads stay end-to-end encrypted,
but delivery is denied and link metadata is exposed), path next-hop
capture, and the row's mode and metadata.

### 0.1 Fixed defect: the wake handler sent a peer's credentials to the caller's URL

On 3281ad5, `POST /v1/wake {"waker_url": W}` runs `exchangeWithPhpPeer(W)`
(`index.php:1804`). That function:

1. finds the peer row with `peer_url = :W`, or with W plus or minus `/v1/wake`
   (`request_interface_registry_trait.php:362-399`);
2. then POSTs that row's `peer_interface_id` and `peer_session_token` to
   `W . '/v1/interfaces/exchange'`, which is the caller's string and not the
   stored URL (`request_php_wake_trait.php:266-296`).

On MySQL 8.4 and MariaDB 11.4 the `interfaces` table is created with
`COLLATE=utf8mb4_unicode_ci` (`request_schema_trait.php:108`). That collation
compares at the UCA primary level, so case, accents and trailing spaces do not
count. `https://rétichat.com/reticulum` therefore finds the row stored as
`https://retichat.com/reticulum`, and the credentials go to whoever owns
`xn--rtichat-bya.com`. Those credentials let the attacker call the other
relay's exchange as this relay: drain and acknowledge that relay's queue for
us, and inject transit packets.

Not proven against production:

- The collation equivalence was checked with ICU at primary strength, which
  applies the same UCA rule. No MySQL server is available here.
- The attack needs the relay's libcurl to resolve IDN hosts. That is
  unverified on the shared hosts.
- The attacker needs to own the look-alike domain and hold a certificate for
  it.
- SQLite (staging and every test) compares bytes, so no test here can show the
  attack.

**Hotfix, independent of everything else in this document:**
`exchangeWithPhpPeer` MUST POST to the stored row's `peer_url`, with any
`/v1/wake` suffix removed, and never to its argument. A look-alike
`waker_url` either reaches the stored URL or nothing.

**Shipped as d3a0eb5 and deployed.** The caller's URL must equal the row's
`peer_url` byte for byte after the same normalisation on both sides (trailing
`/` and one `/v1/wake` removed), compared with `hash_equals`. Otherwise
nothing is sent and `[WAKE-REFUSED]` is logged. bae739a then made the README
rotation wait until the fix is live on both nodes, and called for rotating the
peering again then, because the pair in use before the fix must be treated as
leaked.
§10.1 makes the rule general: credentials go only to a row's stored canonical
URL.

---

## 1. Who proves what

| Registrant | `client` | Proof | Row key | Transit row? (§8.1) |
|---|---|---|---|---|
| Browser (Retichat-js) | `rns-js` | Ed25519 signature by its RNS identity over a relay challenge (§2–§3) | `identity_hash` | never |
| Gateway, wake mode (Reticulum-rust / Python `PostInterface`) | `reticulum-php` | signature by its **persistent transport identity** (§9); its wake URL is confirmed separately, before any wake (§9.8) | `identity_hash` | yes |
| Gateway, poll mode | `rns-post-interface` | same signature | `identity_hash` | yes |
| PHP relay peer (Reticulum-post, §10) | `reticulum-php` | signature by its **persistent relay identity** (§10.2), exactly as a gateway; its wake URL is confirmed the same way (§9.8). Since revision 7 that identity's hash is also the relay's transport id, as a gateway's transport identity's is | `identity_hash` | yes |
| PHP PostInterface client (`[post_interface_peers]`, `request_post_interface_trait.php`) | `reticulum-post` | none: it has no key and no confirm path | — | legacy only, until `enforce_signed_transit`. Move any such link to `[interfaces]` peering before Phase 3c. |

The identity hash is self-certifying. RNS 1.5.2 defines it as
`identity_hash = SHA-256(x25519_pub(32) || ed25519_pub(32))[:16]`
(`RNS/Identity.py` `get_public_key`, `update_hashes`; `TRUNCATED_HASHLENGTH = 128`).
The relay recomputes it from the 64-byte public key in the registration, so
binding a row needs no PKI, no pin, no trust-on-first-use and no configuration.
*Transit treatment* follows from the same proofs. Peering is open (James,
2026-10-03: "Keep peering open"), so a relay keeps no list of gateways or
peers. A gateway that signs with its transport identity, and a PHP relay that
signs with its relay identity, each get a transit row (§8.1). Anyone can make a key
or run a relay, so what limits a transit row is what it may do: it never binds
local destinations, and a random blob already seen never moves a path through
it (§8.5).

Every interface row carries a `registration_proof`:

| Value | Meaning |
|---|---|
| `none` | Legacy. Nothing was proven. New ones are only possible while the matching enforcement switch is off (§11.1). |
| `signed` | Bound by a verified signed registration. The row has `identity_hash`, `identity_public_key` and `registration_seq`. |
| `local` | This relay's own client row toward a relay in its `[interfaces]` (§10.4): its interface for that link. Nobody registers it. |
| `retired` | A signed row whose URL now belongs to another identity (§9.8). It keeps its identity and seq, and is transit for nothing. |

Revision 6 removed `confirmed`, the proof of revision 2's nonce handoff (§10).

---

## 2. The challenge

James's decision: "a standard challenge and signing". It is stateless. The
relay keeps no nonce table, sets no TTL and runs no sweep.

### 2.1 Endpoint

```
POST /v1/interfaces/challenge          {"public_key": "<128 hex>"}
POST /v1/interfaces/challenge          {"identity_hash": "<32 hex>"}
GET  /v1/interfaces/challenge?public_key=<128 hex>
GET  /v1/interfaces/challenge?identity_hash=<32 hex>
```

Exactly one of `public_key` or `identity_hash` MUST be given, as lower-case
hex. Anything else gets `400 {"error":"bad_challenge_request"}`. Clients MUST
use POST. GET exists for operators. The relay MUST send `Cache-Control:
no-store` on both, because a cached challenge would turn into two `409`s
(§6). The response is:

```json
{
  "status": "challenge",
  "version": 1,
  "identity_hash": "<32 hex>",
  "challenge": "<96 hex = 48 bytes>"
}
```

The response reveals nothing about the identity's row on this relay: not its
`registration_seq`, and not whether it exists.

### 2.2 Bytes

```
H          = the identity hash (16 bytes), from public_key or as given
seq        = registration_seq of the row whose identity_hash = H, or 0 if there is none
nonce      = 16 random bytes (CSPRNG)
mac        = HMAC-SHA256(relay_secret, "reticulum-post/challenge/v1" || H || u64be(seq) || nonce)
challenge  = nonce(16) || mac(32)                                       -- 48 bytes
```

The domain string is the 27 ASCII bytes `reticulum-post/challenge/v1`. Every
other part of the MAC input has a fixed width, so the concatenation is
unambiguous. `u64be` is an unsigned 64-bit big-endian integer.

The seq is bound into the MAC but not carried in the clear. To verify, the
relay reads the row's **current** seq, or 0 if there is no row, and recomputes
the MAC with it (§4.3 step 5). A challenge issued before the seq moved fails
that check, as does one issued by another relay, for another identity, under
a rotated secret, or altered in any bit. All of these fail the same way, and
nobody outside the relay can tell them apart. `registration_seq` is a
`BIGINT` that only ever goes up by one, so it never comes near 2^63.

### 2.3 `relay_secret`

- 32 random bytes, generated on first use and stored as hex in
  `transport_state` under `state_key = 'registration_challenge_secret_hex'`.
  To create it, the relay does INSERT-or-ignore and then SELECT, so concurrent
  first requests end up with the same value.
- It MUST never appear in `/health`, `/debug`, `/v1/monitor*`, logs or
  responses.
- Any database reset rotates it. `clearAllData()` already empties
  `transport_state`. When it rotates, every outstanding challenge dies. That is
  intended.
- A challenge minted by one relay fails the MAC at any other relay. That alone
  does not stop a relay the user chose from fetching another relay's challenge
  for the user's identity and relaying it (A12). Revision 3 accepts that risk
  (§3.2).

### 2.4 Single use comes from `seq`

A successful signed registration moves the row from `seq` to `seq + 1`
atomically (§4.4). Every challenge bound to the old `seq` then fails §4.3
step 5, permanently. A captured signed body therefore works at most once, and
since the session token comes back encrypted to the identity (§5), the one
who replays it gets nothing usable.

That holds only while the seq never goes back. §12.5 states the invariant
that keeps it.

A challenge that is never used stays valid until the row's `seq` moves or the
secret rotates. That is harmless: using it needs the identity's private key,
and using it consumes it.

### 2.5 Old relays

A relay that predates this spec answers the challenge endpoint with `404`.
That is the only signal a client uses to fall back to the legacy unsigned
registration (§11.4). Clients MUST NOT fall back on any other status.

---

## 3. Signed bytes

```
lp(x)  = u16be(len(x)) || x                (len(x) ≤ 65535)

signed = lp("reticulum-post/register/v1")            -- 26 bytes, lp = 001a…
      || lp(challenge)                               -- 48 bytes, exactly as received
      || lp(public_key)                              -- 64 bytes: x25519_pub || ed25519_pub
      || lp(utf8(name))
      || lp(u64be(bitrate))
      || lp(u32be(mtu))
      || lp(utf8(metadata.client))
      || lp(u8(metadata.mode))
      || lp(utf8(metadata.transport          or ""))
      || lp(utf8(metadata.peer_url           or ""))
      || lp(utf8(metadata.peer_interface_id  or ""))
      || lp(utf8(metadata.peer_session_token or ""))

signature = Ed25519-sign(ed25519_private_key, signed)  -- RNS Identity.sign, 64 bytes
```

There is one layout, with twelve fields, for every registrant. A browser
signs the four optional fields as empty strings. A wake-mode gateway fills in
the three `peer_*` fields. A poll-mode gateway may fill in `transport`. No JSON
appears in the signed bytes: PHP's `json_encode` escapes `/` and the other
encoders do not.

Revision 2 had a thirteenth field, `audience`, after `challenge`. Revision 3
removed it (§3.2). No port implements either layout yet: across
Reticulum-post, Retichat-js and Reticulum-rust, only this spec, its two tools
and the vector file contain the domain string. So the domain stays
`reticulum-post/register/v1`.

Rules for reading the values:

1. The values MUST be read from the decoded JSON body **before any
   normalisation**: no trimming, no case folding, no URL rewriting. The relay
   normalises only after verification, for storage and lookup.
2. `name`: a non-empty JSON string of valid Unicode (no lone surrogates),
   ≤ 255 bytes as UTF-8.
3. `bitrate`: a JSON integer, 1 … 2^53 − 1. `mtu`: a JSON integer,
   1 … 2^32 − 1. `mode`: a JSON integer, 1 … 7 (the RNS interface modes,
   `MODE_FULL` = 1 … `MODE_INTERNAL` = 7). Strings, booleans and floats such
   as `1e6` are refused.
4. `client`: a non-empty string of ≤ 64 bytes. `implementation` ≤ 64 bytes,
   `transport` ≤ 64, `peer_url` ≤ 512, `peer_interface_id` ≤ 64,
   `peer_session_token` ≤ 128 (the column widths). A key that is absent,
   `null`, or `""` encodes as `lp("")` (`0000`) and is stored as absent.
5. `challenge`, `public_key` and `signature` are lower-case hex of exactly
   96, 128 and 128 characters.

Why each field is covered:

- `challenge` gives freshness and binds the identity's row on this relay.
- `public_key` is what is proven.
- `name`, `bitrate`, `mtu`, `client`, `mode` and `transport` change how the
  relay treats the row.
- The `peer_*` fields are where the relay sends wakes and what it presents
  when it calls back.

Nobody can alter any of them without the key.

**The domain tag cannot collide with RNS signatures.** RNS announce, link,
proof and LXMF signatures sign raw protocol bytes that start with a 16- or
32-byte hash or key. For an RNS-signed blob to begin with `lp("reticulum-post/register/v1")`,
a destination hash would have to equal those 16 bytes, which is a 128-bit
preimage. The critique also checked every other signature the browser makes
(`app.js` 5681, 5970, 5998, 6503), and none can start with the tag.
Implementations MUST build these bytes in a single function
(`signRegistration()` in the browser) and MUST NOT sign bytes received from the
network, other than the challenge placed in its own field.

### 3.1 Worked example: vector `browser-first`

The identity is `browser` from the vectors (hash `20bc2200ebcd73a552b6e6a7ff2a0ba8`).
Relay A's secret is `13cbff96…c59169`. There is no row yet, so `seq = 0`.

```
mac input  7265746963756c756d2d706f73742f6368616c6c656e67652f7631      "reticulum-post/challenge/v1"
           20bc2200ebcd73a552b6e6a7ff2a0ba8                            H
           0000000000000000                                            seq 0 (bound, not sent)
           5ab138262aa3ff7e40d3e0d18156b5b9                            nonce
mac        6bc78010ea1616eb57342eb81a75ee1610f5ba999763b15904037774de39808a
challenge  5ab138262aa3ff7e40d3e0d18156b5b9 6bc78010…de39808a          nonce || mac, 48 bytes

signed     001a 7265746963756c756d2d706f73742f72656769737465722f7631  domain
           0030 5ab13826…de39808a                                      challenge (48)
           0040 bcf19510…4b321596                                      public key (64)
           000c 526574696368617420576562                               "Retichat Web"
           0008 00000000000f4240                                       bitrate 1000000
           0004 000001f4                                               mtu 500
           0006 726e732d6a73                                           "rns-js"
           0001 01                                                     mode 1
           0000 0000 0000 0000                                         transport, peer_url, peer_interface_id, peer_session_token
                                                                       193 bytes in all
signature  b1a0d662c1dbbb2c815bddf402f145e51a499085266f24daf539a671b31f6e12
           15e4ced2e52956751e5c0c602b8b66063ac7357fbd1313f2de6c61622a79b804
```

The full bytes are in the vector file.

### 3.2 No audience

Revision 2 signed the host the client connected to (`audience`), so that a
relay the user chose could not forward another relay's challenge (A12). Asked
whether to keep it, James answered "Don't we have ssl to prevent spoofing?",
and the binding was dropped on 2026-10-03. The signed bytes carry no relay
address, the relay does not read `Host` for registration, and there is no
`403 audience_mismatch`.

TLS alone does not close A12, and this spec does not claim it does. TLS proves
which relay a client reached. It does not stop that relay, when it is the one
the user chose, from fetching another relay's challenge for the user's
identity, having the client sign it, and forwarding the body. The other relay
then binds the identity's row there. The client goes on sending its session
token to the relay it chose on every exchange, so that relay holds the
identity's session at the other relay: it can take the identity's inbound
there (delivery denied, link metadata seen, payloads still end-to-end
encrypted), and the identity's own session there is superseded.

The risk is accepted because nobody can choose another relay today:

- **Browsers:** the web client's CSP `connect-src` (Retichat-js `.htaccess`)
  allows only the page's own origin, `https://retichat.com/reticulum/` and
  `https://selectivesubconscious.com/reticulum/` (and `esm.sh` for modules).
  Both relays are James's.
- **Gateways:** connect only to their configured node URL.
- **PHP relays:** sign since revision 6, but register only at the relays in
  their own `[interfaces]` config (§10.3). Their operator chooses those
  relays, as a gateway's operator chooses its node URL.

Revisit this if the web client ever lets users choose other relays.

---

## 4. Registering

### 4.1 Request

```json
POST /v1/interfaces/register
{
  "name": "Retichat Web",
  "bitrate": 1000000,
  "mtu": 500,
  "metadata": { "client": "rns-js", "implementation": "PostInterface", "mode": 1 },
  "registration": {
    "version": 1,
    "public_key": "<128 hex>",
    "challenge":  "<96 hex, verbatim from §2.1>",
    "signature":  "<128 hex>"
  }
}
```

`registration` is a new top-level key, so a relay that predates this spec
ignores it, and it never reaches `metadata_json`. The `registration` object
MUST hold exactly those four keys, and `version` MUST be `1`. An `audience`
key (revision 2) is a fifth key and gets `400 bad_registration`.

**In a signed registration the metadata keys are limited** to the signed ones
(`client`, `mode`, `transport`, `peer_url`, `peer_interface_id`,
`peer_session_token`) plus two more:

- `implementation`: informational, ≤ 64 bytes. The relay never bases a
  decision on it.
- `identity_hash`: optional. If present it MUST equal the identity hash derived
  from the key (otherwise `400 identity_hash_mismatch`), and it is never stored.

Any other key gets `400 unsigned_metadata`. The relay MUST never act on a value
the signature does not cover. A new field means a new layout (v2), not an
unsigned key. `wake_url` and `ifac_*` are therefore not available to signed
registrations in v1. No signing client sends them today.

### 4.2 Which path

| Body | Path |
|---|---|
| has `registration` | **signed** (§4.3), whatever `client` says; PHP relay peers included (§10.4) |
| anything else | **legacy** (§7.2), accepted only while the matching enforcement switch is off (§11.1) |

### 4.3 Verifying a signed registration

The relay runs these checks in this order, cheapest first. Nothing is written
before step 7, and step 7 only reclaims legacy rows (§12.4).

| Step | Check | On failure |
|---|---|---|
| 1 | Shape: §3 rules 2–5, and the §4.1 `registration` object | `400 bad_registration` |
| 2 | Metadata keys within the signed set (§4.1) | `400 unsigned_metadata` |
| 3 | `H = SHA-256(public_key)[:16]`; `metadata.identity_hash`, if present, equals `H` | `400 identity_hash_mismatch` |
| 4 | Client policy (§4.3.1) | `400 unknown_client`, `transit_mode_not_allowed`, `metadata_not_allowed`, `peer_fields_required` or `peer_url_not_allowed` |
| 5 | Read the row with `identity_hash = H` (its `registration_seq`, or 0 if there is none). Recompute the MAC (§2.2) over the derived `H`, that seq and the challenge's nonce, and compare it with the challenge's MAC in constant time. | `409 stale_challenge` |
| 6 | `sodium_crypto_sign_verify_detached(signature, signed, public_key[32:64])` over bytes rebuilt from the received body (§3) | `403 bad_registration_signature` |
| 7 | Capacity, only when step 5 found no row: §12.4 | `503 registration_capacity` |
| 8 | Make a fresh session token and encrypt it to `public_key[0:32]` (§5). An X25519 result of all zeros (a low-order key; `sodium_crypto_scalarmult` throws) fails. | `400 bad_registration` |
| 9 | Atomic bind (§4.4) with the token from step 8 | `409 stale_challenge` |

Revision 3 removed revision 2's step 5 (`audience`, §3.2) and step 8
(`transit_identities`, §8.1), and renumbered the rest. A signed gateway needs
no permission beyond its signature.

Each negative vector fails exactly one of these steps, so an implementation
that orders them differently still gives the same answers. The order above is
still the one implementations MUST use: it is the cheapest, and step 7 tells
only the key's holder that the relay is full.

#### 4.3.1 Client policy

"Empty" means absent, `null` or `""`.

| `client` | Who | `mode` | `transport` | `peer_url`, `peer_interface_id`, `peer_session_token` |
|---|---|---|---|---|
| `rns-js` | browser | 1, 2, 4 or 7. Transit modes 3, 5 and 6 get `transit_mode_not_allowed`. | must be empty | must be empty |
| `rns-post-interface` | poll-mode gateway | 1–7 | optional | must be empty |
| `reticulum-php` | wake-mode gateway, or a PHP relay peer (§10) | 1–7 | must be empty | all three required (`peer_fields_required`); `peer_url` MUST canonicalise (§10.1) with scheme `http` or `https` (`peer_url_not_allowed`) |
| anything else | — | — | — | `unknown_client` |

A field that a client may not carry gets `metadata_not_allowed`. The sub-checks
run in this order: `unknown_client`, `transit_mode_not_allowed`,
`metadata_not_allowed`, `peer_fields_required`, `peer_url_not_allowed`.

Why: `transport = http-exchange` changes routing and LXMF handoff on the relay
(`request_outbound_batch_trait.php`, `request_lxmf_handoff_trait.php`), and
`peer_*` fields make a row look like a peer. A browser row may carry neither.
PHP relay peers register signed as `reticulum-php`, exactly as a wake-mode
gateway (§10.4).

### 4.4 Binding atomically

The row is looked up only by `identity_hash = :H`, an exact match on its own
column. That column has a UNIQUE index (§12) and holds lower-case hex only, so
the collation cannot fold two values together (§12.2).

- **`seq = 0` (no signed row):** `INSERT` a new row with
  `interface_id = random 16 bytes hex`, `identity_hash = H`,
  `identity_public_key = public_key`, `registration_seq = 1`,
  `registration_proof = 'signed'`, the token from step 8 and the signed
  parameters. A unique-constraint conflict means another registration for `H`
  won: the relay looks the row up again (only to log it) and answers
  `409 stale_challenge`. It does not insert a second time.
- **`seq > 0`:** update in place, with the seq read in step 5.

  ```sql
  UPDATE interfaces
     SET previous_session_token_hash = :old_token_sha256, session_token = :token,
         name = :name, bitrate = :bitrate, mtu = :mtu,
         status = :online, metadata_json = :metadata_json, last_seen_at = :now,
         updated_at = :now, registration_seq = :next_seq, registration_proof = 'signed',
         wake_url_confirmed_key = NULL, wake_outstanding = 0,
         peer_url = :peer_url, peer_url_key = :peer_url_key,
         peer_interface_id = :peer_interface_id,
         peer_session_token = :peer_session_token
   WHERE identity_hash = :h AND registration_seq = :seq AND identity_public_key = :pub
  ```

  `rowCount() = 1` is required, otherwise `409 stale_challenge`.
  `:old_token_sha256` is the SHA-256 hex of the session token step 5 read
  (§6.1). The statement always changes `registration_seq` and `session_token`,
  so MySQL's "affected rows" equals "matched rows". No
  `PDO::MYSQL_ATTR_FOUND_ROWS` is needed.

  Every signed re-bind clears the gateway's wake-URL confirmation and its
  outstanding wake (§9.8), whether or not the URL changed (James,
  2026-10-03: "Re-confirm every time"). For a browser row both are already
  NULL and 0. Both are plain constants, so the order of `SET` assignments does
  not matter. Revision 4's `CASE`, which read `peer_url_key` and so had to come
  before its assignment (MySQL and MariaDB evaluate single-table `SET` left to
  right, SQLite does not), is gone. The INSERT (seq 0) leaves them NULL and 0.
  The bind does not touch `wake_url_proven_key`: that this identity once
  proved its URL here survives its re-registrations (§9.8 step 5, §10.3).

  After the bind commits, every signed `reticulum-php` row starts the
  wake-URL confirm (§9.8). The registration's answer does not wait for it.

The interface keeps its `interface_id` across re-registrations, so its queue,
paths and links survive a re-registration and, for the gateway, a restart.

### 4.5 A signed registration never adopts a squatted row

The legacy path keeps its claims in `claimed_identity_hash`, never in
`identity_hash` (§7). A signed registration therefore can never land on a
legacy row. After every successful signed bind for `H` (the INSERT, and
also the UPDATE, which catches a legacy row that raced in between), the
relay **retires** every row with `claimed_identity_hash = H` and
`registration_proof = 'none'`. When there is none, that costs one indexed
`SELECT`.

For each row it retires, it deletes, in this order:

1. `local_destinations`;
2. `path_entries`, `reverse_path_entries` and `link_transport_entries`
   (matching `received_interface_id` or `outbound_interface_id`);
3. `outbound_packets`, `outbound_batches` and `wake_events`;
4. the `interfaces` row.

It logs `[REG-RETIRE] identity=<H> rows=<n>`.

A signed `reticulum-php` registration (a wake-mode gateway, §9; no other
signed client carries a `peer_url`) also retires every `none` URL row
(`identity_hash IS NULL`) of a transit-class client (`reticulum-php`,
`rns-post-interface`, `reticulum-post`) whose `peer_url_key` equals its own,
with the same deletion set. It logs
`[REG-RETIRE-URL] key=<8 hex> rows=<n>`. That is how Phase 3 removes the
legacy bridge row at the moment the signed gateway row comes up (§11.2). Paths
through the old row are deleted with it and are learned again from the next
announces through the new row, so nothing black-holes behind an always-active
dead row.

Revision 2 allowed this only to a listed transit identity. Peering is open
now, so any signed gateway can do it. That opens nothing new: until
`enforce_signed_transit`, anyone can already take over a `none` URL row by its
URL with an unsigned `reticulum-php` registration (A5, §7.2, §16.1.2), which
is worse than retiring it. Once the switch is on, such a row is no longer
transit and gets `401` (§11.1), so retiring it costs nothing.

Whoever holds a retired row gets `401` on its next exchange, whether it is the
user's own stale tab or a squatter. If it then re-registers unsigned while
claiming `H`, it gets `403 identity_requires_signature` (§7.2).

Packets queued to a retired row are dropped. They were queued to a row whose
owner was never proven, so handing them to the proven identity is exactly the
adoption the critique ruled out (A7).

### 4.6 What is stored

- **Columns:**
  - `identity_hash`, `identity_public_key`, `registration_seq`,
    `registration_proof` and `previous_session_token_hash`;
  - the signed `peer_*` fields in their existing columns, with `peer_url`
    stored in canonical form (§10.1) and its `peer_url_key`;
  - `wake_url_confirmed_key`, written only by the §9.8 confirm and cleared by
    every signed re-bind (§4.4); `wake_url_proven_key`, written only by the
    §9.8 confirm and cleared only by a retire; and `wake_outstanding` (§9.8's
    wake rule);
  - `name`, `bitrate` and `mtu`.
- **`metadata_json`:** only `client`, `implementation`, `mode` and
  `transport`.
- **Never in `metadata_json`, on any path:** `identity_hash`,
  `identity_public_key`, `registration_seq` or the `registration` object.

The relay strips these before every write. That leaves nothing for a LIKE (or
any other metadata lookup) to match (A2, A8).

---

## 5. The response: the token comes back encrypted

A signed registration is answered **only** like this:

```json
{
  "status": "registered",
  "interface_id": "<32 hex>",
  "identity_hash": "<32 hex, the relay's derived H>",
  "session_token_encrypted": "<hex>",
  "idle_exchange_interval_ms": 1000,
  "max_batch_packets": 64,
  "max_packet_bytes": 500
}
```

It MUST NOT contain `session_token`, `peer_interface_id`,
`peer_session_token` or `registration_seq`. A test MUST assert this.
`idle_exchange_interval_ms`, `max_batch_packets` and `max_packet_bytes` are
today's operational fields, unchanged. The session token is a fresh
`bin2hex(random_bytes(32))`, the same as today.

`session_token_encrypted` is RNS `Identity.encrypt(utf8(session_token))` to the
registrant's public key, with no ratchet:

```
eph        = fresh X25519 key pair
shared     = X25519(eph_private, public_key[0:32])      -- all zeros: refuse (§4.3 step 8)
derived    = HKDF-SHA256(ikm = shared, salt = H, info = "", L = 64)
hmac_key   = derived[0:32]      aes_key = derived[32:64]
iv         = 16 random bytes
ct         = AES-256-CBC(aes_key, iv, PKCS7(utf8(session_token)))
blob       = eph_public(32) || iv(16) || ct || HMAC-SHA256(hmac_key, iv || ct)(32)
```

For a 64-character token the blob is 160 bytes (320 hex). This is the
derivation `request_lxmf_handoff_trait.php` already implements
(`buildOutboundSinglePacket` / `encryptIdentityToken`). The salt is the
registrant's **identity** hash.

The client decrypts with its identity, using RNS `Identity.decrypt`, the web
`Identity.decrypt` or Rust `Identity::decrypt`. Then:

- the plaintext MUST be 64 lower-case hex characters, and that string is the
  session token;
- `identity_hash` in the response MUST equal the client's own hash.

If either fails (including an HMAC failure), it is a protocol error: the
client stops and shows it (§6). It never falls back to a plaintext field.

A legacy (unsigned) registration keeps today's response, with a plaintext
`session_token`, until enforcement. A PHP relay peer gets its token like any
signed registrant, encrypted in this response (James, 2026-10-04: keep it),
and decrypts it with its identity (§10.4).

---

## 6. Errors

Every 4xx and 5xx body that carries an `error` is
`{"error": "<code>", "message": "<one line for a person>"}`. Clients act on
the HTTP status and `error` only.

| Status | `error` | Raised when | Client action |
|---|---|---|---|
| 400 | `bad_challenge_request` | challenge request without exactly one well-formed key or hash | stop, show |
| 400 | `bad_registration` | malformed `registration` object or signed field (§3); a key that cannot receive a token (§4.3 step 8) | stop, show |
| 400 | `unsigned_metadata` | a metadata key outside the signed set (§4.1) | stop, show |
| 400 | `identity_hash_mismatch` | `metadata.identity_hash` ≠ the key's hash | stop, show |
| 400 | `unknown_client` | a signed registration whose `client` is not in §4.3.1 | stop, show |
| 400 | `transit_mode_not_allowed` | `rns-js` with mode 3, 5 or 6, signed or legacy | stop, show |
| 400 | `metadata_not_allowed` | a signed field this client may not carry (§4.3.1) | stop, show |
| 400 | `peer_fields_required` | `reticulum-php` without all three peer fields | stop, show |
| 400 | `peer_url_not_allowed` | a `peer_url` that does not canonicalise (§10.1) | stop, show |
| 403 | `bad_registration_signature` | signature does not verify | stop, show |
| 403 | `identity_requires_signature` | legacy registration claiming an identity that has a `signed` row here | stop, show "reload this page" |
| 403 | `signature_required` | unsigned registration while the matching enforcement switch is on (§11.1) | stop, show "reload this page" |
| 403 | `peer_confirmation_required` | a legacy `reticulum-php` registration that would re-bind this relay's own `local` client row (§10.4) | log, stop |
| 409 | `stale_challenge` | the challenge does not verify against this relay, this identity and the row's current seq; or the bind race was lost | **fetch ONE new challenge and register ONCE more**; a second 409 is terminal: stop, show |
| 503 | `registration_capacity` | a new row while the interfaces table is full (§12.4) | stop, show "this relay is full"; a gateway or PHP relay: backoff (§9.6, §10.6) |
| 503 | `relay_identity_unavailable` | `/exchange`, `/tx`, `/poll` and `/v1/wake` only: the relay cannot load or create its identity file, so it has no transport id (§10.2) | as any other 5xx on that endpoint: the browser keeps its existing handling; a gateway's or PHP relay's exchange is logged and not retried (§9.6, §10.6) |
| 401 | `unauthorized` | `/exchange`, `/tx`, `/poll`, `/goodbye` only: unknown session, or a `none` row under the matching enforcement switch | re-register once per run (§6.1) |
| 409 | `session_superseded` | `/exchange`, `/tx`, `/poll`, `/goodbye` only: the token is the row's previous one, replaced by a newer registration of the same row | stop, show (§6.1) |
| 404 | (any) | challenge endpoint on a relay that predates this spec | legacy registration (§11.4) |

`/v1/interfaces/register` and `/v1/interfaces/challenge` never return 401 or
`session_superseded`. The authenticated endpoints never return
`stale_challenge`.

The `409 stale_challenge` second step is a documented protocol step with a
fixed bound of one, like a digest-auth challenge. It is not a retry loop
(§3 of the principles). It covers a relay DB reset or another registration of
the same identity landing between challenge and register.

**"Stop, show"** means:

- **Browser:** no further automatic registration. The reason reaches the UI
  through `down`. A reload or an explicit reconnect starts again. The 5-second
  reconnect cadence MUST NOT apply to these codes.
- **Gateway, and a PHP relay registering at a peer (§10.6):** an ERROR log
  line with the code. The interface goes **offline
  in Transport** with the code as its reason (visible in `rnstatus`), so
  nothing is routed into it. It registers again on the backoff schedule of
  §9.6, James's decided exception to §3 of the principles. `409
  session_superseded` is the exception: it stays terminal until the process
  restarts (§6.1, §9.6).

Revision 3 removed `403 audience_mismatch` (§3.2), `403
transit_identity_not_allowed` and `403 peer_not_accepted` (§8.1, §10).
Revision 6 removed `503 peer_confirm_backlog` and the `202 confirm_pending`
answer, both of the nonce handoff (§10). Revision 7 added
`503 relay_identity_unavailable` (§10.2).
The gateway's answers to the wake-URL confirm (`400 bad_confirm_request`,
`403 not_my_identity`, `unknown_relay`, `not_my_wake_url`) are in §9.8.

Network failures and 5xx without one of the codes above are not protocol
answers. The browser keeps its existing handling. When they answer the
gateway's registration, the gateway follows §9.6.

Old clients do not know these codes. An old tab treats any non-401 as
"failed" and tries again every 5 s with the error text in its "down" reason,
which is why the `message` for `signature_required`,
`identity_requires_signature` and `session_superseded` says what to do.

### 6.1 Session lost versus session superseded

Every time a row's session token changes, the relay keeps
`previous_session_token_hash = SHA-256 hex of the old token`. That happens on
a signed re-bind (§4.4) and a legacy re-bind (§7.2).
`authenticateInterface(id, token)` answers:

1. a row `id` whose `session_token` equals `token` (`hash_equals`): success;
2. a row `id` whose `previous_session_token_hash` equals
   `SHA-256(token)`: **`409 session_superseded`**. A newer registration of
   this row replaced the session;
3. anything else, or (under the matching enforcement switch) a `none` row:
   **`401 unauthorized`**. The relay does not know this session.

| Client | `401` | `409 session_superseded` |
|---|---|---|
| Browser | register again (signed: challenge, then register), once per run, as today | stop, show "This identity connected from another tab or device. Reload to connect here." |
| Gateway | §9.5 | ERROR "another process registered this identity", offline in Transport, no registration until restart: no backoff, and a wake does not restart it (§9.6) |
| PHP relay, on its client row's exchange (§10.6) | register at once, with a compare-and-swap | ERROR `[PEER-SUPERSEDED] <url>`, terminal until `GET /v1/initialize`: no backoff, and a wake does not restart it |

This ends the eviction loop between two holders of one identity. Today, and in
revision 1, each holder's 401 made it re-register and evict the other, every
poll (D11). Now the older holder stops and says why, and the last explicit
registration wins.

An old tab does not know `session_superseded`, so it treats it as a failure.
It then exchanges again every 5 s with the same token and never re-registers,
so it evicts no one. The `message` tells its user to reload.

---

## 7. Re-bind rules

### 7.1 Summary

| Registration | May create | May re-bind |
|---|---|---|
| signed (§4.3) | the row for its own derived identity | only that row, through §4.4 |
| legacy `rns-js` (`enforce_signed_registration` off) | a `none` row with `claimed_identity_hash = claim`, or with no claim | only a `none` `rns-js` row with the same `claimed_identity_hash`. Never a `signed` row |
| legacy `reticulum-php`, an old PHP relay or gateway (`enforce_signed_transit` off) | a `none` URL row | only a `none` URL row with the same `peer_url_key` |
| legacy `rns-post-interface` or `reticulum-post` (`enforce_signed_transit` off) | a new `none` row (no deduplication, as today) | nothing |
| legacy, any other `client` (`enforce_signed_registration` off) | a new `none` row. It is an endpoint with no owner, so §8 drops every announce it sends. | nothing |
| anything unsigned, with the matching switch on | nothing (`403 signature_required`) | nothing |

Every INSERT by a signed or legacy registration is subject to the capacity
rule (§12.4). A relay's own client rows are created by the relay itself
(§10.4), never by a registration.

Invariants:

- **Identity rows are reachable only through §4.3, whatever `client` says.**
  The only reads of `identity_hash` and `identity_public_key`, and the only
  advance of `registration_seq`, happen in the signed path. The read-only
  checks in §7.2 and §8 are the exception. No legacy path writes those
  columns.
- **Every URL lookup goes by `peer_url_key` and excludes identity rows**
  (`AND identity_hash IS NULL`). That covers the wake handler's client-row
  lookup (§10.5), the legacy wake and peer paths, maintenance and §4.5's
  retire by URL. No SQL compares `peer_url` itself (§12.2). Two lookups read
  identity rows by `peer_url_key`, and each counts only rows whose URL is
  proven: §10.3's check (confirmed, or proven before and being re-confirmed)
  and §9.8's retire (the URL just confirmed). A signed row that names a PHP peer's
  URL can therefore never take over wake lookups. Wake *dispatch* to a signed
  gateway row uses that row's own stored `peer_url`, and only while it is a
  transit row (§8.1) whose URL is confirmed (§9.8).
- `interfaceByIdentityHash()`, the metadata lookup the hotfix narrowed, is
  deleted. The legacy claim lives in `claimed_identity_hash` (§12).

### 7.2 The legacy path

Legacy `rns-js`, in order:

1. Mode 3, 5 or 6: `400 transit_mode_not_allowed`.
2. `enforce_signed_registration` on: `403 signature_required`.
3. The claim is `metadata.identity_hash` if it is 32 lower-case hex. A
   malformed claim is no claim, logged `[REG-BAD-IDENTITY]` as today.
4. If a row has `identity_hash = claim`: `403 identity_requires_signature`.
5. If there is a claim and a row with `claimed_identity_hash = claim AND
   registration_proof = 'none' AND identity_hash IS NULL` and `client = rns-js`:
   re-bind it in place, as today, with a plaintext token, and set
   `previous_session_token_hash` to the old token's hash (§6.1). Otherwise
   INSERT with
   `claimed_identity_hash = claim` (§12.4 applies).
6. Log `[REG-LEGACY] client=rns-js type=browser action=<created|rebound> interface=<id8>`.

Legacy `reticulum-php` (an old PHP relay, or an old wake-mode gateway):

- If `enforce_signed_transit` is on: `403 signature_required`.
- `peer_url` that does not canonicalise (§10.1): `400 peer_url_not_allowed`.
- If a URL row with the same `peer_url_key` has proof `none`, it is re-bound,
  as today.
- If such a row has proof `local` (this relay's own client row, §10.4):
  `403 peer_confirmation_required`.
- If there is no such row, a new one is inserted with proof `none`.

All of these are logged `[REG-LEGACY] client=reticulum-php type=<peer|gateway>`.
The type is `gateway` when `mode = 6` and `peer_url` is not `https`. That is
only a hint for the log.

Legacy `rns-post-interface` or `reticulum-post`: under `enforce_signed_transit`,
`403 signature_required`. Otherwise a new row is inserted, as today. Legacy,
any other `client`: under `enforce_signed_registration`,
`403 signature_required`. Otherwise a new row is inserted, but it can bind
nothing (§8.2).

An `identity_hash` key in the metadata of any non-`rns-js` legacy registration
is ignored and logged `[REG-LEGACY … identity_claim_ignored]`. Only `rns-js`
claims are honoured (A8).

---

## 8. Transit rows and the announce guard

This section is required (A3, A4, A6, A10). Signing registrations does not
by itself close announce-replay interception, and an unsigned `client` string
proves nothing.

### 8.1 Transit rows

Peering is open (James, 2026-10-03: "Keep peering open"). Transit is decided
by proof alone; no configuration lists who may be transit.

`isTransitRow(R)` is true exactly when one of these holds:

- `R.registration_proof = 'local'`: this relay's own client row toward a
  relay in its `[interfaces]` (§10.4), while its `peer_state` is `connected`
  or `registering` (§10.6). A client row that is refused, superseded or
  standing down is not active, so nothing is routed into it;
- `R.registration_proof = 'signed'` and `R.client` is `reticulum-php` or
  `rns-post-interface`, and the row is not closed by its holder's goodbye
  (§10.7): a gateway that signed with its transport identity (§9), or a PHP
  relay that signed with its relay identity (§10). For a signed row, `client` is one of the signed fields (§3) and passed
  the client policy (§4.3.1), so it is part of what the signature proves, not
  a label;
- `R.registration_proof = 'none'`, `R.client` is `reticulum-php`,
  `rns-post-interface` or `reticulum-post`, and `enforce_signed_transit` is
  off. This is legacy, kept as it is today so that Phase 1 does not cut the
  live bridge or peering.

A10 stays closed: an unsigned `client` string makes a row transit only as
legacy under the switch, `peer_*` columns never make a row a peer, and a
browser (`rns-js`) row is never transit. What open peering gives up is the
operator's say over *who* proves: anyone with a fresh key, gateway or PHP
relay, can hold a transit row. §8.5 and §16.1 say what such a row can
and cannot do.

Transit rows, and only transit rows:

- skip the identity guard (§8.2), because they carry other identities'
  announces;
- count as always active (a client row only in the states above), and are
  woken at their stored `peer_url`, when they have one and, for a signed
  gateway or relay row, only under §9.8's wake rule (its URL confirmed since
  its last registration, and no wake outstanding). A client row is never
  woken: its own relay exchanges instead (§10.5). This replaces `isPhpPeerInterface()`, which keyed on non-null
  `peer_url` and `peer_interface_id` columns that any registrant could fill;
- never create local bindings, as today.

Path updates follow §8.5, the same rule as on every other row: a random blob
already seen never moves a path through a transit row either. Revision 2 kept
the `shorter_path_replaced` exception for proven transit rows. With open
peering anyone can prove one, so revision 3 removes it.

Every other row is an **endpoint row**.

### 8.2 Endpoint rows: the identity guard

The guard applies to every announce, path responses included, received on an
endpoint row, in every mode:

```
I        = SHA-256(announce public key)[:16]
owner(R) = R.identity_hash                     if R.registration_proof = 'signed'
         = R.claimed_identity_hash             if R.registration_proof = 'none', R.client = 'rns-js',
                                                  enforce_signed_registration is off,
                                                  and no row has identity_hash = R.claimed_identity_hash
         = none                                otherwise
accept   ⇔ owner(R) ≠ none  and  I = owner(R)  and, for a 'none' row, §8.3 allows it
```

An announce that is not accepted is dropped whole: no remembered key, no local
binding, no path update, no announce cache, no relay. It is logged as
`[ANNOUNCE-FOREIGN] interface=<id8> dest=<hash> identity=<I8> owner=<…>`.

`owner(R)` is evaluated when the announce arrives, so a legacy row whose claim
becomes owned by a signed row loses it at once, even if it raced past §7.2
step 4.

- **Nothing legitimate breaks.** The web client registers IN destinations only
  under `IdMgr.id` (Retichat-js `app.js:5816`, `lxmf_router.js:70`, per the
  critique). Its delivery, rfed and distro announces all carry its own
  identity. Distro announces from RFed reach the relay through the gateway, a
  transit row.
- **Browsers are endpoints.** Modes 3, 5 and 6 are refused for `client =
  rns-js` at registration, signed or legacy. The guard runs in every mode
  anyway, so an old row that already holds a transit mode is covered.
- With the guard in place, the endpoint→endpoint overwrite in
  `registerLocalDestinationIfOwnInterface` can move a binding only between
  rows that have the same owner, such as two tabs of one identity (D11). The
  identity fallback in `deliverLocallyIfKnown` only ever sees rows that passed
  the guard.

### 8.3 Legacy endpoint rows: no replays, no takeovers

A legacy claim costs nothing, so `owner(R)` of a `none` row proves nothing.
Until enforcement, an announce that passed §8.2 on a `none` row is **still
dropped** when either of these holds:

1. **Seen.** Its random blob is already recorded for that destination
   (`path_entries.random_blobs_json`), or its packet hash equals the one
   `known_destinations` remembers for it. It is a replay, and reference RNS
   refuses seen blobs too. No timer is involved.
2. **Held.** Another row already holds the destination: a
   `local_destinations` binding on another row, or a usable path entry through
   another row.

These are logged `[ANNOUNCE-LEGACY-REFUSED] interface=<id8> dest=<hash> reason=<seen|held>`.

Rule 2 is what protects native-app users. They never register on a relay, but
this relay reaches them through the gateway, so their destinations are
"held". The cost is that an old cached tab cannot take over a destination the
relay already reaches through another row: for example, when its user
switched relays, or also uses the identity in a native app. Its inbound then
follows the existing binding or path until the tab reloads into code that
signs (§11.3). A signed row is never subject to §8.3.

What remains open until enforcement is in §16.1.

### 8.4 Where the guard runs

The guard (§8.2 and §8.3) runs **immediately after
`AnnounceValidator::validate`**. It comes before
`rememberKnownDestination`, `registerLocalDestinationIfOwnInterface`,
`upsertPathFromAnnounce`, announce caching and relaying. Today
`processAcceptedAnnounce` calls `rememberKnownDestination` first
(`request_control_plane_trait.php:15-33`), and that call overwrites the stored
ratchet, `app_data` and packet hash. A dropped announce MUST leave no trace
other than its log line.

That `rememberKnownDestination` stores the ratchet and `app_data` of any valid
announce, replays included, matches RNS 1.5.2 (`Identity.validate_announce`
calls `Identity.remember` and `_remember_ratchet` for every valid copy). This
spec does not change it (§16.1).

### 8.5 Path rules: a seen random blob never moves a path

On **every row**, transit and endpoint, signed, confirmed, local and legacy
alike, from Phase 1: an announce whose random blob is already recorded for
the destination (`path_entries.random_blobs_json`) never creates or replaces a
path, whatever its hop count. In `upsertPathFromAnnounce`
(`request_control_plane_trait.php:446-604` at bae739a) that means:

- no `shorter_path_replaced` for a seen blob. Today that branch replaces the
  path whenever the hop count is lower, seen or not (lines 515-526). The hop
  count is not signed, so a replay with it lowered to 0 took the path (A4);
- no `unusable_path_replaced` for a seen blob (lines 512-514). A path that is
  expired, or whose row is not active, is replaced only by an announce with a
  blob not yet seen;
- every other branch is unchanged. They already require an unseen blob, or
  keep the existing path.

**This is RNS parity.** The reference decides it in the announce branch of
`Transport` (`random_blobs` is the path entry's `IDX_PT_RANDBLOBS`):

- **RNS 1.5.2**, the parity target (`Transport._inbound`, Transport.py:2213-2296
  in the workspace `.venv`): an unknown destination is added (2222-2225). With
  equal or fewer hops, the path is replaced only if `not random_blob in
  random_blobs and announce_emitted > path_timebase` (2236-2240). With more
  hops, an expired path is replaced only by an unseen blob (2267-2275), and a
  live one only by a more recently emitted, unseen announce (2281-2286).
- **RNS 1.1.3**, the `Reticulum-master` mirror in this workspace
  (`Transport.inbound`, Transport.py:1687-1776): the same checks, except that
  with equal or fewer hops an expired path is also replaced by any unseen blob
  (1703-1709), and there is no gravity branch.

In neither version does a lower hop count let a copy of an announce already
heard replace a path. 1.5.2 lets such a copy (same emission time) replace a
path in two cases, neither keyed on hop count: the copy arrived on an
interface with a higher operator-set `gravity` than the path's (2241-2251),
or the path was marked unresponsive by a failed link and the copy has more
hops (2292-2295; 1.1.3 has this one too, 1766-1771). The relay has neither an
interface gravity nor an unresponsive mark, so neither applies. If either is
ever added, it keys on the receiving row's operator setting or on this relay's
own failure event, never on the hop count, which nothing signs.

**What it costs.** `shorter_path_replaced` was added for the documented
retichat↔selectiv direct-versus-gateway case (comment at lines 516-524): the
same announce arrives through the gateway (6 hops) and through the direct peer
(2 hops), and whichever arrives first claims the blob. When the gateway copy
wins, the direct copy no longer replaces it. The path moves to the direct
peer only when a later announce (a new blob) reaches this relay through the
direct peer first (`better_or_equal_hops_newer_announce`). Until then traffic
for that destination takes the gateway. James: "Leave it, watch it"
(2026-10-03). §11.2's Phase 1 note is the watch. If it ever matters, the fix
is RNS 1.5.2's own answer to this case, a per-interface `gravity` (§16.1.13).

---

## 9. The gateway

The gateway is the Reticulum-rust `PostInterface`. The Python `PostInterface`
in `python/RNS/Interfaces/PostInterface.py` MUST reach parity.

Since James's decision of 2026-10-04, a PHP relay registering at a peer relay
follows this section too, as §10 sets out: its identity file is its
transport identity (§10.2), its registration is §10.4's, and its backoff runs
without a timer (§10.6). Since revision 7 the analogy is exact: the relay's
transport id is that identity's hash, as a gateway's is its transport
identity's (RNS `Transport.identity.hash`). At the relay it registers at,
nothing tells the two apart: both are signed `reticulum-php` rows.

1. **Identity.** The gateway signs with its **persistent transport identity**.
   - **Rust:** `Transport::start` loads or creates `storage/transport_identity`
     before `load_system_interfaces` builds the interface. Add an accessor that
     returns the identity, and clone it once in `start_exchange_worker`,
     outside the interface lock (`process_incoming` already takes `TRANSPORT`
     inside it, so a second lock-order edge must be avoided). A missing
     identity at registration is a loud ordering error (§5 of the principles).
     It never leads to an unsigned registration.
   - **Python:** RNS 1.5.2 builds interfaces in `__apply_config` before
     `Transport.start`. On a non-transport node, `Transport.identity` is also
     replaced by an ephemeral one at every start. So `PostInterface` MUST
     itself load or create `RNS.Reticulum.storagepath + "/transport_identity"`
     with `Identity.from_file` / `Identity().to_file`, using the same file and
     format, before its first registration. `Transport.start` then loads the
     same key. It signs with that persistent key whether or not
     `enable_transport` is set. A failed registration MUST NOT abort interface
     creation (today it does, from `__init__`).
2. **Body.**
   - **Wake mode:** `client = reticulum-php`, `mode` as configured (6 in
     production), `peer_url` = the wake base URL (`wake_url` minus `/v1/wake`),
     and `peer_interface_id` / `peer_session_token` random per process, as
     today. All of them are signed.
   - **Poll mode:** `client = rns-post-interface`, with `transport` and no peer
     fields.
   - The gateway fetches its challenge with its own public key. It signs no
     relay address (§3.2).
3. **No list.** Revision 2 required the gateway's identity hash in
   `[registration] transit_identities` on every relay. Peering is open, so
   revision 3 has no such list: a gateway that signs with its transport
   identity gets a transit row on any relay (§8.1), and no relay's config
   names it. The gateway logs its identity hash at startup.
4. **One row for good.** The row is keyed by the gateway's identity hash, so
   restarts keep the same `interface_id` and PHP-side paths survive gateway
   restarts (they do not today). `peer_url` becomes an address attribute that
   the relay wakes, once §9.8 has confirmed it.
5. **The 401 is the event** (this fixes the wake-mode wedge). On `401` from an
   exchange, the interface **stays online in Transport**, so nothing goes
   through an `[OFFLINE-DROP]` window. It immediately fetches a challenge,
   registers signed and continues the same exchange cycle with the new
   session. That happens at most once per 401: a 401 right after a fresh
   registration is logged and ends the cycle. After a relay DB reset the row
   is gone and the relay will not wake the gateway. The gateway's next
   outbound packet still drives an exchange, because backbone announces never
   stop. That exchange gets the 401 and re-registers.
6. **Failure: exponential backoff, James's decided exception to §3 of the
   principles.** `DESIGN_PRINCIPLES.md` §3 forbids retries. Its decided
   exception of 2026-10-03 for "the gateway's registration at a PHP relay
   after a hard refusal" says: when a relay answers the gateway's signed
   registration with a server error or a terminal refusal code, "the gateway
   re-registers with exponential backoff — 2 s, doubling, capped at 5 min —
   and resets the backoff on a successful registration or whenever the relay
   wakes it". James's decision covers a network failure the same way. The
   exception covers that registration only: exchanges, sends, links and path
   requests are still never retried.
   - **What starts it.** A registration that fails on the network, is
     answered with a 5xx, or is answered with a terminal code from §6. That
     includes the challenge request that precedes it, a second
     `409 stale_challenge`, and a signed answer without
     `session_token_encrypted` (step 7). A challenge `404` is not a failure:
     the gateway registers legacy (§11.4). A first `409 stale_challenge` is
     not a failure either: it is the one protocol step of §6.
   - **Surfaced while it lasts.** Each failed attempt logs ERROR with the
     relay, the status, the code and the delay before the next attempt
     (§13). The interface is offline in Transport with that code as its
     reason, visible in `rnstatus`, so nothing is routed into it. Each
     attempt is still a network send under §1 of the principles: a late
     success is asserted and logged.
   - **Schedule.** After the n-th consecutive failed registration the next
     one starts `min(2 s × 2^(n−1), 300 s)` later: 2, 4, 8, 16, 32, 64, 128,
     256, 300, 300 … seconds.
   - **Resets.** A successful registration puts the interface back online in
     Transport and resets the delay to 2 s. A wake from the relay (wake mode)
     resets the delay to 2 s and starts a registration at once, in place of
     the pending wait. Poll mode has no wakes, so only a success resets it.
   - **One in flight.** Only one registration is in flight at a time. A wake
     that arrives while one is in flight resets the delay, so a failure of
     that attempt waits 2 s, and starts nothing else.
   - **Outbound packets start nothing.** Revision 1 re-registered on every
     outbound packet, which would hammer a failing relay at traffic rate.
     Nothing is routed into an offline interface, and only the schedule, a
     wake or a restart starts a registration.
   - **`409 session_superseded` is terminal, with no backoff.** It answers an
     exchange, not a registration, so the exception does not cover it.
     Another process with the same transport identity registered after this
     one, and the newest registration wins (§6.1). Registering again would
     evict it, and the two would take turns. The interface stays offline in
     Transport until the process restarts, and a wake does not restart it.
   - **Exchanges are not retried.** The exchange back-off of up to 60 s in
     today's `post_interface.rs` exchange worker (`consecutive_errors`) is
     removed (§3 and §4 of the principles). A failed exchange is logged, and
     the next exchange waits for the next wake, outbound packet or (poll mode)
     poll. A `401` is the event of step 5.
   - A relay whose DB was reset and that answered 5xx no longer needs a
     gateway restart: the schedule reaches it once it is healthy, at most
     5 min later.
7. **Decrypting.** The gateway decrypts `session_token_encrypted` with the
   transport identity (§5).
   - If the challenge endpoint answers `404`, it registers legacy and accepts
     a plaintext token, until `enforce_signed_transit` (§11).
   - If a signed registration is answered without `session_token_encrypted`,
     that is a protocol error: terminal, under the backoff of step 6.
8. **Its wake URL is confirmed before it is woken.** §9.8.

### 9.8 Confirming a gateway's wake URL

James's answer to revision 3's question 3 (2026-10-03): "Confirm it first." A
relay never wakes a signed gateway row at its `peer_url` until the gateway's
own wake server has answered a one-time nonce at that URL, signed with the
transport identity the row was registered with. It follows §10's PHP-peer
confirm: a detached runner, bounded pending records, the canonical URL stored
with the pending record, the confirm sent only to that stored URL, and nothing
woken until it is confirmed.

Unlike §10, the answer is a signature, not the nonce sent back. Reaching the
URL alone proves only that something there answers. A server at that URL that
echoes request bodies would confirm itself (vector `answer-echo-nonce`). The
signature shows that whoever answers at the URL holds the row's key.

**Bytes.**

```
signed = lp("reticulum-post/gateway-confirm/v1")   -- 33 bytes, lp = 0021…
      || lp(nonce)                                  -- 16 bytes
      || lp(identity_hash)                          -- 16 bytes, the row's
      || lp(utf8(relay_url))                        -- exactly as in the request body
      || lp(utf8(peer_url))                         -- exactly as in the request body

signature = Ed25519-sign(ed25519_private_key, signed)  -- the transport identity; RNS Identity.sign, 64 bytes
```

`lp` is §3's. No JSON is signed. The domain keeps these bytes apart from a
registration's: its `lp` starts `0021`, a registration's `001a` (vector
`answer-registration-signature`), and RNS-signed data starts with a 16- or
32-byte hash, so a collision needs a 128-bit preimage (§3). `relay_url` binds
the answer to the relay that asked, and `peer_url` to the URL being
confirmed. A signature over another nonce, another URL or for another relay
does not verify (vectors `answer-other-*`).

Worked example, vector `gateway-confirm`: relay A confirms the URL the
`gateway-wake` row stores, at `http://gateway.example.net:4371/v1/gateway/confirm`.

```
signed     0021 7265746963756c756d2d706f73742f676174657761792d636f6e6669726d2f7631        "reticulum-post/gateway-confirm/v1"
           0010 47e0c3c9956c9ec00f3e328018178229                                            nonce
           0010 03f43750ef2ba1ad2d3c67c5f358349b                                            identity hash (gateway)
           0025 68747470733a2f2f72656c61792d612e6578616d706c652e6f72672f7265746963756c756d  "https://relay-a.example.org/reticulum"
           001f 687474703a2f2f676174657761792e6578616d706c652e6e65743a34333731              "http://gateway.example.net:4371"
                                                                                            143 bytes in all
signature  2085e0334b54b74f152457865c7e4ac4d18059d0c67eef051fa5902bac469a8f
           5d32b0a333fdde05c5e21a5690369e6bf9e1fe678d7f1effdb97b3fe4e743001
```

**The relay.**

1. **When: every signed registration.** After every signed bind of a
   `reticulum-php` row commits (§4.4), even with the URL unchanged (James,
   2026-10-03: "Re-confirm every time"). The bind has already cleared the
   row's confirmation, so from that commit the row is not woken until this
   confirm succeeds. Anything queued for it in the gap goes out in the one
   wake sent at confirm time (step 5).
2. **Pending record.** Take the lock of a new runner (§10.10), then upsert
   `gateway_wake_confirms` for the row's `interface_id`, one record per row:
   the canonical `peer_url` and `peer_url_key` just stored, the
   `registration_seq` the bind set, `nonce_hex` = 16 random bytes in hex, the
   new `runner_id`, and `created_at` (shown, never compared). A newer
   registration replaces the record, and the older runner's result is then
   discarded (step 5). At most **64** records exist in all. When 64 records
   of other rows already exist, the relay first checks each of their runners
   (§10.10): a record whose runner is gone is a failed confirm (step 6,
   reason `runner_gone`) and is deleted. If 64 still remain, no record is
   made, the new runner's lock file is deleted, the row stays unconfirmed,
   and the relay logs `[GW-WAKE-CONFIRM-BACKLOG] identity=<H>`. The
   registration still succeeds. Commit before step 3.
3. **Runner.** Spawn the record's `gateway-wake-confirm` runner as §10.10
   says, handing it the lock, and log `[GW-WAKE-CONFIRM] identity=<H> key=<8>`.
   A spawn that fails, or a host that cannot spawn one, is a failed confirm
   (step 6). The runner POSTs to the record's `peer_url` followed by
   `/v1/gateway/confirm`, and to no other URL:

   ```json
   {"version": 1, "nonce": "<nonce_hex>", "identity_hash": "<the row's 32 hex>",
    "relay_url": "<own canonical host_url>", "peer_url": "<the record's peer_url>"}
   ```

   A §1 assertion runs from the POST to the answer. An answer later than 5 s
   is logged `[GW-WAKE-CONFIRM-LATE]`, a §1 violation, and still decides the
   outcome.
4. **The answer.** It is accepted only if the status is `200`, the body is a
   JSON object with exactly one key, `signature`, whose value is 128
   lower-case hex, and `sodium_crypto_sign_verify_detached` verifies it over
   the bytes above, rebuilt from the body the relay sent, with the row's
   `identity_public_key[32:64]`. Anything else is a bad answer (status or
   shape) or a bad signature.
5. **Confirmed.** In one transaction:
   `DELETE FROM gateway_wake_confirms WHERE interface_id = :id AND nonce_hex = :n`,
   requiring `rowCount() = 1` (otherwise a newer record replaced this one:
   log `[GW-WAKE-CONFIRM-STALE]` and stop), then
   `UPDATE interfaces SET wake_url_confirmed_key = :k, wake_url_proven_key = :k WHERE interface_id = :id AND registration_seq = :seq AND registration_proof = 'signed'`
   with the record's key and seq. `wake_url_proven_key` records that this
   row's identity has proven this URL here. Unlike the confirmation, a
   re-bind (§4.4) does not clear it, and §10.3 reads it (A16). Only a retire
   (below) clears it. `rowCount() = 0` means a newer registration
   bound the row after this confirm was sent, whether or not it changed the
   URL: log `[GW-WAKE-CONFIRM-STALE]` and change nothing. The seq, not the
   URL, is what makes this exact. A newer registration with the same URL
   can commit its bind (clearing the confirmation) before it replaces the
   record, and in that window the DELETE above still succeeds. Otherwise log
   `[GW-WAKE-CONFIRMED] identity=<H> key=<8>`, and if the row has queued
   outbound packets, send it one wake, so what queued before the confirm,
   including during the gap since the bind, moves at once. Then the relay
   retires every other row for that URL (below).
6. **Not confirmed.** A network failure, any other answer, a signature
   that does not verify, or a runner that is gone before it wrote its outcome
   (§10.10) or could not be spawned: delete the record by
   `(interface_id, nonce_hex)`, log
   `[GW-WAKE-CONFIRM-FAIL] identity=<H> key=<8> -> <status> <reason>`
   (`reason` is `network`, `bad_answer`, `bad_signature`, `runner_gone`,
   `runner_unavailable`, or the gateway's `error` code), and change nothing
   else. A gone runner's record is found by step 2's check or by §10.3's,
   whichever needs it first, and the row's next registration replaces it in
   any case. Its confirm is not started again, as no failed confirm is (§3
   of the principles). The row is not woken. No timer
   starts another confirm: the gateway's next signed registration does (a
   restart, a `401`, or a changed URL). Until then the gateway still works by
   its own exchanges, which its outbound packets drive (§9 step 5), and
   packets for it wait in its queue for the next one. `/health` shows the
   row's `wake_confirmed` (§12.5).

**A URL belongs to one identity** (James, 2026-10-04: accepted, question 3
of revision 6, gateways included). Once step 5 confirms URL `U` for row `R`,
every other signed `reticulum-php` row whose `peer_url_key = key(U)` is
retired, in the same transaction. Retiring a row:

- sets `registration_proof = 'retired'`, status offline,
  `wake_url_confirmed_key` and `wake_url_proven_key` NULL and
  `wake_outstanding` 0;
- deletes its `gateway_wake_confirms` record, if it has one (its runner's
  result is then discarded as stale, step 5);
- replaces its session token with a random value that is never sent;
- clears its peer fields;
- deletes its traffic with §4.5's deletion set.

It keeps `identity_hash`, `identity_public_key` and `registration_seq`, so the
seq never goes back (§12.5). It is logged
`[REG-RETIRE-IDENTITY] identity=<old H> by=<H> key=<8>`.

A retired row is not a transit row and authenticates nothing. If its identity
ever registers again, §4.4 re-binds it like any other row and sets its proof
back to `signed`.

This is how a gateway or PHP relay that lost its identity file (§10.2) stops
leaving a dead row behind. It is safe because only the holder of the key the
server at `U` signs with can confirm `U`. Two identities cannot both be served
at one URL, because the confirm handler signs only for its own identity
(check 2).

**Wake rule.** A signed gateway row is woken only at its stored `peer_url`,
only while its `wake_url_confirmed_key` equals its `peer_url_key`, and only
while it has no outstanding wake (`wake_outstanding = 0`):

- a wake that left, meaning its request was written in full, sets
  `wake_outstanding`. A wake that did not leave is already reported as
  `[WAKE-DROP]` (connect, handshake or write failure,
  `fireAndForgetWakeWithSocket`, `request_php_wake_trait.php:162-232`). It
  sets nothing;
- an authenticated exchange from the row, and its next signed bind (§4.4),
  clear it.

So a gateway gets at most one wake between two of its own exchanges. A live
gateway answers a wake with an exchange, which allows the next one. If a
wake that left is lost, relay-to-gateway traffic waits for the gateway's next
exchange, which its own outbound packets drive (§9 step 5).

PHP-peer URL rows are proven by §10. Legacy (`none`) rows are woken as today
until `enforce_signed_transit` (§16.1.2).

**What ends wakes to a gateway that stops.** Nothing in the row's lifetime
does. A signed row is permanent (§12.4, §12.5). At bae739a every peer row
receives every relayed announce whatever its status (`allOtherInterfaceIds`,
`request_relay_routing_trait.php:933-949`). Pending outbound packets are never
expired (`request_maintenance_trait.php:80`). And `dispatchWakes` wakes every
peer row with pending outbound at most once per `min_wake_interval_ms`
(`request_php_wake_trait.php:75-113`). Without the rule above, a gateway that
stopped would be woken at its last confirmed URL for as long as the row
exists. With it:

- **At most one wake is delivered after the gateway's last exchange.** A
  host that later takes over its name (a lapsed dynamic-DNS name) and accepts
  connections on that port receives at most that one wake: a fixed body
  carrying no credentials.
- **Every later attempt fails before anything is sent**, or is not made. A
  name that no longer resolves, or a host that refuses, is a `[WAKE-DROP]`
  each time: nothing leaves, and it costs this relay one failed connect per
  `min_wake_interval_ms`, as any dead peer does today.
- **The row's own wakes end** only when its gateway registers again (which
  confirms afresh) or an operator deletes the row (§12.5).

**The gateway.** Its wake server (Rust `PostInterface::wake_server`, Python
`PostInterface._start_wake_server`) answers `POST /v1/gateway/confirm`. A PHP
relay answers the same request, with checks 3 and 4 as §10.5 states them.

- **The path** is matched exactly, before the wake route. It does not begin
  with `/v1/wake`, because today's Rust wake server treats any request whose
  text starts with or contains `POST /v1/wake` as a wake.
- **Checks, in order:**
  1. the body is a JSON object with exactly the five keys, `version` is `1`,
     `nonce` and `identity_hash` are 32 lower-case hex, and `relay_url` and
     `peer_url` are non-empty strings of at most 512 bytes. Otherwise
     `400 {"error": "bad_confirm_request"}`;
  2. `identity_hash` is its own transport identity's hash. Otherwise
     `403 not_my_identity`;
  3. `canonical(relay_url)` (§10.1) equals the canonical form of its
     configured `node_url`, the rule its wake route already applies to
     `waker_url`. Otherwise `403 unknown_relay`: the gateway is not a signing
     oracle for relays it does not use;
  4. `canonical(peer_url)` equals the canonical form of its configured
     `wake_url` (canonicalisation drops `/v1/wake`), which is the `peer_url`
     it signs in its registration. Otherwise `403 not_my_wake_url`;
  5. it signs the bytes above, built from the body as received, with the
     transport identity it registers with (§9 step 1), and answers
     `200 {"signature": "<128 hex>"}`.
- **No session is needed.** The handler depends only on the config and the
  transport identity, so it answers correctly even before the gateway has
  read its registration's answer. The confirm can arrive that early, because
  the relay starts it as soon as the bind commits.
- **Ordering** (§5 of the principles): the wake listener's successful bind is
  the event the first registration waits for. A bind that fails is an ERROR.
  The gateway still registers, because its exchanges work without wakes; the
  confirm then fails, and the relay does not wake it.
- **Logging:** NOTICE for each confirm it signs, with the relay URL; WARNING
  for each it refuses, with the code.

**When the wake URL changes.** `wake_url` is configuration, read at start, so
a change means a restart. The restart's signed registration names the new
`peer_url` and, like every signed registration, clears the confirmation in
its bind (§4.4) and starts a confirm. The relay then wakes neither URL: not
the old one, which the row no longer names, and not the new one until its
confirm lands. A confirm still in flight for the old URL fails at the gateway
(check 4) or at the relay (step 5).

Vectors: `gateway_confirm` (§14).

---

## 10. PHP relay peers register like gateways

James's decision of 2026-10-04: a PHP relay registers at a peer relay exactly
as the gateway registers at a relay (§9). This replaces revisions 2 to 5's
one-time-nonce handoff.

A gateway and a PHP peer play the same role: a neighbour reached over HTTP
that relays for others and is woken when there are packets for it. They
differed for two reasons only:

- a PHP relay had no Reticulum key;
- peers held credentials both ways, because each pulled from the other.

The gateway shows that one registration is enough: it pushes and pulls in one
exchange, and the relay only wakes it. So each PHP relay now has its own
persistent identity (§10.2), and a peering is one relay's signed registration
at the other (§10.4). The session token comes back encrypted to the
registrant, as for everyone (§5; James, 2026-10-04: keep it).

When relay A registers at relay B, A is the **client** of that link and B the
**server**. A's row for the link is its **client row** (§10.4). B's row for it
is A's signed row, exactly as for a gateway.

Gone from this spec, along with revision 5's §10.2 to §10.10:

- the nonce handoff: `connectToPeer`'s nonce, the receiver's pending record
  and confirm runner, `POST /v1/peers/confirm`, promotion on first use;
- the `peer_registration_nonces` and `peer_registration_pending` tables;
- the `confirmed` proof;
- the wake-back with `session_lost`;
- the initiator rule and its one-sided-peering gap;
- the PHP-peer-only handling of `401` and `409` on a pull.

Until `[registration] register_at_peers` is switched on (§11.1), a relay keeps
today's legacy peering (bae739a) unchanged, so the live peering moves over in
one step (§11.2).

### 10.1 The canonical URL and its key

`canonical(u)` (vectors: `url_canonical`):

1. Refuse, rather than fix:
   - a non-ASCII character (an IDN host is written in its `xn--` form);
   - any character ≤ 0x20 (whitespace or control);
   - `?` or `#` anywhere;
   - userinfo (`@` in the authority);
   - a scheme other than `http` or `https`;
   - a host that is not an IPv6 literal in brackets or `[A-Za-z0-9.-]+`;
   - a port outside 1–65535.
2. Lower-case the scheme and the host. Drop the port if it is the scheme's
   default.
3. Strip trailing `/`, then one trailing `/v1/wake`, then trailing `/` again.
   The path otherwise keeps its case and its percent-encoding as given.

`peer_url_key = SHA-256 hex of canonical(u)`. The relay stores `peer_url` in
canonical form together with `peer_url_key`, and **every lookup by URL is
`peer_url_key = :key`** (§12.2). Config values (`node_url`, `host_url`) are
trimmed and then canonicalised when loaded. One that does not canonicalise is
a config error: it is logged and that peer is skipped.

A relay's canonical `host_url` MUST equal the canonical `node_url` its peers
configure for it. It is the `peer_url` the relay registers with (§10.4), the
URL its peer confirms and wakes (§10.5), and what §10.3 compares.

**Where credentials go.** A relay sends its session token at X only to the
stored canonical URL of its client row for X, which comes from its own
`[interfaces]` config. The server sends the client no credentials at all,
only wakes and confirms, to the client's stored, confirmed URL (§9.8). Nothing
is ever sent to a URL taken from a request (a `waker_url`, a `relay_url`).
§0.1 is the case of breaking this rule, fixed live by d3a0eb5. An `http`
`node_url` sends the token in the clear; production configs use `https`, and
staging may use loopback `http`.

### 10.2 The relay's identity

- **What it is.** A Reticulum identity like any other: an X25519 key pair and
  an Ed25519 key pair.
  - The private key is the 64 bytes `x25519_private(32) || ed25519_seed(32)`,
    the layout RNS `Identity.to_file` writes and `Identity.from_file` reads
    (vector `php_relay_peer.identity_file_hex`).
  - `x25519_pub = sodium_crypto_scalarmult_base(x25519_private)`;
    `ed25519_pub` comes from `sodium_crypto_sign_seed_keypair(seed)`; and
    `H = SHA-256(x25519_pub || ed25519_pub)[:16]`, as in §1.
- **Where it lives.** A file at `[registration] identity_path`, outside the
  web root and outside the database, so a DB reset (`clearAllData()`, a new
  SQLite file, a dropped MySQL schema) does not change it. The default is
  `relay_identity` in the directory of `sqlite_path` (`php/var/`). Phase 1's
  gate checks that the file cannot be fetched over HTTP (§11.2). The same
  directory holds the runner directory (§10.10).
- **Created on first use, once.** Since revision 7 the first use is the first
  ingest request on this code, because every ingest request needs the
  transport id (§10.2.1). The relay reads the file. If it does not exist, the
  relay:
  1. creates the directory, mode 0700, if it does not exist;
  2. writes 64 bytes from `random_bytes` to a temporary file in that
     directory, mode 0600;
  3. `link()`s it to `identity_path`, then unlinks the temporary file.

  `link()` fails when the name already exists. So of two concurrent first
  requests exactly one creates the file and the other reads it, and no reader
  ever sees a partial file. A file that exists but is not 64 bytes is a loud
  error: `[RELAY-IDENTITY] ERROR`. It is never overwritten. What the relay
  does without its identity is in §10.2.1.
- **Never shown.** The private key never appears in `/health`, `/debug`,
  `/v1/monitor*`, logs or responses. The identity hash is public: `/health`
  shows it as `transport_id` (§12.5), and every announce the relay relays
  carries it. It is logged as `[RELAY-IDENTITY] created hash=<H>` when the
  relay creates the file. Revision 6 also logged it when the relay first
  used the identity in a process; each PHP request is its own process, and
  every ingest request now loads the identity, so that would be a line per
  request.
- **What it does.** It signs §3's registration bytes and §9.8's confirm
  answer, and decrypts this relay's own session tokens (§10.4). Since
  revision 7 its hash is also the relay's transport id (§10.2.1). Nothing
  else.
- **One file per relay, never copied.** Two relays with one identity file
  would have one transport id, and each would take packets meant for the
  other as its own. Staging creates its own file. Phase 1's gate checks that
  the two relays' `transport_id` differ (§11.2).
- **If the file is lost.** The next ingest request creates a new identity,
  and with it a new transport id (§10.2.1). The relay's next registration at
  each peer is then:
  1. a new identity row there (§4.4's INSERT), not a re-bind;
  2. confirmed afresh (§9.8). That confirm retires the old identity's row at
     the peer (§9.8, "A URL belongs to one identity"): its traffic is
     deleted, and its identity and seq are kept, so the seq invariant holds
     (§12.5).

  Peers need no config change. A client row registered under the old identity
  registers again at the next ingest request, because its `registered_as` no
  longer matches (§10.6).

#### 10.2.1 Its hash is the relay's transport id

James's answer to revision 6's question 1 (2026-10-04): switch the relay's
transport id to the hash of its persistent identity, as in RNS, and keep
treating the old id as the relay's own too, so that packets on paths learned
before the switch are not dropped.

- **The transport id is `H`.** It is the 16 bytes the relay writes as the
  transport id into every announce it relays (`transportedAnnounceRelayRaw`,
  `request_relay_routing_trait.php:105-130` at bae739a), every path response
  it builds (`buildPathResponsePacket`, `request_path_state_trait.php:203-230`)
  and every path request it sends (the requestor field,
  `request_relay_routing_trait.php:615-621`). Neighbours learn it as this
  relay's address: the next hop of their paths through it. In RNS 1.5.2 it is
  `Transport.identity.hash`, loaded from `storage/transport_identity`
  (Transport.py:319-327). Until revision 7 it was 16 random bytes that
  `transportIdentityHashHex()` created in `transport_state` under
  `identity_hash_hex` (`request_interface_runtime_trait.php:22-43`), and
  every DB reset made a new one.
- **Two ids are this relay's own.** A packet in transport (HEADER_2) is for
  this relay when its transport id is `H`, or the **pre-switch id** `P`, the
  value of `transport_state.identity_hash_hex` if that row exists. Three
  checks compare a packet's transport id with the relay's own, and each MUST
  accept both, through one function:
  - the packet filter (`applyPacketFilter`, `request_packet_ingest_trait.php:55`);
  - the forward rewrite (`relayPacketBase64`, `request_relay_routing_trait.php:71-72`);
  - the outbound rewrite (`request_outbound_batch_trait.php:298-299`).

  Everywhere the relay writes a transport id, it writes `H`, never `P`.
  RNS checks the same three places against its one id (Transport.py:1631,
  2019, 2541). Recognising `P` as well departs from the reference, on
  James's word, and only so that the switch drops nothing.
- **Who still sends `P`.** Every neighbour that learned a path through this
  relay before the switch: the gateway's path table, the peer relay's
  `path_entries.next_hop_hex`, and any other node that exchanges with it.
  Browsers do not: they send in HEADER_1, and the relay puts their packets
  into transport itself. A neighbour moves to `H` for a destination when that
  destination's next announce reaches it through this relay, which now
  carries `H`. Until then its packets carry `P` and are forwarded exactly as
  before. Vectors: `php_relay_peer.transport_id`.
- **How long `P` stays.** This code reads `P` and never writes it. So `P` is
  exactly the id the relay used before the switch, for as long as the
  database keeps it. No clock ends it. A DB reset (`clearAllData()`, a new
  SQLite file, a dropped schema) deletes it. That reset also deletes every
  path, link and queued packet the relay had, and at bae739a every reset
  changed the transport id outright, so losing `P` then costs nothing that
  a reset did not cost before. After it, `H` alone is the relay's own, and
  `H` survives every later reset. A rollback to bae739a finds `P` where old
  code left it and uses it again (§11.5).
- **No identity, no transport.** The prelude of every ingest endpoint
  (`/exchange`, `/tx`, `/poll`, `/v1/wake`, and each runner's own) loads the
  identity before the first packet is read (§5 of the principles). If the
  file cannot be loaded or created (a file of the wrong length, a directory
  that cannot be created or written), the relay never makes up an id and
  never falls back to `P`. The endpoint answers
  `503 {"error": "relay_identity_unavailable"}` (§6) and logs
  `[RELAY-IDENTITY] ERROR <reason>`, and `/health` shows `transport_id: null`
  with the reason. Revision 6 had the relay register nowhere in that case.
  Now it also carries nothing, because every relayed packet needs the id. The
  registration and challenge endpoints do not need it and keep working.
- **When it switches.** In Phase 1, at the first ingest request on this code
  (§11.2). There is no switch to flip: accepting `P` makes the change
  invisible to every neighbour.

### 10.3 Who registers, and why there is exactly one link

Every relay registers at every relay in its own `[interfaces]`, at the
canonical `node_url`, with one exception. A relay R does not register at a
configured relay X, and stands down its client row at X if it has one
(§10.7), while both of these hold:

1. X's canonical `node_url` sorts before R's own canonical `host_url`, in byte
   order (vectors `php_relay_peer.link_order`);
2. R holds X's registration: a signed `reticulum-php` row with
   `peer_url_key = key(X)` that is neither retired nor closed, and either
   - whose URL is confirmed (`wake_url_confirmed_key = peer_url_key`), or
   - whose identity has proven that URL here before
     (`wake_url_proven_key = peer_url_key`, §9.8 step 5) and whose
     re-confirm is pending: a `gateway_wake_confirms` record whose runner is
     alive (§10.10). A record whose runner is gone is a failed confirm, and
     the check deletes it (§9.8 step 6).

Then X's registration at R is the link, and R relies on it. James accepted
this rule on 2026-10-04 (question 2 of revision 6), with the lasting double
link it allows (below). Revision 6 counted any pending confirm in condition
2. Revision 7 counts one only for an identity that has proven X's URL
before: anyone can register a row naming X's URL, and revision 6 let such a
row make R stand down (A16). The re-confirm that follows each of X's own
registrations still counts, which is what revision 6 counted pending
confirms for. Why this gives exactly one link, with A sorting before B:

- **One-sided config.** If only B configures A, B registers at A. Condition 2
  never holds at B, because A never registers at B. If only A configures B, A
  registers, and condition 1 is false at A. Either way there is one link.
  Revision 3's one-sided gap is gone: the relay that lists the other
  registers.
- **Both configure each other.** Condition 1 is never true at A, so A always
  registers at B. B registers at A until A's registration at B is in place,
  then stands down. When both register in the same moment, the end state is
  still A's registration, whichever lands first.
- **The rule never leaves zero links.** B stands down only while it holds A's
  registration, confirmed or being re-confirmed, and A never stands down for
  B. If A's link fails, A's own events re-form it (§10.6). If B loses A's row
  (a DB reset), condition 2 fails, and B registers again until A's
  re-registration is confirmed (§10.9). If B's confirm runner dies, its
  record is a failed confirm (§10.10), condition 2 fails, and B registers.
- **Neither relay needs the other's config.** Each decides from its own config
  and its own rows.
- **Nobody else can make R stand down.** Condition 2 needs a row whose URL is
  X's and whose identity's signature the server at X's URL has returned
  (§9.8): now, or before with a re-confirm under way. A stranger's row that
  names X's URL never has that, because X's handler signs only for X's own
  identity (§9.8, check 2), so it cannot make R stand down (A16). This lookup
  reads an identity row by `peer_url_key`, an exception to §7.1's rule that
  URL lookups exclude identity rows. It counts only rows whose URL that
  identity has proven.

What it costs:

- **A brief double link when both register at once.** Announces then reach
  the other relay twice, and paths may be learned through either row until
  the stand-down deletes the second row's paths (§10.7).
- **A lasting double link when A's URL fails to confirm at B** (James,
  2026-10-04: accepted) while B's own registration at A succeeds. Condition
  2 then fails, and B keeps its own link as well, until A's next
  registration confirms. B cannot wake A on A's link in that state, so B's
  own link is what carries B's traffic promptly. A confirm runner that dies
  at B is such a failure (§10.10).
- **After B's DB reset, the double link lasts until A's confirm lands**,
  not only until A registers: A's new row at B has proven nothing yet, so its
  pending confirm does not count (A16).

### 10.4 Registering at a peer

A relay registers at a configured relay X with §2 to §4's signed
registration, signed with its identity (§10.2), after fetching the challenge
with its own public key:

```json
{"name": "<own host>", "bitrate": 1000000, "mtu": 500,
 "metadata": {"client": "reticulum-php", "implementation": "Reticulum-post", "mode": 1,
              "peer_url": "<own canonical host_url>",
              "peer_interface_id": "<32 hex, random per registration>",
              "peer_session_token": "<64 hex, random per registration>"},
 "registration": {"version": 1, "public_key": "<128 hex>",
                  "challenge": "<96 hex>", "signature": "<128 hex>"}}
```

Vector `php-relay-peer` is this registration at relay A.

- **The fields.**
  - `mode` is 1 (`MODE_FULL`).
  - `peer_url` is the relay's own canonical `host_url`: the wake base URL X
    confirms and wakes.
  - The two peer fields are required for `reticulum-php` (§4.3.1). They are
    random per registration, signed and stored. No relay presents them under
    this spec: they are the gateway's legacy (§18).
- **X verifies it** like any signed registration (§4.3). There is no
  PHP-specific path. X answers with §5's response.
- **Decrypting the token** (vector `php_relay_peer.decrypt`, refusals
  `decrypt_negative`). The blob is `eph_pub(32) || iv(16) || ct || hmac(32)`:
  1. `ct` must be a positive multiple of 16 bytes. Otherwise refuse.
  2. `shared = sodium_crypto_scalarmult(x25519_private, eph_pub)`. Sodium
     throws on an all-zero result, and the relay also compares `shared` with
     32 zero bytes using `hash_equals`. Either one refuses.
  3. `derived = hash_hkdf('sha256', shared, 64, '', H)`: the salt is the
     relay's own identity hash, and the info is empty. Then
     `hmac_key = derived[0:32]` and `aes_key = derived[32:64]`.
  4. `hash_equals(hash_hmac('sha256', iv . ct, hmac_key, true), hmac)`, before
     anything is decrypted. Otherwise refuse.
  5. `openssl_decrypt(ct, 'aes-256-cbc', aes_key, OPENSSL_RAW_DATA, iv)`, which
     removes the PKCS7 padding. Otherwise refuse.
  6. The plaintext must be 64 lower-case hex. It is the session token.

  The response's `identity_hash` must equal `H`. Any failure is a protocol
  error, handled by §10.6's backoff. The relay never falls back to a plaintext
  field.
- **The client row** is this relay's interface toward X:
  - a URL row (`identity_hash IS NULL`) with `peer_url` = X's canonical
    `node_url` from the config, and its `peer_url_key`;
  - proof `local`, and `interface_id` = the first 32 hex of
    `SHA-256("reticulum-post/client/" || peer_url_key)`, so concurrent first
    registrations create it once (INSERT-or-ignore, then the claim of §10.6);
  - `peer_interface_id` and `peer_session_token` hold this relay's
    `interface_id` and session token **at X**;
  - `registered_as` holds the identity hash it registered with;
  - its own `session_token` is random and never sent, because nobody
    authenticates against a client row;
  - `peer_state` and `runner_id` (§10.6), and `exchange_pending_runner`
    (§10.5).

  Packets routed to X queue on the client row, and packets pulled from X are
  ingested as received on it. It is a transit row (§8.1). It is kept across
  registrations, so its queue and paths survive. A successful registration
  writes the new credentials, `registered_as`, `peer_state = 'connected'` and
  status `online` in one statement guarded by the claim. The first success
  also retires this relay's own legacy (`none`) URL rows with the same
  `peer_url_key`, with §4.5's deletion set: the rows of the legacy peering
  this link replaces (§11.2, Phase 3b).
- **At X**, the client's signed row is X's interface toward the client, as
  for a gateway.

### 10.5 Exchanges, wakes and the confirm

Client A, server B.

- **B confirms A's URL after every registration**, with §9.8's relay side
  unchanged. A's PHP answers `POST /v1/gateway/confirm` with §9.8's handler
  and its four checks, where:
  - check 3 is that `canonical(relay_url)` is the canonical `node_url` of a
    relay in A's `[interfaces]`, the only relays A registers at;
  - check 4 is that `canonical(peer_url)` equals A's canonical `host_url`.

  The handler reads only the identity file and the config: no session, no
  database row, no outbound call (vectors `php_relay_peer.confirm`,
  `confirm_refusals`, `confirm_answer_negative`).
- **B wakes A** at A's confirmed URL, under §9.8's wake rule: at most one wake
  between two of A's exchanges.
- **A's wake handler.** With `register_at_peers` on, `POST /v1/wake
  {"waker_url": W}`:
  1. runs the request prelude: maintenance, and any registration that is due
     (§10.6);
  2. looks up A's client row by `peer_url_key = key(canonical(W))`. Only a
     `local` row matches;
  3. if the client row is `connected`: spawns the exchange runner (subject to
     the spawn rule below) and answers `200` at once. The handler no longer
     exchanges inline, which closes §16.1.6 for these links;
  4. if the client row is `refused` (backing off): the wake resets the delay
     to 2 s and registers now, as the gateway's wake does (§9.6);
  5. if there is no client row, W is a `node_url` in A's `[interfaces]`, and
     §10.3 says A registers: registers now;
  6. otherwise: logs `[WAKE-UNKNOWN-PEER] <W>` or `[PEER-WAKE-IGNORED] <W>
     reason=<…>` and does nothing else. There is no wake-back.
- **The exchange runner** (a detached runner, job `peer-exchange`, spawned
  as §10.10 says). It runs the request prelude first, since maintenance
  rides ingest. Then:
  - it clears the client row's `exchange_pending_runner` by compare-and-swap
    from its own `runner_id` (the spawn rule below), and deletes its lock
    file, which has done its job. Only after that does it read the queue and
    POST to
    `<the client row's peer_url>/v1/interfaces/exchange` with A's
    `interface_id` and session token at B, the packets queued on the client
    row, A's acks and `max_packets`;
  - the response's delivery packets are ingested as received on the client
    row, and their batch id is acked on the next exchange. This is a push and
    a pull in one exchange, as the gateway's;
  - it goes on while the answer says more is waiting or packets remain
    queued, then exits;
  - its URL is only the client row's stored canonical URL;
  - a `401`, a `409` or a failure: §10.6.
- **When A has packets for B** they queue on A's client row. The request
  epilogue that queued them, where `dispatchWakes` runs today, spawns the
  exchange runner for each connected client row with queued packets or owed
  acks. A never wakes B: B's wakes exist only for B's packets for A.
- **The spawn rule**, for a wake and for the epilogue alike. A runner reads
  the queue and pulls only once it has cleared `exchange_pending_runner`. So
  a new runner is not needed while one was spawned for the row but has not
  yet cleared it: that one will carry what is queued now, and pull what B
  holds now. The client row's `exchange_pending_runner` names that runner.
  To spawn, the request reads it, then:
  - if it names a runner that is alive (§10.10), skips the spawn;
  - otherwise takes a new runner's lock, sets `exchange_pending_runner` to the
    new `runner_id` by compare-and-swap from the value it read, and spawns
    that runner. If the compare-and-swap fails (`rowCount() = 0`), another
    request has just spawned one: this request deletes its lock file and
    skips.

  So a wake or packet that arrives after a runner cleared the column always
  gets a runner of its own, and one that arrives before is carried by that
  runner, because the runner reads the queue only after clearing it. A
  runner that dies before clearing it leaves its id named, but its lock is
  free, so the next wake or queued packet spawns another. No clock is
  involved (James, 2026-10-04, question 4 of revision 6): revision 6's
  `min_wake_interval_ms` ceiling and its `last_exchange_spawned_ms` and
  `last_exchange_started_ms` columns are gone. Two runners may overlap, which
  exchanges already tolerate (today's inline wake exchanges overlap too).
- **B's side** is a gateway's: its packets for A queue on A's signed row, it
  wakes A, and it never calls A's exchange or sends A credentials.

### 10.6 Registration events and failures, without a timer

A client row's `peer_state` is one of:

- `registering`: the runner named by `runner_id` holds the claim;
- `connected`;
- `refused:<status>:<error>`, with `next_attempt_at` and `backoff_seconds`;
- `superseded`;
- `standing-down` (§10.7): the runner named by `runner_id` holds the claim.

**One registration at a time.** A registration starts only by claiming the
row. The request takes a new runner's lock (§10.10), then runs
`UPDATE interfaces SET peer_state = 'registering', runner_id = :r WHERE interface_id = :id
AND peer_state = :seen` (plus `AND next_attempt_at <= :now` for a due retry),
with `rowCount() = 1`, and then spawns runner `:r`, handing it the lock. A
claim that fails deletes the lock file and starts nothing. A spawn failure
(the shell's exit status) releases the claim at once and counts as a failed
attempt.

**A runner that is gone** (James, 2026-10-04, question 4 of revision 6).
Revision 6 left a dead runner's `registering` claim in place until an
operator's `GET /v1/initialize`. Now every ingest request's prelude checks
each configured relay whose client row is `registering` or `standing-down`:
is the runner its `runner_id` names alive (§10.10)?

- **Alive:** nothing happens, however long the runner takes. Its own events
  decide: an answer, a failure, or curl's ceiling.
- **Gone:** the runner ended without writing its outcome.
  - `registering`: a failed attempt, `refused:0:runner_gone`, under the
    backoff below, logged ERROR
    `[PEER-REGISTER] <X> -> 0 runner_gone next_in=<s>s`. The registration
    starts again at the first ingest request after that delay, 2 s after a
    first death, or at once on a wake from X. Starting again in the same
    request would restart a runner that dies the same way every time (a PHP
    fatal on the registration path) at the rate requests arrive.
  - `standing-down`: the stand-down completes without its runner (§10.7).

  Both are a compare-and-swap on `(peer_state, runner_id)`, so two requests
  that find the same runner gone act once, and a runner that wrote its
  outcome a moment before the check is not touched.

A host that cannot run §10.10 makes no claim at all: the attempt fails at
once as `refused:0:runner_unavailable`, under the same backoff.

**What starts a registration, and nothing else does:**

- **Due, at an ingest request.** The request prelude runs on every ingest
  endpoint (`maintenance_rides_every_ingest_test.php`). It checks each
  configured relay. A registration is due when:
  - there is no client row and §10.3 says register;
  - the row is `refused` and `next_attempt_at <= now`;
  - the row is connected, but `registered_as` differs from the relay's
    current `H` (§10.2).

  This is how the backoff works without a timer: the next attempt is made at
  the first ingest request after the delay has passed. The endpoints that
  count are those the prelude covers: exchange, tx, poll, the wake handler,
  and each runner's own prelude. `/v1/interfaces/register`,
  `/v1/interfaces/challenge`, `/v1/gateway/confirm`, `/health`, `/debug` and
  the monitor do not count. A relay that receives no ingest request makes no
  attempt. Its peers' traffic and wakes, and its own clients' exchanges, are
  such requests.
- **A wake from X**, at once, resetting the delay (§10.5).
- **A `401`** on an exchange with X, at once, as §9 step 5, when the row's
  stored `peer_session_token` still equals the token that got the 401
  (compare-and-swap). At most once per 401: a 401 right after a fresh
  registration is logged and ends the cycle, and the next due or wake event
  goes on from there.
- **A runner found gone**, as a failed attempt (above).
- **`GET /v1/initialize`** (operator). For each configured relay whose client
  row is not connected, including `superseded`, it clears the state and
  registers now. A claim whose runner is alive is left to that runner. One
  whose runner is gone is handled as above first. It cannot touch a
  connected link.

**Failure: James's §3 exception.** A registration that fails on the network,
gets a 5xx, or gets a terminal code from §6 is a failure. That includes a
second `409 stale_challenge`, an answer that does not decrypt (§10.4), a
challenge `404` (X runs older code, and with `register_at_peers` on there is
no legacy fallback), a runner found gone (`runner_gone`) and a host that
cannot spawn one (`runner_unavailable`, §10.10). On a failure:

- `peer_state = 'refused:<status>:<error>'` and status offline, so nothing is
  routed into the row;
- `backoff_seconds` follows §9.6's schedule: 2 s, doubling, capped at 300 s;
- `next_attempt_at = now + backoff_seconds`;
- an ERROR line `[PEER-REGISTER] <X> -> <status> <error> next_in=<s>s`.

A success or a wake from X resets the delay to 2 s. `DESIGN_PRINCIPLES.md` §3
records that this exception covers a PHP relay's registration at a peer, and
that the relay runs no timer.

**`409 session_superseded` on an exchange is terminal.** The row becomes
`superseded`, logged ERROR `[PEER-SUPERSEDED] <X>`. Another registration of
this relay's identity at X replaced the session: a second relay sharing the
identity file, or a second runner that should not exist. There is no backoff,
and no wake restarts it. Only `GET /v1/initialize` does. The relay's own
registrations are single-flight, so this does not happen on its own.

**Exchange failures are not retried.** A network failure or a 5xx on an
exchange is logged `[PEER-EXCHANGE] <X> -> <status>`. The next exchange comes
from the next event (an epilogue with queued packets, or a wake), as for the
gateway (§9.6). An exchange runner that dies is not replaced by anything but
that next event either (§10.5). A host that cannot spawn one logs
`[PEER-EXCHANGE] <X> -> 0 runner_unavailable` at each event that wanted one.

Each registration and exchange is a network send under §1 of the principles,
with its late-success assertion.

### 10.7 Standing down

The stand-down is triggered when §10.3's rule turns against an existing client
row. The events are this relay's §9.8 step 5 confirming X's URL, or a due
check in the prelude that finds both conditions. Then R:

1. takes a new runner's lock (§10.10) and sets the client row to
   `standing-down` with that `runner_id`, by compare-and-swap from
   `connected` or `refused`. A `registering` row is checked again by its
   runner when it finishes, or turns `refused` when its runner is found gone
   (§10.6), and is then stood down from there. Nothing new is queued or
   routed to a row that is standing down;
2. spawns that runner (job `peer-standdown`), which:
   - pushes what is queued and pulls once;
   - POSTs X's `/v1/interfaces/goodbye` with the session;
   - deletes the row with §4.5's deletion set;
   - logs `[PEER-STANDDOWN] <X>`.

**If the stand-down's runner is gone** before it deleted the row (§10.6,
§10.10), the stand-down completes without it. The prelude that found it gone
deletes the row with §4.5's deletion set, by compare-and-swap on
`('standing-down', runner_id)`, and logs ERROR
`[PEER-STANDDOWN] <X> runner_gone dropped=<n>`, where `n` counts the packets
still queued on the row, which are dropped. No goodbye is sent: that is the
lost-goodbye case below. Running the stand-down again would retry its
exchange and its goodbye, which §3 of the principles forbids. A host that
cannot spawn the runner at all completes the stand-down the same way, with
`runner_unavailable`.

At X, a goodbye on a signed transit row closes it: status `closed`, not
active, not woken, nothing relayed to it, until its next signed bind (§4.4
sets status `online` again). Today's goodbye sets `offline` and deletes the
row's local destinations and paths, but a transit row ignores its status, so
for a signed transit row the goodbye now sets `closed`.

If the goodbye is lost, X keeps the row active. It relays announces into the
row's queue, which the storage cap bounds, and wakes it at most once (§9.8's
rule). R ignores that wake (`[PEER-WAKE-IGNORED] reason=stood-down`). The
row stays until R registers again, which re-binds it in place, or an operator
deletes it.

### 10.8 Events

| Event | At the client | At the server |
|---|---|---|
| An ingest request (the prelude) | registers at each configured relay that is due (§10.6) | — |
| Packets queued on a client row | the exchange runner, under §10.5's spawn rule | — |
| Packets queued on a client's signed row | — | a wake, under §9.8's rule |
| A wake from X | an exchange if connected, or a registration now if refused or missing (§10.3 permitting) | — |
| A `401` on an exchange (compare-and-swap holds) | registers at once | — |
| `409 session_superseded` on an exchange | terminal until `GET /v1/initialize` | — |
| A signed registration from a relay | — | the bind, then §9.8's confirm of its URL |
| §9.8's confirm lands | the stand-down check (§10.7), if this relay is also a client of the other | other identities' rows for the URL are retired (§9.8) |
| A goodbye from a client | — | its row is closed |
| A claimed runner found gone at the prelude (§10.10) | `registering`: a failed attempt under the backoff; `standing-down`: the stand-down completes without it (§10.6, §10.7) | — |
| An exchange runner that died before it started | the next wake or queued packet spawns another (§10.5) | — |
| A confirm runner found gone (§10.10) | — | a failed confirm: its record is deleted, and the row waits for its next registration (§9.8) |
| `GET /v1/initialize` | clears client rows that are not connected, leaving a claim to a runner that is alive, and registers | — |

Nothing else starts a registration or an exchange. There is no timer and no
cron. The only clock is §10.6's `next_attempt_at`, and it is compared only
when an ingest request arrives. No runner is judged by a clock: whether one
is still there is the OS's answer (§10.10).

### 10.9 Recovery

| Event | What happens |
|---|---|
| Client (A) DB reset; identity file intact | A's first ingest request finds no client row and registers. So does B's wake, which B sends while A's row at B is confirmed. B re-binds A's identity row in place (seq + 1), so B's queue and paths for A survive, and B re-confirms A's URL. If both configure each other, B holds A's row the whole time, confirmed or being confirmed, so B does not register (§10.3). |
| Server (B) DB reset | A's next exchange with B, which A's own packets drive and announces never stop, gets `401`. A registers at once, and B inserts A's identity row (seq 0 under B's new secret) and confirms it. If B also configures A, B's first request finds neither a client row at A nor A's row, so B registers at A too. That leaves two links until A's registration is confirmed at B, and then B stands down: one link. |
| Both reset | Both register, and §10.3 leaves A's. |
| A's identity file lost | §10.2: A's next registration is a new identity row at B, and its confirm retires the old row (§9.8). If A's DB is intact, A sees at its next ingest request that `registered_as` differs from its new `H`, and registers at once. A's transport id changes with the file: packets on paths learned through the lost hash are refused at A until the next announces teach its neighbours the new one (§10.2.1, §16.1.14). |
| B unreachable or failing | A backs off (§10.6), and attempts again at the first ingest request after each delay. A wake from B, once B is back, resets the delay. |
| A registration runner dies | A's next ingest request finds its lock free (§10.10): a failed attempt, `refused:0:runner_gone`. The registration starts again at the first ingest request after the backoff's delay, or at once on a wake from B. |
| A stand-down runner dies | A's next ingest request finds it gone and deletes the client row without a goodbye; the packets still queued on it are dropped and counted in the log (§10.7). |
| An exchange runner dies | If it died before it started, the next wake or queued packet spawns another (§10.5). If it died mid-exchange, the next event starts the next exchange, as after any failed exchange (§10.6). |
| B's confirm runner dies | B's next check finds it gone: a failed confirm (§9.8 step 6). A is not woken until its next registration confirms; it still works by its own exchanges. If B configures A too, B registers at A until then (§10.3). |
| A host reboots | Every runner on it is gone, and every lock with it. The next ingest request finds each claim's runner gone and acts as the rows above say. |
| Rotating a link's session | Every registration rotates the token. `GET /v1/initialize` does not touch a connected link. To rotate one, delete the client row (one statement, on the client); the next ingest request registers afresh, and the server re-binds in place. |

No request handler waits on another relay. Registrations, exchanges and
confirms run in detached runners, and the wake and confirm handlers call
nobody.

### 10.10 Is the runner still there? The OS answers, not a clock

James's answer to revision 6's question 4 (2026-10-04): instead of leaving a
client row `registering` until `GET /v1/initialize`, the relay checks on its
next request whether the runner still exists, with an OS check and never a
clock, and starts again if it is gone. The same principle applies wherever
revision 6 guarded a dead runner with a time bound, or did not guard it at
all:

| Runner (job) | Its claim | Gone means | Section |
|---|---|---|---|
| registration (`peer-register`) | the client row's `runner_id`, state `registering` | a failed attempt under the backoff | §10.6 |
| stand-down (`peer-standdown`) | the client row's `runner_id`, state `standing-down` | the stand-down completes without it | §10.7 |
| exchange (`peer-exchange`), until it starts | the client row's `exchange_pending_runner` | the next wake or queued packet spawns another | §10.5 |
| wake-URL confirm (`gateway-wake-confirm`) | its record's `runner_id` | a failed confirm, and the record is deleted | §9.8 |

The legacy wake runners (`wake-event`, `spawnDetachedWakeRunner`) belong to
the legacy peering and are unchanged (§16.1.15).

**The event.** A runner can end without writing its outcome: a PHP fatal
error, an out-of-memory kill, a reboot. The deterministic event that it has
ended, however it ended, is the kernel releasing a lock it held. An `flock`
lock belongs to an open file description, and is released when the last
descriptor for it is closed; a process's descriptors are all closed when it
ends. So a runner holds an exclusive `flock` on a file of its own for as long
as it runs, and "the lock is free" means "the runner is gone".

**Why not the process id.** A process id can be reused by another process.
Telling the runner from a stranger with the same id needs
`/proc/<pid>/cmdline`, which macOS (where staging runs) does not have, and
`posix_kill(pid, 0)` answers only "some process has this id". Between the
spawn and the runner's first write to the database, its id is the only thing
there is to check. A lock handed over at fork has neither problem, and PHP's
`flock` needs no extension.

**Taking the lock and handing it over.** The lock is taken before the claim
exists and passes to the runner when it is forked:

1. The request makes a `runner_id` (16 random bytes, 32 lower-case hex),
   creates `<runner dir>/<runner_id>.lock` (exclusive create, mode 0600,
   close-on-exec: `fopen` mode `xe`) and takes `flock(LOCK_EX)` on it.
2. It writes the claim that names `runner_id`: the compare-and-swap of the
   claim's own section. If the claim fails, it deletes the file and stops.
3. It spawns the runner with `proc_open`, passing the locked descriptor as
   the child's descriptor 3:
   `/bin/sh -c '<php> <index.php> <job> <args> <runner_id> </dev/null >/dev/null 2>&1 &'`.
   `proc_open` puts the lock there with `dup2`, which makes that copy
   inheritable, and the background job inherits descriptor 3, so it shares
   the lock from the moment it is forked. Every lock file the relay opens,
   this one and every probe, is opened close-on-exec, so a runner inherits
   its own lock and no other. `proc_close` returns the shell's exit status,
   which is the spawn's success or failure, as `exec()`'s is today. It waits
   only for the shell, which exits as soon as the job is in the background.
4. It closes its own descriptor without unlocking: `fclose`, never
   `flock(LOCK_UN)`, which would release the runner's lock as well. The lock
   now belongs to the runner alone.

From step 1 until the runner ends, some process holds the lock, so there is
no moment when a claim exists and a live runner does not hold its lock. If
the request itself dies between steps 2 and 3, the kernel closes its
descriptor, and the claim's runner, which never started, is correctly found
gone. If it dies after step 3, the runner holds the lock on its own.

This was checked on macOS with PHP 8.5.6 while revision 7 was written, with
a throwaway script in the self-test's shape: after the spawning process's
`fclose`, `LOCK_NB` from a new descriptor was refused while the child ran,
and the blocking lock returned once it had ended; another lock the spawning
process held, opened close-on-exec, did not pass to the child. Linux on the
production hosts is the self-test's to show.

**The runner** first checks that its `runner_id` still holds the claim, and
exits if it does not. Every outcome it writes is a compare-and-swap on its
`runner_id`. When it is done, whether or not its compare-and-swap held, it
deletes its lock file. An exchange runner deletes it as soon as it has cleared
`exchange_pending_runner`, because nothing checks it after that (§10.5).

**The check, `runner_alive(r)`.** Open `<runner dir>/<r>.lock` without
creating it, then:

- no such file: the runner finished. Gone;
- `flock(LOCK_EX | LOCK_NB)` refused: a runner holds it. Alive;
- granted: the runner ended without deleting its file. Gone. The checker
  deletes the file while it holds the lock, then closes it.

Whoever acts on "gone" does so by compare-and-swap on the claim and its
`runner_id`. So two requests that find one runner gone act once, and a runner
that wrote its outcome just before the check is not touched. A request that
replaces a claim (a newer registration's confirm record, `GET
/v1/initialize`, a retire) checks the old `runner_id` the same way, which
deletes the file of a runner that died.

**The runner directory** is `runners/` in the identity file's directory
(§10.2), created mode 0700 on first use: outside the web root, on the host's
own disk, never under `/tmp`. A temp-file cleaner that deleted a held lock
file would let a check open a new file and find it free while the runner
lives. A file system on which an `flock` lock is not shared with a child
forked from the holder cannot carry this rule. NFS is one: Linux emulates
`flock` there with POSIX locks, which belong to one process.

**What the host must provide.** `proc_open` (not in `disable_functions`),
`/bin/sh`, `fopen`'s close-on-exec flag `e` (a POSIX.1-2008 system: Linux
and macOS are), and a runner directory on which `flock` is shared across a
fork. None of it needs a PHP extension.

- **Checked at every claim:** `proc_open` exists and the runner directory can
  be created and written. When either fails, no claim is made and no runner
  starts. A registration fails as `refused:0:runner_unavailable` under
  §10.6's backoff (an ERROR line at most once per delay), a confirm fails
  (`[GW-WAKE-CONFIRM-FAIL] reason=runner_unavailable`), a stand-down
  completes without its runner (§10.7), and an exchange does not start
  (`[PEER-EXCHANGE] <X> -> 0 runner_unavailable`). `/health` shows
  `runner_spawn` with the reason (§12.5).
- **Checked by the operator:** whether the lock is really shared across the
  fork cannot be checked per request without a spawn, so
  `php index.php runner-selftest` checks it, with nothing but `flock`. It
  takes a control lock, then spawns a runner exactly as above, which waits
  to take the control lock and then ends. Once it has closed its own
  descriptor, it checks that `LOCK_NB` on the runner's lock from a new
  descriptor is refused, and that a second lock it held during the spawn did
  not pass to the runner. It releases the control lock, so the runner ends,
  then takes the runner's lock blocking, which returns when the runner has
  ended. It prints `[RUNNER-SELFTEST] PASS` or
  `[RUNNER-SELFTEST] FAIL <reason>`. It runs on staging in Phase 0 and on
  each relay before Phase 3b (§11.2). It needs nothing from the web
  server's PHP but the runner directory, which both share; `proc_open` in
  the web server's PHP is the per-claim check above.
- **No fallback.** There is no clock to fall back to, and no wait for
  `GET /v1/initialize`. A relay on a host that fails these checks does not
  peer the signed way. With `register_at_peers` off it keeps the legacy
  peering until Phase 3c; after Phase 3c it cannot peer at all.

**Where no clock-free answer exists.** On a host that can neither hand a
descriptor to a child (`proc_open`) nor ask the OS about a process
(`posix_kill`, `/proc`), nothing deterministic tells a runner that has not
started yet from one that died. A host without `proc_open` but with `exec()`
has other answers, through the process id that the spawning shell prints
(`… & echo $!`):
- with `/proc` (Linux): exact. The runner is alive while
  `/proc/<pid>/cmdline` contains its `runner_id`, which the command line
  carries from the fork on (first the shell's `-c` argument, then PHP's);
- with only `posix_kill(pid, 0)`: right, except when the runner died and
  its id was reused, which keeps a dead claim held for as long as the other
  process lives.

This spec uses neither. If a production host fails the self-test, which of
them to use is the question to bring back to James (§16.2).

---

## 11. Rollout

### 11.1 Configuration

```toml
[registration]
enforce_signed_registration = false   # browsers. James flips to true on a date he sets.
enforce_signed_transit      = false   # gateways and PHP peers. James flips once Phases 3 and 3b are verified.
max_interface_rows          = 20000   # §12.4
register_at_peers           = false   # §10: register signed at every [interfaces] relay. James flips it in Phase 3b.
identity_path               = ""      # §10.2: the relay identity file, outside the web root; its hash is the transport id (§10.2.1). "" = relay_identity next to sqlite_path.
```

The runner directory (§10.10) is `runners/` beside the identity file and has
no key of its own. The transport id has no switch: it is the identity's hash
from the first request on this code (§10.2.1).

Revision 2's `accepted_peer_urls` and `transit_identities` are gone: peering
is open (§8.1, §10). Revision 6 removed `allow_loopback_http_peers`: no relay
sends credentials to a peer's URL any more (§10.1). A relay that still has
these keys in its config ignores them.

While a switch is off ("accept-both"), every path in this spec is live:
signed registrations are preferred, and legacy registrations are accepted and
logged `[REG-LEGACY] client=<c> type=<t>`.

**`register_at_peers`** chooses how this relay peers. Off: today's legacy
peering (bae739a) runs unchanged, and the relay registers nowhere. On: the
relay registers signed at every relay in its `[interfaces]` (§10), and runs no
legacy connect, legacy pull or legacy peer wake at all. A relay never mixes the
two. Switching it off stands down every client row at the next ingest request
(§10.7). Either way the relay accepts signed registrations from others, so a
peer can move first.

**`enforce_signed_registration` on:**

- unsigned `rns-js` registrations, and those of any client outside §4.3.1, get
  `403 signature_required`;
- `authenticateInterface` answers `401` for those rows when their proof is
  `none`;
- the guard's legacy branch ends (`owner = none` for every `none` row).

**`enforce_signed_transit` on:**

- unsigned `reticulum-php`, `rns-post-interface` and `reticulum-post`
  registrations get `403 signature_required`;
- `none` rows of those clients stop being transit rows (§8.1), and
  `authenticateInterface` answers them `401`.

The transit switch ends *unproven* transit, not open peering. Under it, any
gateway or PHP relay that signs still gets a transit row, with no list (§8.1).
It needs `register_at_peers` on at both relays of a peering first (Phase 3b).

Gateways and peers are few and operator-run. They can be moved within days,
so the transit switch does not have to wait for the last cached browser tab.

**Enforcement is gated on dates James sets, not on `[REG-LEGACY]` going
quiet.** An attacker, or the selectiv Aug-01 `app.js` that keeps reappearing,
can keep that log busy forever. Before flipping a switch, read `[REG-LEGACY]`
grouped by `client`.

### 11.2 Deploy order

Each phase is gated by the existing checks: `deploy.sh` runs the whole PHP
suite, then `verify-live-stamp.sh`; the web has its boot gate, CSP check and
`verify-deploy.sh`.

| Phase | What | Gate and notes |
|---|---|---|
| 0 | Staging only (`staging.sh`, `STAGING_PHP=local`, gateway in wake mode) | The §15 before/after stage MUST fail on bae739a (and on Reticulum-rust before its change) and pass on the fix. Staging is SQLite, so it cannot show A9 (§12.2). The staging relays switch their transport id here first (§10.2.1), each with its own identity file, and `php index.php runner-selftest` passes on the staging host (§10.10). |
| 1 | Relays, accept-both: selectiv, then retichat.com | No new config: peering is open, so there is no list to fill in (§11.1). `register_at_peers` stays off, so the legacy peering runs unchanged. **Gates:** (a) schema probe: the columns, the UNIQUE index, the `gateway_wake_confirms` table, and `peer_url_key` filled for every row with a `peer_url`. A failed MySQL `ALTER` leaves the fingerprint unrecorded and would make every signed registration 500. (b) One signed test registration against each relay succeeds. (c) `/health` shows `registration_proof` and `peer_state` per node and gateway row. (d) The relay identity file (§10.2) exists after the first ingest request, is 64 bytes and mode 0600, its directory is outside the web root, and an HTTP request for it from outside gets no file; `[RELAY-IDENTITY] created` names its hash. (e) **The transport id switches here** (§10.2.1). The first ingest request on this code loads or creates the identity file, and from then on the relay writes its hash as the transport id. `/health` shows `transport_id` equal to the hash `[RELAY-IDENTITY] created` names, and `previous_transport_id` equal to the relay's id before the deploy (read from `transport_state.identity_hash_hex` beforehand, read-only). The two relays' `transport_id` differ. Nothing else changes for the switch: the gateway and the other relay learn the new id from the next announces this relay relays, and their packets that carry the old one are still forwarded. (f) The count of `inbound_packets` rows with `filter_reason = 'transport_id_mismatch'` does not rise after the deploy (a read-only count before and after): packets on paths learned before the switch still find their relay. If the identity file cannot be created, every ingest request answers `503 relay_identity_unavailable` (§10.2.1): roll back at once (§11.5). From this phase §8.5 holds on every row, so watch for its cost: a selectiv destination that retichat.com reaches through the gateway rather than the direct peer (James: "Leave it, watch it"; the fix if it ever matters is gravity, §16.1.13). The relays also run the §9.8 confirm from this phase; there is no signed gateway row until Phase 3. |
| 2 | Retichat-js | New page loads sign. Against a relay still on old code, the client gets a `404` from the challenge endpoint and registers legacy. |
| 3 | Gateway: James pushes Reticulum-rust and redeploys (`rnsd-redeploy.sh`) | **Before this phase** the Reticulum-rust and Python `PostInterface` gateways MUST carry the §9.8 confirm handler, and its wake listener must be reachable from the relay: a gateway that registers signed without it is never woken (the relay's confirm gets `404`, logged `[GW-WAKE-CONFIRM-FAIL]`), and works only by its own exchanges. **Gate:** `/health` on retichat.com shows `wake_confirmed = true` for the gateway row, and its log has `[GW-WAKE-CONFIRMED]`. It registers signed and gets an identity row; no relay needs its identity hash. That registration retires the legacy bridge row with the same canonical `peer_url` at once (§4.5, `[REG-RETIRE-URL]`), and paths are learned again from the next announces. Its `interface_id` changes this one time and is stable from then on. Check rx/tx per minute (runbook §5). Python bridges follow the same path. |
| 3b | PHP peering moves to the signed link: `register_at_peers = true` on retichat.com, then on selectiv, in one window | Both relays run this code (Phase 1). **Before it:** `php index.php runner-selftest` prints `PASS` on each relay's host, and `/health` shows `runner_spawn: available` on both (§10.10). A relay that fails either keeps the legacy peering, and the phase waits for James (§16.2). In order:<br>1. **retichat.com first.** It registers signed at selectiv. Its registration retires selectiv's legacy (`none`) rows for retichat.com's URL (§4.5, `[REG-RETIRE-URL]`). selectiv confirms retichat.com's URL (§9.8). retichat.com's client row then retires retichat.com's own legacy rows for selectiv (§10.4). From then on the signed link carries both directions. selectiv's legacy code, if it tries to reconnect, is refused at retichat.com's client row (`403 peer_confirmation_required`), so nothing churns.<br>2. **Then selectiv.** It holds retichat.com's confirmed registration, and retichat.com sorts first, so it does not register (§10.3). One link.<br>Flipping in the other order also ends in one link, with one stand-down (§10.7) at selectiv. **Gate:** retichat.com shows a `local` client row for selectiv, `connected`; selectiv shows retichat.com's signed row with `wake_confirmed = true`; neither shows a `none` row for the other, and selectiv has no client row at retichat.com. **Rollback before 3c:** `register_at_peers = false` on both (client rows stand down, §11.1), then `GET /v1/initialize` on retichat.com re-forms the legacy peering. |
| 3c | `enforce_signed_transit` on both relays, on James's word | **Gate:** `/health` on both relays lists no `none` node or gateway row, and `[REG-LEGACY]` shows no `reticulum-php`, `rns-post-interface` or `reticulum-post` line since Phase 3b. The live config of each relay has no `[post_interface_peers]` block, or each such link has moved to `[interfaces]` peering (§16.2). After 3c the legacy peering code can be removed in a later change, and `register_at_peers` becomes always on. |
| 4 | `enforce_signed_registration`, on James's date: selectiv, then retichat.com | A config edit on each host. |

### 11.3 What old software experiences

**Phases 1–3b:**

- **Old cached tab:** works unchanged through the legacy path, with three
  exceptions:
  - if the same identity has a signed row on that relay (the user also
    opened a new tab), its re-registration gets
    `403 identity_requires_signature`, and the signed row has retired its
    legacy row;
  - its announces cannot take over a destination this relay already reaches
    through another row (§8.3);
  - if a newer tab supersedes it, it gets `409` every 5 s and never evicts
    the newer one.

  In each case the "down" text says to reload.
- **Old gateway binary:** works unchanged (legacy, `[REG-LEGACY] type=gateway`).
- **Relay without this code (peer):** registers legacy, as today. Once this
  relay has `register_at_peers` on, that registration is refused where it
  would re-bind this relay's own client row for it
  (`403 peer_confirmation_required`).
- **Every neighbour of a relay whose transport id switched** (from Phase 1),
  old software or new: nothing changes for it. Its packets that carry the
  relay's old id are still forwarded, and the next announces it hears
  through the relay carry the new id (§10.2.1).

**Phase 3c:**

- **Old cached tab:** as above.
- **Old gateway binary:** refused, and the bridge is down. **Phase 3 must be
  finished first.**
- **Relay without this code (peer):** refused, and the peering is down. Both
  relays must run this code first.

**Phase 4:**

- **Old cached tab:** its next exchange gets 401 (a `none` row) and its
  re-registration gets `403 signature_required`. It shows "down … reload" and,
  being old code, tries again every 5 s until reloaded.
- **Old gateway binary and relay without this code:** as in Phase 3c.

### 11.4 Client fallback

A client falls back to legacy registration only on a challenge `404` (§2.5).
Once every relay it talks to enforces, a later client release MAY remove the
fallback. A forged `404` would need someone on the path inside HTTPS.

### 11.5 Rollback

- **A relay back to bae739a:**
  - The new columns and tables are ignored, and signed rows' `metadata_json`
    carries no identity, so nothing breaks.
  - New browsers get `404` from the challenge endpoint and register legacy. The
    old relay inserts a fresh row for them.
  - Gateways do the same.
  - Peers: switch `register_at_peers` off on both relays first, so the client
    rows stand down (§10.7), then roll back and re-form the legacy peering
    with `GET /v1/initialize` on retichat.com. Old code ignores signed rows,
    client rows, the identity file and the runner directory. Stored URLs are
    canonical, which is the form the configs already use.
  - **The transport id goes back** to the pre-switch id, which this code left
    in `transport_state.identity_hash_hex` (§10.2.1). Old code accepts only
    that id, so packets on paths that neighbours learned through the identity
    hash since Phase 1 are refused (`transport_id_mismatch`) until the next
    announces the relay relays teach them the old id again. If the database
    was reset in between, old code makes a new random id, as any reset does
    at bae739a. Forward again, the identity hash is the transport id once
    more, and whatever id old code last used is kept as the pre-switch id.

  **This restores every attack in §0 except A2**, which the hotfix keeps
  closed, and A9's live case, which d3a0eb5 keeps closed (§0.1).
- **Forward again:** `migrateIfNeeded()` runs, because the fingerprint
  differs. The `peer_url_key` and `claimed_identity_hash` backfills fill rows
  that old code wrote, and `authenticateInterface` fills any it missed (§12.3).
- **Enforcement back off:** flip the switch. It takes effect at once.
- **Web, before Phase 4:** any build works. **After Phase 4:** the rollback
  target MUST be a build that signs.
- **Gateway, before Phase 3c:** any build works, but a build that signs is
  woken only if it also answers §9.8's confirm. A legacy registration
  inserts a separate legacy row, because identity rows are invisible to URL
  lookups. **After Phase 3c:** the rollback target MUST be a binary that signs.
- **A relay rolled back to old code while its peer runs this code with
  `register_at_peers` on:** the old relay's legacy registrations are refused
  at the peer's client row for it. Switch `register_at_peers` off on the peer
  (its client rows stand down), or roll both relays back.
- **Schema:** the changes are additive, so a rollback needs no schema change.
  Old code never writes `identity_hash`, so the UNIQUE index never conflicts.

---

## 12. Schema (Reticulum-post)

### 12.1 Objects

The new columns, indexes and tables are added in `request_schema_trait.php`.
That changes the schema fingerprint, so `migrateIfNeeded()` runs the migration
again.

| Object | Definition |
|---|---|
| `interfaces.identity_hash` | `VARCHAR(32) DEFAULT NULL` + `CREATE UNIQUE INDEX idx_interfaces_identity_hash ON interfaces (identity_hash)` (multiple NULLs are allowed on MySQL 8.4, MariaDB 11.4 and SQLite) |
| `interfaces.identity_public_key` | `VARCHAR(128) DEFAULT NULL` |
| `interfaces.registration_seq` | `BIGINT NOT NULL DEFAULT 0` |
| `interfaces.registration_proof` | `VARCHAR(16) NOT NULL DEFAULT 'none'` |
| `interfaces.claimed_identity_hash` | `VARCHAR(32) DEFAULT NULL` + `CREATE INDEX idx_interfaces_claimed_identity_hash …` |
| `interfaces.peer_url_key` | `VARCHAR(64) DEFAULT NULL` + `CREATE INDEX idx_interfaces_peer_url_key …` (not unique: a signed gateway row and a legacy row may name one URL until §4.5 retires the legacy one) |
| `interfaces.previous_session_token_hash` | `VARCHAR(64) DEFAULT NULL` |
| `interfaces.peer_state` | `VARCHAR(64) DEFAULT NULL`: a client row's state (§10.6) |
| `interfaces.next_attempt_at`, `interfaces.backoff_seconds` | `INT DEFAULT NULL`: a client row's backoff (§10.6) |
| `interfaces.registered_as` | `VARCHAR(32) DEFAULT NULL`: the identity hash a client row registered with (§10.4) |
| `interfaces.runner_id` | `VARCHAR(32) DEFAULT NULL`: the runner that holds a client row's claim, `registering` or `standing-down` (§10.6, §10.10) |
| `interfaces.exchange_pending_runner` | `VARCHAR(32) DEFAULT NULL`: the exchange runner spawned for a client row that has not yet started (§10.5) |
| `interfaces.wake_url_confirmed_key` | `VARCHAR(64) DEFAULT NULL`: the `peer_url_key` §9.8 confirmed for a signed gateway row since its last registration |
| `interfaces.wake_url_proven_key` | `VARCHAR(64) DEFAULT NULL`: the `peer_url_key` this row's identity last proved by a confirm (§9.8 step 5). A re-bind keeps it; a retire clears it. §10.3 reads it (A16) |
| `interfaces.wake_outstanding` | `TINYINT NOT NULL DEFAULT 0`: a wake left for this signed gateway row and it has not exchanged since (§9.8) |
| `gateway_wake_confirms` | `interface_id VARCHAR(64) NOT NULL PRIMARY KEY, peer_url_key VARCHAR(64) NOT NULL, peer_url VARCHAR(512) NOT NULL, registration_seq BIGINT NOT NULL, nonce_hex VARCHAR(32) NOT NULL, runner_id VARCHAR(32) NOT NULL, created_at INT NOT NULL DEFAULT 0` (§9.8; `created_at` is shown, never compared) |
| `transport_state` rows | `registration_challenge_secret_hex` (new). `identity_hash_hex`, which bae739a creates, is read as the pre-switch transport id and never written by this code (§10.2.1) |
| Not in the database | the relay identity file at `[registration] identity_path` (§10.2), and the runner directory `runners/` beside it, with a lock file for each runner a claim names (§10.10) |

`registration_proof` takes `none`, `signed`, `local` or `retired` (§1).
`status` gains `closed`, a signed transit row its holder said goodbye on
(§10.7).

Revision 3 adds `peer_registration_pending.peer_url`, the canonical URL the
confirm goes to (revision 3's §10.5). Revision 2 took it from the config, which an open
peering may not have. No column is removed: the accept-list and
`transit_identities` were config, never schema. Revision 4 adds
`interfaces.wake_url_confirmed_key` and `gateway_wake_confirms` (§9.8).
Revision 5 adds `interfaces.wake_outstanding` and
`gateway_wake_confirms.registration_seq`. Revision 6 drops
`peer_registration_nonces` and `peer_registration_pending` (the nonce
handoff, never deployed) and adds the client-row columns `next_attempt_at`,
`backoff_seconds`, `registered_as`, `last_exchange_spawned_ms` and
`last_exchange_started_ms`. Revision 7 replaces the last two, which were
never implemented, with `exchange_pending_runner`, and adds
`interfaces.runner_id`, `interfaces.wake_url_proven_key` and
`gateway_wake_confirms.runner_id`. It adds no table: the transport id needs
none (§10.2.1).

### 12.2 Lookups never compare free text (A9)

On MySQL and MariaDB the tables are `utf8mb4_unicode_ci`
(`request_schema_trait.php:108`). That collation compares at the UCA primary
level: `é = e`, `A = a`, and trailing spaces do not count. Lower-case hex
compares exactly under it, because no two distinct lower-case hex strings
share primary weights. So:

- Every lookup a request can influence uses a value that is lower-case hex,
  validated by shape before it reaches SQL (`identity_hash`, `nonce_hex`,
  `claimed_identity_hash`), or a SHA-256 hex key (`peer_url_key`).
- **No SQL compares `peer_url`**, or any other free-text column, with a value
  from a request. A static test enforces this for `peer_url`.

This needs no collation change and no backend-specific DDL. SQLite compares
bytes, so staging and every test here pass either way. That is why the rule is
enforced statically and by the canonical-URL vectors, not by a SQLite test.

### 12.3 Backfills

These run in PHP on every migration, idempotently, with no `LIKE`.

- **`claimed_identity_hash`:** only for `rns-js` rows with `identity_hash IS
  NULL AND claimed_identity_hash IS NULL`. It copies the top-level
  `metadata.identity_hash` when that is 32 lower-case hex. `authenticateInterface`
  does the same for any such row it meets, which covers rows that old code
  wrote after the migration (a rollback). Announces arrive through an
  authenticated exchange, so the fill happens before §8 sees them.
  `metadata_json` loses the key at the row's next write.
- **`peer_url` and `peer_url_key`:** for rows with a `peer_url` and no key,
  the relay rewrites `peer_url` in canonical form and sets the key. A URL that
  does not canonicalise keeps a NULL key and is logged `[SCHEMA-PEER-URL]`.
  Such a row can no longer be found by URL.

### 12.4 Rows are bounded by the operation that creates them (A14)

Before a signed or legacy registration INSERTs into `interfaces`:

1. If `SELECT COUNT(*) FROM interfaces` is below `max_interface_rows`, insert.
2. Otherwise reclaim up to 100 rows with `registration_proof = 'none'` that
   are offline and have no queued outbound packets, oldest `last_seen_at`
   first, with the §4.5 deletion set. Log `[REG-RECLAIM] rows=<n>`.
3. If the table is still full, answer `503 registration_capacity`, logged
   `[REG-CAPACITY] client=<c>`.

Signed, retired and `local` rows are never reclaimed (§12.5). A
re-registration of an existing row never counts. A PHP relay's registration
is a signed registration and counts like any other. A relay's own client rows
(`local`) are exempt: there is at most one per relay in its `[interfaces]`
(§10.4). With nothing to schedule, the bound is enforced by the only
operations that grow the table without limit, as the no-cron rule asks.

`gateway_wake_confirms` holds at most one record per signed gateway or relay
row and 64 in all (§9.8 step 2). A record is deleted by its runner's outcome,
or as a failed confirm once its runner is found gone (§10.10). It is replaced
by the row's next registration, and emptied by `clearAllData()`. Revision 6
had no way to free the record of a runner that died, so such records could
fill all 64 for good (A17).

The runner directory holds a lock file only while a claim names its runner.
A runner deletes its own file once it has written its outcome, and an
exchange runner once it has started (§10.5). The file of a runner that died
is deleted by the next check of that `runner_id` (§10.10): the prelude's
check of a client row, the next spawn's check of `exchange_pending_runner`,
§9.8 step 2's or §10.3's check of a confirm record, or the check of whoever
replaces the claim. So the directory holds at most one file per client row
for its claim, one for its pending exchange runner, and one per confirm
record, which are at most 64.

### 12.5 Invariants and operator rules

- **The seq never goes back.** A row with `identity_hash` set is deleted only
  together with a rotation of `relay_secret`. `clearAllData()` does that,
  because it empties `transport_state`. An operator who must delete one deletes
  the secret too, in the same session:
  `DELETE FROM transport_state WHERE state_key = 'registration_challenge_secret_hex'`.
  Without the rotation, the row's seq would restart at 0, and a body already
  used at a low seq would work once more (§2.4).
- **`monitor.php`'s clear** must add `gateway_wake_confirms` to its
  `TABLES`. It must stop at the first
  failed `DELETE` rather than carry on, so that it never empties `interfaces`
  while `transport_state` survives.
- **The README's peering procedures change** (§10.9): rotating a link is
  deleting the client row on the client, and `GET /v1/initialize` clears a
  client row that is terminal (`superseded`) or backing off. A row whose
  runner died needs no operator: the next ingest request finds it (§10.10).
  They touch only URL rows (`identity_hash IS NULL`), never identity rows,
  and the warning must say so.
- **The identity file and the runner directory are not database state.**
  `clearAllData()`, a dropped schema and `monitor.php`'s clear never touch
  them (§10.2, §10.10). A runner alive across a reset finds its claim gone
  and exits (§10.10).
- **The pre-switch transport id is database state.** It lives in
  `transport_state.identity_hash_hex`, so `clearAllData()` and
  `monitor.php`'s clear delete it with everything else (§10.2.1). An operator
  never deletes that row on its own: packets on paths neighbours learned
  before the switch would then be refused.
- **SQL rules:**
  - no SQL string literal containing a backslash
    (`no_backslash_in_sql_literals_test.php`);
  - every value bound;
  - every query must prepare on MySQL 8.4, MariaDB 11.4 and SQLite;
  - `INSERT … ON CONFLICT` goes through `Database::upsertSql`, and
    INSERT-or-ignore through `Database::insertOrSql`.
- `clearAllData()` adds `gateway_wake_confirms`.
- `/health` adds `registration_proof` and `peer_state` to each node and gateway
  row it lists, `wake_confirmed` (true when `wake_url_confirmed_key` equals
  `peer_url_key`) to each signed gateway or relay row, and `peer_state`,
  `next_attempt_at` and, for a claim, `runner` (`alive` or `gone`, a read-only
  §10.10 check that changes nothing) to each client row. Since revision 7 it
  also shows, for the relay itself, `transport_id` (`H`, or `null` with the
  reason when the identity is unavailable), `previous_transport_id` (the
  pre-switch id, or `null`) and `runner_spawn` (`available`, or the reason it
  is not). They are not secrets: every relayed announce carries the
  transport id. The Phase 1, 3, 3b and 3c gates read them. It never shows the
  identity file's contents or path, or the runner directory's path.

---

## 13. Logging

Every refusal and every legacy acceptance is logged; nothing is dropped
silently. Logs MUST NOT contain session tokens, peer session tokens, nonces,
signatures, `relay_secret` or anything from the relay identity file but its
hash. Identity hashes, transport ids, interface ids, URL keys and runner ids
are public. Logs give them in full or as 8-hex prefixes.

| Tag | When |
|---|---|
| `[REG-SIGNED] identity=<H> interface=<id8> <created\|rebound> client=<c>` | a signed registration succeeded |
| `[REG-REFUSED] <status> <error> client=<c> [identity=<H>] [key=<8>]` | any 4xx or 5xx from register or challenge; `key` is the canonical peer URL's key, for a peer registration |
| `[REG-LEGACY] client=<c> type=<browser\|peer\|gateway\|other> action=<created\|rebound> …` | accept-both |
| `[REG-RETIRE] identity=<H> rows=<n>`, `[REG-RETIRE-URL] key=<8> rows=<n>` | §4.5 |
| `[REG-RETIRE-IDENTITY] identity=<old H> by=<H> key=<8>` | §9.8: a URL's confirm retired another identity's row |
| `[REG-RECLAIM] rows=<n>`, `[REG-CAPACITY] client=<c>` | §12.4 |
| `[REG-BAD-IDENTITY]` | malformed legacy claim (existing) |
| `[SESSION-SUPERSEDED] interface=<id8>` | §6.1, at most once per row per token, so an old tab's 5 s loop does not flood the log |
| `[RELAY-IDENTITY] created hash=<H>` (once, when the file is made), `[RELAY-IDENTITY] ERROR <reason>` (with each `503 relay_identity_unavailable`: loud on purpose, and bounded by the storage budget's cap on log files) | §10.2, §10.2.1. Revision 6's `loaded` line is gone: every ingest request loads the identity now. |
| `[PEER-REGISTER] <X> -> <status> <error> next_in=<s>s` (ERROR; `0 runner_gone` and `0 runner_unavailable` included), `[PEER-REGISTERED] <X> interface=<id8>`, `[PEER-401] <X>`, `[PEER-SUPERSEDED] <X>` (ERROR), `[PEER-EXCHANGE] <X> -> <status> <error>`, `[PEER-STANDDOWN] <X>`, `[PEER-STANDDOWN] <X> runner_gone\|runner_unavailable dropped=<n>` (ERROR), `[PEER-WAKE-IGNORED] <W> reason=<…>`, `[WAKE-UNKNOWN-PEER] <W>` | §10.5 to §10.7. `httpPostJson` must return the status, not `null`. |
| `[RUNNER-SELFTEST] PASS`, `[RUNNER-SELFTEST] FAIL <reason>` | §10.10, printed by `php index.php runner-selftest` |
| the legacy peering's tags (`[PEER-HTTP]`, `[PEER-REGISTER]` of `connectToPeer`, …) | as at bae739a, while `register_at_peers` is off |
| `[WAKE-REFUSED]` | a wake whose `waker_url` does not match the stored URL (§0.1; live since d3a0eb5) |
| `[GW-WAKE-CONFIRM]`, `[GW-WAKE-CONFIRMED]`, `[GW-WAKE-CONFIRM-FAIL]` (reasons include `runner_gone` and `runner_unavailable`), `[GW-WAKE-CONFIRM-LATE]`, `[GW-WAKE-CONFIRM-STALE]`, `[GW-WAKE-CONFIRM-BACKLOG]`, each with `identity=<H>` and, where there is a URL, `key=<8>` | §9.8 |
| `[WAKE-DROP]` | a wake that did not leave (existing); for a signed gateway row it leaves `wake_outstanding` unset (§9.8) |
| `[ANNOUNCE-FOREIGN]`, `[ANNOUNCE-LEGACY-REFUSED]` | §8 |
| `[SCHEMA-PEER-URL]` | §12.3 |

The gateway (§9) logs the following; a PHP relay registering at a peer
logs the same through §10's tags. At ERROR, every failed registration with the relay's
URL, the HTTP status (`0` for a network failure), the code and the delay
before the next attempt (§9.6); at NOTICE, each reset of that delay and its
cause (`registered` or `wake`); at ERROR, a `409 session_superseded` and that
it will not register again until restarted; at startup, its transport
identity hash; at NOTICE, each wake-URL confirm it signs, with the relay URL;
at WARNING, each it refuses, with the code (§9.8); and at ERROR, a wake
listener that fails to bind. The reason it gives Transport for being offline
carries the same code, so `rnstatus` shows it.

---

## 14. Test vectors

The vector file (format 6) contains:

| Section | Contents |
|---|---|
| `relays.A` / `relays.B` | `relay_secret` for each relay, and nothing else: no `host` (no audience, §3.2) and no `transit_identities` (open peering, §8.1). Every vector is presented to A. |
| `identities` | `browser`, `gateway`, `other` and `relay_b` (a PHP relay's identity, §10.2): private key (`x25519_prv \|\| ed25519_seed`, RNS layout), public key and identity hash. `lowx`: an Ed25519 seed with an all-zero X25519 half and no X25519 private key. |
| `challenges` | the MAC input, MAC and 48-byte challenge for every challenge used, with the seq each binds, including relay B's and one minted for another identity. Each `challenge_response` example carries no seq. |
| `registrations` | five end-to-end positive vectors: `browser-first` (seq 0 → 1, INSERT), `browser-reregister` (seq 1 → 2, non-ASCII name), `gateway-wake` (`reticulum-php`, mode 6, peer fields, seq 5 → 6, an identity no relay lists), `gateway-poll` (`rns-post-interface`, `transport`) and `php-relay-peer` (relay B registering at relay A as §10.4 says: `reticulum-php`, mode 1, `peer_url` = its canonical `host_url`, seq 0 → 1). Each has the request body, the field-by-field `lp` breakdown, the signed bytes, the signature, the expected identity hash and new seq, a response example, and an encrypted token pinned by a fixed ephemeral key and IV, with the shared key, derived key, HMAC key and AES key for debugging. |
| `negative` | twenty vectors, each failing exactly one §4.3 step: tampered name, bitrate, `peer_url` and `peer_session_token`; another key's signature; a replay after success; a lower-seq challenge; relay B's MAC; a challenge for another identity; an altered nonce; a mismatched `metadata.identity_hash`; an unsigned metadata key; an upper-case public key; a browser asking for mode 6; a browser carrying `peer_url`; an unknown client; a wake gateway without peer fields; a poll gateway with `peer_url`; a relay at capacity; a low-order X25519 key. Revision 3 removed revision 2's `audience-mismatch` and `transit-identity-not-listed`, with the two challenges only they used. |
| `tokens_negative` | a flipped ciphertext bit, and decryption by the wrong identity. Both MUST fail to decrypt. |
| `url_canonical` | nineteen inputs to §10.1, with the canonical form and key or the reason for refusal. They include the look-alike `https://rétichat.com/…` (refused), its ASCII form `xn--rtichat-bya.com` (accepted, under a different key), case, port, `/v1/wake`, userinfo, query and fragment. |
| `gateway_confirm` | §9.8: the domain, the path, the field order, and the gateway's config (`node_url` written with a trailing slash, which pins the comparison of canonical forms, and `wake_url`). One positive: the confirm relay A sends for the `gateway-wake` row's stored canonical `peer_url`, to that URL plus `/v1/gateway/confirm`, with the field-by-field `lp` breakdown, the 143 signed bytes, the gateway's signature and its answer. Five refusals the gateway's handler gives: another identity, relay B, another wake URL, an upper-case nonce, an extra key. Ten answers the relay must not accept: another key's signature; the gateway's signature over another nonce, another wake URL or for relay B; its registration signature; an echoed nonce; the wake route's `{"status": "ok"}`; upper-case hex; an extra key; a `404`. |
| `php_relay_peer` | §10. Relay B's identity file (64 bytes, RNS layout) and identity hash; its config (`host_url`, and an `[interfaces]` list that writes relay A with a trailing slash); the id of its registration vector. `decrypt`: its token's decryption as the PHP client does it (§10.4), with the blob split into ephemeral key, IV, ciphertext and HMAC, and the shared, derived, HMAC and AES keys. `decrypt_negative`: four blobs it must refuse, with the reason: an all-zero ephemeral key (`zero_shared_secret`), a flipped HMAC bit, the gateway's token (`hmac`), and a correctly encrypted plaintext that is not 64 hex (`not_a_token`). `confirm`: relay A's §9.8 confirm of B's URL, its 149 signed bytes and B's signature; three refusals by B's handler (another identity, a relay not in its `[interfaces]`, a URL that is not its own); one answer the relay refuses (the gateway's key). `link_order`: four pairs of relay URLs with the relay whose registration is the link and the one that stands down (§10.3), including the live pair and a port that sorts after a path. `transport_id` (revision 7, §10.2.1): relay B's transport id, which is its identity hash, a pre-switch id, and the two as its own ids; a link request for the browser's `lxmf.delivery` destination as its sender packs it; and that packet put into transport three ways, as RNS `Transport.outbound` does: through B's transport id (own), through its pre-switch id (own), and through the gateway's identity hash (not own: `transport_id_mismatch`). Each carries its header fields and its packet hash, which is the same for all three, because the transport id is not part of it. |

Revision 3 removed revision 2's `audience_client` and `audience_relay`
sections. No vector carries an audience, and the PHP checker fails if one
does.

What changed from format 2 (revision 3): every signed byte string and
signature (the `audience` field is gone, so each signed string is 21 bytes
shorter for relay A's 19-byte host), and the sections above. The identities,
challenges, nonces, MACs, pinned encrypted tokens, token negatives and
canonical URLs are byte-identical, because none of them depended on the
audience. What changed from format 3 (revision 4): only the new
`gateway_confirm` section and the format number. Every other byte is the same.
Revision 5 changes no byte: re-confirming at every registration and the
outstanding-wake rule change when a confirm runs and when a wake is sent, not
what is signed. What changed from format 4 (revision 6): the identity
`relay_b`, its challenge, the positive vector `php-relay-peer`, the new
`php_relay_peer` section and the format number. Every earlier vector is
byte-identical. What changed from format 5 (revision 7): only
`php_relay_peer.transport_id` and the format number. Every other byte is
the same. Revision 7's other decisions (the two-way rule, a URL belonging to
one identity, runner liveness) change when things happen, not what is
signed or sent, so they have no vectors.

How the file was checked when it was committed (revision 7):

- **RNS 1.5.2:** `.venv/bin/python Reticulum-post/tools/registration_vectors.py --check`.
  `Identity.validate` accepts every signature (the RNS Ed25519 key for `lowx`),
  `Identity.hash` matches every identity, `Identity.decrypt` recovers every
  pinned token, and the generator's own §4.3 reference verifier gives every
  positive `200` and every negative its expected status, error and step. For
  `gateway_confirm`, `Identity.validate` accepts the positive's signature, the
  generator's reference gateway handler signs it and gives every refusal, and
  its reference answer verifier accepts the positive and refuses every
  negative answer. For `php_relay_peer`, its reference decrypt recovers the
  token and gives every refusal its reason, its PHP relay handler signs the
  confirm and gives every refusal, and `Identity.validate` accepts the
  confirm's signature. For `php_relay_peer.transport_id`, `Identity.from_bytes`
  of the identity file gives the transport id, and `Packet.unpack` and
  `Packet.get_hash` read every packet's header and hash.
- **PHP sodium/openssl:** `php Reticulum-post/tools/check_registration_vectors.php`
  (384 checks). It re-derives keys, MACs, signed bytes, pinned tokens and
  canonical URLs. It runs its own §4.3 verifier over all twenty-five
  registration vectors, comparing the status, the error and the failing step,
  and it decrypts every token. For `gateway_confirm` it checks that the
  confirm names the `gateway-wake` row's stored canonical URL and is sent only
  there, rebuilds the signed bytes, reproduces the signature through its own
  gateway handler (sodium), and runs its own answer verifier over every
  answer. For `php_relay_peer` it derives the identity hash from the file
  bytes, checks that the registration signs with that key as `reticulum-php`
  mode 1 with `peer_url` = the canonical `host_url`, runs its own PHP client
  decrypt (sodium, `hash_hkdf`, `hash_hmac`, openssl) over the token and every
  refusal, reproduces the confirm through its own PHP relay handler, and
  recomputes every link order with `strcmp`. For the transport id it
  derives the id from the identity file, puts the sent packet into transport
  itself, and decides each packet's own-or-not with `hash_equals` against
  the two ids. It fails on the files of revisions 2 to 6, and on each of
  these mutated copies: a changed expected error, an `audience` added back to
  a positive's `registration`, `audience` added back to the field order, a
  `transit_identities` list added to relay A, a canonical URL, a seq added to
  a challenge response, one hex digit of a gateway signature; and, for the
  confirm, the registration signature as the answer, the confirm sent to
  another URL, another `peer_url` in its body, a path under `/v1/wake`, the
  register domain, an unknown relay accepted, an echoed nonce accepted, the
  gateway's config naming another wake URL, and the field order changed;
  and, for the PHP relay peer, one byte of the identity file, an
  all-zero-key decrypt accepted, a `not_a_token` decrypt accepted, the
  unknown-relay refusal accepted, a link order swapped, its registration
  with mode 6, and its confirm's signature swapped for the gateway's; and,
  for the transport id, the pre-switch id given as the transport id, a third
  own id added, the pre-switch packet expected as not own, the other node's
  packet expected as own, one byte of a packet's transport id, and a
  packet's hash taken over its transport id.
- **Not re-run on revisions 2 to 7:** the Retichat-js `lib/rns/identity.js`
  (Node) and Reticulum-rust `identity.rs` cross-checks that revision 1
  recorded. The deterministic Ed25519 signature and the token derivation are
  unchanged primitives, and revision 3's signed bytes have revision 1's
  twelve fields again, but with the 48-byte challenge, so each port re-checks
  them in its own suite (below).

Each implementation MUST pin these vectors in its own test suite:

- **Reticulum-post:** feed every registration and negative vector through the
  real `registerInterface()` / challenge code. Set the relay secret from
  `relays.A`, and the row's `seq` and capacity from `relay_state_before`. Pin
  `url_canonical` against the real function. As a client (§10): sign
  `php-relay-peer` from the identity file, decrypt `php_relay_peer.decrypt`
  and refuse every `decrypt_negative`, answer `php_relay_peer.confirm` and its
  refusals through the real confirm handler, pin `link_order` against the
  real §10.3 rule, and feed each `transport_id` packet through the real
  packet filter and forward rewrite with relay B's identity file and its
  pre-switch id in `transport_state`.
- **Retichat-js:** check that `signRegistration()` reproduces
  `signed_bytes_hex` and `signature_hex`, and that decryption yields the
  plaintext.
- **Rust and Python:** the same, through the gateway's own signing and
  decryption paths, and `gateway_confirm` through the wake server's confirm
  handler: the positive gives `signature_hex`, and each refusal its status
  and error.

---

## 15. Required tests (each fails before the fix, passes after; §10 of the principles)

Reticulum-post, against the real traits (SQLite in memory or `php -S`):

- **`signed_registration_test.php`:**
  - INSERT at seq 0;
  - re-bind in place at a higher seq, with the same `interface_id` and a
    rotated token;
  - replay → 409;
  - a tampered field → 403;
  - relay B's challenge → 409;
  - a `registration` object with an `audience` key (revision 2's body) →
    `400 bad_registration`, and nothing is written;
  - a gateway identity that no config names registers `reticulum-php` and
    gets a transit row (open peering);
  - the challenge response contains no seq;
  - the response has no plaintext token and its encrypted token decrypts;
  - a low-order key → 400, and nothing is written;
  - two parallel registrations on one identity produce one row, and the loser
    gets 409.
- **`session_superseded_test.php`:**
  - after a re-registration, the old token gets `409 session_superseded`;
  - an unknown token gets 401;
  - a 401 on a PHP relay's client-row exchange registers again only when
    the compare-and-swap holds (§10.6).
- **`registration_rebind_rules_test.php`:**
  - the A1 takeover (an unsigned claim of a signed identity, and `'%'`, `'_%'`)
    neither finds nor re-binds the signed row, and the victim's token stays
    valid;
  - legacy creates only;
  - `identity_hash` from a non-`rns-js` client is ignored;
  - identity fields never appear in `metadata_json`;
  - a squatted row is retired, not adopted;
  - a signed gateway retires the legacy bridge row with its URL, and only
    `none` URL rows of transit-class clients;
  - each enforcement switch refuses its unsigned registrations and 401s its
    `none` rows;
  - the capacity rule reclaims legacy rows and then answers 503.
- **`announce_row_identity_test.php`:**
  - the A3 replay, through another signed row and through a legacy row with a
    made-up claim, does not move the victim's binding or its DATA;
  - a legacy row cannot bind a destination held through the gateway (the
    native-user case) or one whose blob is seen;
  - a dropped announce leaves `known_destinations` untouched;
  - **the seen-blob rule on every row kind (§8.5):** the A4 replay of a seen
    blob with its hop count lowered to 0 neither creates nor replaces a path
    through an endpoint row, a signed gateway row, a signed PHP relay row, a
    `local` client row or a legacy transit row, with the existing path usable,
    expired, or through an inactive row (no `shorter_path_replaced`, no
    `unusable_path_replaced` for a seen blob). Each case fails on bae739a;
  - on each of those row kinds, an announce with a new blob still replaces a
    path when the rules allow (`better_or_equal_hops_newer_announce`,
    `expired_path_replaced`, `newer_announce_replaced`,
    `unusable_path_replaced`);
  - the direct-versus-gateway order: the gateway copy first, then the direct
    copy of the same announce, keeps the gateway path; a later announce
    through the direct peer first moves it (the cost §8.5 states);
  - a browser's own `lxmf.delivery` and rfed announces still bind.
- **`peer_url_canonical_test.php`:**
  - pins `url_canonical`;
  - a static check that no SQL in `php/src` compares `peer_url` (only
    `peer_url_key`);
  - a look-alike `waker_url` reaches only the stored URL (§0.1).
- **`peer_link_test.php`** (§10), on two `php -S` relays, A and B, with A's
  canonical `host_url` sorting first, `register_at_peers` on, and each with
  its own identity file:
  - **both configure each other → exactly one link:** both register; after
    the dust settles A holds a `connected` client row for B, B holds A's
    signed row with `wake_confirmed`, B has no client row for A and has logged
    `[PEER-STANDDOWN]`, and A's signed row for B is `closed` by the goodbye.
    Run it in both orders (A's registration first, B's first) and with both
    started in the same request;
  - **one-sided config forms a link:** only B configures A → B's client row at
    A, and A registers nowhere; only A configures B → A's client row at B;
  - **traffic both ways on one link:** a packet queued for B at A goes out on
    A's exchange runner with no wake; a packet queued for A at B wakes A, whose
    wake handler spawns one exchange that pulls it; nothing is ever POSTed to
    A's `/v1/interfaces/exchange`;
  - **a DB reset on each side re-forms one link from events:** clearing A's
    database makes A's next ingest request (or B's wake) register again, B
    re-binds A's row in place (same `interface_id`, seq + 1) and B registers
    nowhere; clearing B's database makes A's next exchange get `401` and
    register at once, B registers at A as well, then stands down once A's
    registration is confirmed. Each ends with exactly one link;
  - **backoff without a timer:** with B answering `503`, A's attempts follow
    2, 4, 8 … 300 s, each made only at the first ingest request after its
    delay (driven by a test clock and real requests; nothing sleeps). No
    attempt happens without an ingest request. `/health`, `register`,
    `challenge` and `/v1/gateway/confirm` requests never count. A wake from B
    resets the delay and registers at once. A spawn failure releases the
    claim and counts as a failure;
  - **one registration at a time:** two prelude runs racing for one due client
    row make one claim and one runner;
  - **`409 session_superseded`** on A's exchange makes the client row
    `superseded`: no backoff, a wake does not restart it, and
    `GET /v1/initialize` does;
  - **the identity file survives a DB reset:** same identity hash, same row at
    the peer, same `interface_id` there;
  - **the identity file is created once:** concurrent first requests in
    separate processes end with one 64-byte file, mode 0600, and the same
    hash; a file of the wrong length is an ERROR, never overwritten, and the
    relay registers nowhere;
  - **the identity never leaks:** after a registration, a confirm and a stand
    down, no response, `/health`, `/debug`, monitor page or log line contains
    any byte of the file's 64 bytes in hex, base64 or raw;
  - **a lost identity file:** A gets a new identity, registers as a new row at
    B, B's confirm retires the old row (proof `retired`, its seq kept,
    `[REG-RETIRE-IDENTITY]`), and A's client row re-registers at the next
    ingest request because `registered_as` changed;
  - **credentials only to stored URLs:** with recording stand-ins for curl,
    streams and sockets, A's session token at B is sent only to
    `<B's canonical node_url>/v1/interfaces/exchange` and `/goodbye`, whatever
    `waker_url` a wake carries, and B sends A nothing but wakes and confirms,
    to A's stored, confirmed URL;
  - **the client decrypt:** A decrypts `php_relay_peer.decrypt` and refuses
    each `decrypt_negative` with its reason, writing no credentials;
  - **the confirm handler:** `php_relay_peer.confirm` and its refusals through
    the real route, which reads no database row and makes no outbound call;
  - **the legacy migration (Phase 3b):** two relays peered the legacy way;
    switching `register_at_peers` on at A retires B's legacy rows for A (§4.5)
    and A's own (§10.4), B's legacy reconnect is refused with
    `403 peer_confirmation_required`, and switching B on leaves one link.
    Switching both off stands the client rows down, and `GET /v1/initialize`
    re-forms the legacy peering;
  - with `register_at_peers` off, the legacy peering behaves exactly as at
    bae739a (the two legacy tests below stay green);
  - **a dead registration runner** (revision 7, §10.6): a runner killed by
    the test (SIGKILL) after it took its claim is found gone at A's next
    ingest request, which makes the row `refused:0:runner_gone` with a 2 s
    delay and logs ERROR; the first ingest request after the delay registers,
    and so does a wake from B at once. A live runner, held by a stand-in curl
    that waits for a control lock the test holds, is never replaced, however many
    requests arrive and wherever the test clock is moved. Fails on revision
    6's rule, which leaves the row `registering`;
  - **a dead stand-down runner** (§10.7): the client row is deleted without a
    goodbye and `[PEER-STANDDOWN] <B> runner_gone dropped=<n>` counts the
    packets it held;
  - **the exchange spawn rule without a clock** (§10.5): a pending runner that
    is alive absorbs a wake and a queued packet; one killed before it starts
    does not, and the next wake spawns another; one that has started does not
    absorb either. Moving the test clock forward or back changes none of
    these decisions;
  - **a stranger's pending confirm moves nothing** (A16, §10.3): with both
    relays configuring each other and A sorting first, a fresh key registers
    at B naming A's URL, and while its confirm is pending B neither stands
    down nor stops registering at A. A's own re-registration, whose
    re-confirm is pending, does keep B from registering. The first case fails
    on revision 6's rule;
  - **a host that cannot spawn** (§10.10): with `proc_open` unavailable (a
    stand-in), a due registration makes no claim and no lock file, becomes
    `refused:0:runner_unavailable` under the backoff, and `/health` shows
    `runner_spawn` with the reason.
- **`gateway_wake_confirm_test.php`** (§9.8), with curl, streams and sockets
  replaced by recording stand-ins, as
  `wake_exchanges_only_with_stored_peer_url_test.php` does:
  - an unconfirmed signed gateway row is never woken: with packets queued for
    it, `dispatchWakes` sends it nothing, before the confirm, after a failed
    one, after a re-registration with the same URL, and after a URL change;
  - the confirm goes only to the stored canonical `peer_url` plus
    `/v1/gateway/confirm`. The stand-ins see exactly one POST per runner, to
    that URL, whatever form the registration wrote the URL in, and never to a
    `waker_url` or any other URL;
  - the positive vector's answer confirms the row, after which it is woken
    at its stored URL, once at confirm time if packets are queued;
  - each `answer_negative` vector leaves the row unconfirmed and unwoken,
    deletes the record, and logs `[GW-WAKE-CONFIRM-FAIL]` with its reason;
  - the pending bounds: one record per row (a second registration replaces
    it, and the first runner's success is discarded); with 64 records of
    other rows, a registration still answers `200`, makes no record, spawns
    no runner, and logs `[GW-WAKE-CONFIRM-BACKLOG]`;
  - **re-confirm every time:** a re-registration with the same, confirmed URL
    clears the confirmation and `wake_outstanding` in the bind's UPDATE (on
    SQLite: §4.4's assignments are now constants, so no engine-specific `SET`
    order is left to pin), starts exactly one confirm, and wakes nothing until
    that confirm succeeds. Packets queued in the gap go out in the one wake
    sent at confirm time. One with a new URL does the same, and wakes neither
    URL in the gap;
  - **a stale confirm is discarded:** the previous registration's confirm,
    for the same URL, landing after the new bind confirms nothing and logs
    `[GW-WAKE-CONFIRM-STALE]`. That holds both when it lands after the new
    record replaced its own (the `DELETE` fails) and when it lands between the
    new bind and the new record (the `registration_seq` in the `UPDATE`
    fails). The same holds for a confirm for an old URL;
  - **one outstanding wake:** after a wake that left, the row is not woken
    again until its next authenticated exchange or signed bind, however many
    packets queue; a wake reported `[WAKE-DROP]` leaves it wakeable; and a
    gateway that stops exchanging receives exactly one wake after its last
    exchange, then none, with packets still queued;
  - a PHP relay's signed row follows the same rules; legacy `reticulum-php`
    rows are woken exactly as before; a `local` client row is never woken
    (the client exchanges instead, §10.5);
  - **a dead confirm runner** (revision 7, A17): a confirm runner killed
    before its answer leaves its record, which no longer blocks anything.
    With 64 records, one of them dead, a new registration's step 2 deletes
    the dead one (`[GW-WAKE-CONFIRM-FAIL] … runner_gone`) and makes its own
    record; §10.3's check does not count the dead record as pending. Fails on
    revision 6, where the dead record stays and the new registration logs
    `[GW-WAKE-CONFIRM-BACKLOG]`;
  - **the proven key** (A16): step 5 sets `wake_url_proven_key` with the
    confirmation; a re-bind clears the confirmation but keeps it; a retire
    clears both.
- **`transport_id_test.php`** (revision 7, §10.2.1), against the real traits:
  - every announce the relay relays, every path response it builds and every
    path request it sends carries the identity file's hash as the transport
    id. Fails on bae739a, where it is the random `identity_hash_hex`;
  - that id survives `clearAllData()` and a new SQLite file. Fails on
    bae739a;
  - with `identity_hash_hex = P` in `transport_state`, a packet in transport
    through `P` is accepted and forwarded exactly as one through `H` (the
    filter, the forward rewrite and the outbound rewrite), and one through any
    other id is refused `transport_id_mismatch`. The
    `php_relay_peer.transport_id` vectors go through the real filter;
  - the relay never writes `identity_hash_hex`: on a fresh database no such
    row appears after traffic in every direction, and after `clearAllData()`
    a packet through `P` is refused;
  - an identity file of the wrong length, or a directory that cannot be
    created: every ingest endpoint answers `503 relay_identity_unavailable`,
    nothing is ingested or relayed, `[RELAY-IDENTITY] ERROR` is logged, and
    register and challenge still answer;
  - `[RELAY-IDENTITY] created` is logged once, when the file is made, and not
    on every request.
- **`runner_liveness_test.php`** (revision 7, §10.10), with real processes:
  - the lock passes to the runner with no gap: once the spawning request has
    closed its descriptor, `runner_alive` is true for as long as the runner (a
    test job that waits for a control lock the test holds) runs. After it ends
    normally its file is gone. After SIGKILL its file is there, `runner_alive`
    is false, and the check deletes the file;
  - two requests that find one runner gone act once (compare-and-swap);
  - a claim that loses its compare-and-swap leaves no lock file;
  - `php index.php runner-selftest` prints `PASS` on the test host, and `FAIL`
    when the runner is spawned without the descriptor (a stand-in);
  - a runner inherits its own lock and no other: a lock the spawning
    request holds for something else is free once that request lets it go;
  - static checks: every lock file is opened close-on-exec (`e`); no
    handed-over lock is ever released with
    `flock(LOCK_UN)`; `runner_alive` and every claim, spawn and liveness path
    read no clock (`time()`, `microtime()`, `hrtime()`,
    `$_SERVER['REQUEST_TIME…']`); no lock file is made under
    `sys_get_temp_dir()`.
- **`health_allowlist_test.php`** adds `transport_id`,
  `previous_transport_id`, `runner_spawn` and each client row's `runner`, and
  still publishes nothing from the identity file and neither path.
- **`peer_session_rotation_test.php`** and **`peer_session_self_heal_test.php`**
  pin today's legacy peering, which runs while `register_at_peers` is off.
  They stay green until Phase 3c, and go with the legacy code after it.
- **`schema_migration_marker_test.php`:** the new columns (the client-row
  columns of §12.1 included), the UNIQUE index, `gateway_wake_confirms` with
  `runner_id`, no `peer_registration_*` table, no `last_exchange_*` column,
  and the backfills (`rns-js` claims only; canonical URLs and keys), all
  idempotent.
- **Tests that read the transport id today** (`packet_filter_contexts_test.php`
  calls `transportIdentityHashHex()`; `hops_test.php`,
  `gateway_path_request_test.php` and `local_link_relay_sql_test.php` stub
  it) keep their meaning: `transportIdentityHashHex()` returns `H`, and the
  three own-id checks go through one function that accepts `H` and `P`.
- **MySQL gap.** Nothing here runs on MySQL or MariaDB. Before Phase 1,
  James runs one read-only probe on each production database:
  `SELECT COUNT(*) FROM interfaces WHERE peer_url = 'https://rétichat.com/reticulum'`
  against a known stored URL. It must show that the collation folds, and so
  that keys are needed. Then the gate in §11.2 runs on the real schema.

Retichat-js:

- `post_interface_signed.test.mjs`:
  - challenge, then sign (twelve fields, no relay address), then decrypt;
  - a 409 `stale_challenge` leads to one more challenge, and a second 409
    stops;
  - `session_superseded` stops with its message;
  - terminal codes stop without the 5 s loop;
  - a challenge 404 leads to legacy;
  - a 401 re-registers signed once.
- `register_canonical_vector.test.mjs` pins §14.

Reticulum-rust and Python:

- vector tests;
- a 401 re-registers without ever going offline in Transport;
- **the backoff schedule (§9.6).** The delay is a pure function of the count
  of consecutive failures, and the worker's timer is driven by a test clock,
  never by sleeping (§7 of the principles):
  - consecutive failures give 2, 4, 8, 16, 32, 64, 128, 256, 300, 300 s;
  - each kind of failure starts it: a network failure, a 5xx, a terminal
    code, a second `409 stale_challenge`, a signed answer without
    `session_token_encrypted`, and a failed challenge request; a challenge
    `404` (legacy) and a first `409 stale_challenge` do not;
  - while it lasts the interface is offline in Transport with the code as its
    reason, and each failed attempt logs ERROR with the next delay;
- **its resets:** a success puts the interface online and the next failure
  waits 2 s again; a wake mid-wait registers at once and resets the delay; a
  wake during an in-flight registration starts no second one; an outbound
  packet starts nothing; in poll mode only a success resets it;
- `409 session_superseded` on an exchange takes the interface offline with no
  backoff: no timer fires, and a wake does not restart it;
- a failed exchange is not retried and does not sleep (the 60 s exchange
  back-off is gone);
- **the wake-URL confirm handler (§9.8):** the `gateway_confirm` positive
  signs to `signature_hex`; each `gateway_refusals` vector gives its status
  and error and signs nothing; `POST /v1/gateway/confirm` never signals a
  wake, and no `POST /v1/wake…` is answered as a confirm; the handler answers
  before the registration's answer has been read; the wake listener's bind
  comes before the first registration, and a failed bind is logged ERROR and
  still lets the gateway register;
- a restart keeps the same `interface_id` (staging);
- a fresh relay DB while the gateway runs heals through the 401
  (`staging.sh`'s fresh-DB guard, lines 308–318, comes out once this
  passes).

Staging stage `stage_transport_id_switch` (revision 7): the gateway learns a
path to a browser's destination through a staging relay on bae739a; the relay
moves to this code; a packet on that path still reaches the browser; and
after the browser's next announce, the gateway's path names the relay's
identity hash. MUST fail on a build of this code that does not keep `P`.

Staging stage `stage_relay_takeover`: MUST fail on Reticulum-post bae739a and
the current Retichat-js and gateway (the A1, A3 and A5 probes succeed), and
pass on the fixed refs.

---

## 16. Residual exposure, decisions, and questions for James

### 16.1 What stays open, and until when

1. **Legacy browser rows until `enforce_signed_registration`.** A victim with
   no signed row on a relay can still be taken over there through the legacy
   path (A1 against a `none` row). §8.3 confines what a legacy row can bind.
   The one hole left is a race. An attacker on the Reticulum network hears a
   native user's fresh announce and delivers it through a legacy row before
   this relay hears it any other way. If the relay has never reached that
   destination before, the attacker gets the binding.
2. **Legacy transit rows until `enforce_signed_transit`.** Anyone can still
   create a `none` `reticulum-php`, `rns-post-interface` or `reticulum-post`
   row, which is a transit row (it skips the identity guard, §8.2) and
   re-bindable by URL (A5). This is today's exposure, unchanged until Phase
   3c. A4 is no longer part of it: §8.5 holds on legacy rows from Phase 1.
3. **Registrations can be flooded.** Since revision 6 a peering is an
   ordinary signed registration, so a flood is a flood of keys: rows are
   bounded by §12.4, and each registration's wake-URL confirm by §9.8's 64
   pending records, each holding a detached runner until the URL answers or
   curl's ceiling ends it. While the confirm records are full, new gateway
   and relay rows stay unconfirmed and unwoken, but they still work by their
   own exchanges, and links that exist are untouched. A URL that kills its
   confirm runner (an answer too large for its memory) frees the record at
   the next check (§10.10), so it holds a record no longer than a URL that
   answers slowly; revision 6 let it hold one for good (A17). Junk
   `GET /v1/initialize` calls make a relay register again only where a client
   row is not connected (§10.6).
4. **Existence oracle until `enforce_signed_registration`.** A legacy
   registration claiming `H` gets `403 identity_requires_signature` when `H`
   has a signed row here, and `200` otherwise. That tells anyone whether `H`
   has ever registered signed on this relay. It does not say when, because
   signed rows are permanent.
5. **Restoring a DB backup** brings back an old `relay_secret` together with
   old `seq` values. Each captured body in that range can then be replayed
   once. The replayer gets an encrypted token it cannot use, so the cost is
   one session eviction per captured body. With §6.1, the evicted holder stops
   and shows "connected elsewhere" until it reloads.
6. **The `/v1/wake` handler still exchanges inline** (`index.php:1804`), a
   synchronous outbound call in a request handler (§7 of the principles). It
   goes only to a stored URL since d3a0eb5 (§0.1). Even so, an unauthenticated
   flood of wakes against both relays can hold every worker on each side
   waiting on the other until curl's 10 s ceiling. That is true today, and
   stays true for the legacy peering until Phase 3b. With `register_at_peers`
   on, the wake handler spawns the exchange runner and answers at once
   (§10.5), so no worker waits on another relay. A flood of wakes naming a
   configured relay still costs this relay one runner (one exchange with
   that relay) per wake that §10.5's spawn rule does not absorb, as today's
   inline exchange per wake does.
7. **Replays can still roll back a remembered ratchet through a transit row.**
   `rememberKnownDestination`, like RNS 1.5.2's `Identity.validate_announce`,
   stores the ratchet and `app_data` of any valid announce, replays included.
   §8.4 keeps foreign announces on endpoint rows from doing it, but a replay
   through a transit row still can, and with open peering anyone can hold a
   transit row. Changing that would depart from the reference, so it is left
   as it is.
8. **A12, accepted (James, 2026-10-03).** A relay the user chose can forward
   another relay's challenge and end up holding the identity's session there
   (§3.2). It stays accepted while nobody can choose a relay other than
   James's two: the web client's CSP, the gateways' configured node URL, and
   the PHP relays' own `[interfaces]`.
9. **Open peering gives anyone a transit row.** A fresh key, registered as a
   gateway or as a PHP relay, is enough. A
   transit row skips the identity guard (§8.2), so it can deliver a
   destination's fresh announce here first and hold the path until that
   destination's next announce reaches this relay first some other way. §8.5
   stops it doing the same with a blob already seen, whatever hop count it
   claims. This is the exposure of any open RNS transport interface: payloads
   stay end-to-end encrypted, but delivery can be denied and link metadata
   seen. James accepted open peering on 2026-10-03.
10. **A gateway's wake URL is proven at every registration.** Revision 3 woke
    a signed gateway row at its unproven `peer_url` (A15). Revision 4
    confirmed it first (§9.8, James 2026-10-03: "Confirm it first"), and
    revision 5 confirms it again at every signed registration (James: "Re-confirm
    every time"). What remains:
    - **after a gateway stops altogether, at most one wake is delivered.** No
      row lifetime ends a signed gateway row's wakes (§9.8, "What ends
      wakes"). The outstanding-wake rule does: a host that takes over a lapsed
      name receives at most one fixed, credential-free wake. Later attempts
      fail before anything is sent, each a `[WAKE-DROP]` that costs this relay
      one failed connect per `min_wake_interval_ms`, until the gateway
      registers again or an operator deletes the row;
    - **each registration opens a short no-wake gap** until its confirm lands.
      The one wake at confirm time carries what queued;
    - **confirms go to unproven URLs by design**, from detached runners, at
      most 64 at once and one per registration. A tarpit holds a runner, not a
      PHP worker, until curl's ceiling;
    - legacy `reticulum-php` rows are still woken at unproven URLs, as today,
      until `enforce_signed_transit` (item 2).
11. **The table can fill with permanent rows.** Signed and retired rows (a
    fresh key each) are never reclaimed (§12.4, §12.5). Once the table is
    full, new registrations get `503 registration_capacity`. Rows that exist
    keep working. Revision 6 removed the `confirmed` rows revision 3 added to
    this.
12. **PHP peering, after revisions 6 and 7.** Revision 4's one-sided-peering
    gap is gone: the relay that lists the other registers, and a server's DB
    reset is noticed by the client's own `401` (§10.9). What remains:
    - **a brief double link** when both relays of a pair register at once,
      until the later-sorted one stands down (§10.3, §10.7); and a lasting
      one when the earlier relay's URL fails to confirm at the later relay
      (a confirm runner that dies included) while the later relay's own
      registration works, until the earlier relay's next registration.
      James accepted both on 2026-10-04. After the later relay's DB reset the
      double link lasts until the earlier relay's confirm lands, not only
      until it registers (A16);
    - **a lost goodbye** leaves the stood-down relay's row active at the other
      side: announces queue into it up to the storage cap, and it is woken at
      most once (§10.7);
    - **a runner that dies** costs its attempt and no more. Revision 6 left a
      dead registration runner's row `registering` until `GET /v1/initialize`.
      Since revision 7 the next ingest request finds its lock free (§10.10):
      a registration is a failed attempt under the backoff, a stand-down
      completes without its goodbye and drops what the row still held, and a
      confirm is a failed confirm;
    - **an idle relay makes no attempt.** The backoff runs only at ingest
      requests (§10.6). A relay that receives none, with its link down, stays
      down until a request arrives: a browser, a gateway, or the peer's wake;
    - **an `http` `node_url`** sends the session token in the clear. That is
      the operator's config choice; production uses `https` (§10.1);
    - **the identity file sits on the relay's host**, mode 0600 and outside
      the web root. Anyone with the hosting account's files has the key,
      exactly as with the database and its `relay_secret`. Since revision 7
      that key also names the relay as a transport node (§10.2.1).
13. **§8.5's cost: watched** (James, 2026-10-03: "Leave it, watch it"). The
    retichat↔selectiv direct-versus-gateway case that `shorter_path_replaced`
    covered can come back: when the gateway copy of an announce arrives
    first, the path stays on the gateway until a later announce reaches this
    relay through the direct peer first. §11.2's Phase 1 note is the watch.
    If it ever matters, the fix is RNS 1.5.2's per-interface `gravity`: an
    operator-set preference that lets a copy of an announce already heard
    move the path to a row of higher gravity, never on hop count (§8.5).
14. **The transport id switch (§10.2.1).** James decided it on 2026-10-04.
    What it leaves:
    - **two ids are the relay's own**, a departure from RNS's one. Anyone
      who can reach the relay could already address it by its single id, so
      the second one opens nothing new. It lasts as long as the database
      keeps it, and no clock ends it;
    - **a DB reset after the switch forgets the pre-switch id.** Packets on
      paths that neighbours still hold through it are then refused
      (`transport_id_mismatch`) until the next announces teach them the
      identity hash. At bae739a every reset changed the id outright, so this
      happens at most once more;
    - **a lost identity file changes the transport id** (§10.2), with the
      same cost as such a reset. Only the pre-switch random id is kept as the
      relay's own, not a lost identity's hash: the relay has no record of it;
    - **a neighbour still on the pre-switch id does not recognise this
      relay's path requests as coming from its next hop**: they carry the new
      id (the requestor check: RNS 1.5.2 `Transport.path_request`,
      Transport.py:3475; `requestor_is_next_hop`,
      `request_control_plane_trait.php:170`, here). It may answer one with a
      path back through this relay, which leads nowhere until the
      destination's next announce. A packet sent round that loop comes back
      with the same packet hash, which leaves out the transport id (vectors
      `php_relay_peer.transport_id`), so its second copy is dropped as a
      duplicate. It can happen only while this relay has no path to that
      destination and the neighbour has a stale one through `P`;
    - **no identity, no relay.** If the identity file cannot be loaded or
      made, every ingest endpoint answers `503` (§10.2.1). Revision 6 lost
      only its peering in that case.
15. **The legacy wake runners keep bae739a's handling.** A `wake-event`
    runner (`spawnDetachedWakeRunner`) that dies leaves its `wake_events` row
    claimed until maintenance expires it by age (`wake_event_ttl_seconds`,
    `deleteExpiredWakeEvents` in `request_maintenance_trait.php`): a clock, in
    the legacy peering's code. §10.10 does not cover it, because that code
    goes after Phase 3c (§11.2). Flagged under "How to apply" item 4 of the
    principles.
16. **A host without `proc_open`, or whose runner directory does not share an
    `flock` lock across a fork, cannot peer the signed way** (§10.10). It
    keeps the legacy peering until Phase 3c and cannot peer after it. Both
    production hosts must pass `runner-selftest` before Phase 3b.

### 16.2 Decisions, and questions for James

James decided on 2026-10-04 (revision 6):

| Decision | Revision 6 |
|---|---|
| A PHP relay peer registers at another relay exactly like the gateway, replacing the one-time-nonce handoff | §10 rewritten: an identity file per relay (§10.2); every relay registers at every relay it configures, with one link per pair (§10.3); the gateway's registration, token, confirm, wake and backoff (§10.4 to §10.6); the legacy peering moves over in Phase 3b (§11.2) |
| Keep the session token encrypted to the registrant (§5) | §5 unchanged; the PHP client's decrypt is §10.4, with vectors |
| A PHP relay runs no timer: its backoff's next attempt is made at the first incoming request after the delay | §10.6 names the requests that count; `DESIGN_PRINCIPLES.md` §3 records the exception |

James answered revision 6's questions on 2026-10-04, each time as
recommended:

| Revision 6 asked | James decided | Revision 7 |
|---|---|---|
| 1. The relay's transport id: switch to the identity's hash, and when? | Switch it (RNS parity, stable across DB resets), and keep treating the old random id as the relay's own too, so packets on paths learned before the switch are not dropped | §10.2.1: the transport id is `H`; the pre-switch id `P` stays the relay's own while the database keeps it; it switches in Phase 1 (§11.2); vectors `php_relay_peer.transport_id` (format 6) |
| 2. The rule for two-way configs (both register; the later-sorted relay stands down while it holds the earlier relay's registration, confirmed or pending; a double link remains while the earlier relay's URL fails to confirm) | Accepted | §10.3 records it. Applying it found A16: "pending" now counts only for an identity that has proven the URL here before |
| 3. A confirmed wake URL belongs to one identity; a new identity's confirm retires other identities' signed rows for that URL, gateways too | Accepted | §9.8 records it; a retire also clears the proven key and the record |
| 4. A dead registration runner waits for `GET /v1/initialize` | Replace the wait: on its next request the relay checks whether the runner process still exists, with an OS check and never a clock, and starts again if it is gone; the same principle wherever the spec guards a dead runner with a time bound, and say what hosts without the OS support do | §10.10 (an OS lock handed to the runner at fork); §10.5's spawn rule loses its clock; §10.6, §10.7 and §9.8 act on a gone runner; A17 |

Open questions (revision 7). Each is a choice the decisions above forced
and James has not made (§18):

1. **How the relay asks the OS** (§10.10). James suggested the runner's
   process id, checked with `posix_kill(pid, 0)` or `/proc`, plus a nonce
   the runner writes to guard against a reused id. The spec uses an `flock`
   lock handed to the runner at fork instead: a reused id cannot fool it, it
   needs no extension, and it works on macOS staging, where there is no
   `/proc`. It needs `proc_open` and a runner directory on the host's own
   disk, which `runner-selftest` checks before Phase 3b. Acceptable? And if
   a production host fails the self-test: a process-id check (exact with
   Linux's `/proc`, with a reuse gap through `posix_kill` alone), or no
   signed peering on that host?
2. **A dead registration runner starts again on the backoff** (§10.6), at
   the first ingest request 2 s or more after the death (at once on a wake
   from the peer), not in the request that found it gone. That keeps a
   runner that dies the same way every time from being restarted at the
   rate requests arrive. Acceptable?
3. **A stranger's pending confirm no longer counts** (A16, §10.3). The cost:
   after the later relay's DB reset, the double link lasts until the earlier
   relay's confirm lands, not only until it registers. Acceptable?
4. **A dead stand-down runner** (§10.7): the stand-down completes without it,
   dropping what was still queued on the client row and sending no goodbye,
   rather than running the stand-down again. Acceptable?
5. **No identity, no relay** (§10.2.1). A relay that cannot load or create
   its identity file answers `503` on every ingest endpoint, rather than
   carrying traffic under its pre-switch id (which a DB reset would lose).
   Acceptable?

James's earlier answers, 2026-10-03:

James answered revision 2's questions on 2026-10-03:

| Revision 2 asked | James decided | Revision 3 |
|---|---|---|
| 1. Ship the §0.1 hotfix first? | Shipped as d3a0eb5; bae739a gates the next peering rotation on it | §0.1 |
| 2. Accept-lists (`transit_identities`, `accepted_peer_urls`), closing open peering for v1 | "Keep peering open" | No lists. Transit by proof (§8.1, §10); A4 closed on every row (§8.5) |
| 3. A second switch, `enforce_signed_transit` | Yes: browsers on a date James sets, gateways and peers after their rollout | §11.1 |
| 4. The signed `audience` | "Don't we have ssl to prevent spoofing?" Dropped | §3.2; A12 accepted (§0, §16.1.8) |
| 5. The wake-back | Yes, only between configured relays | §10.9 then; removed by revision 6, which needs none (§10) |
| 6. The gateway after a 5xx | Exponential backoff, 2 s doubling to 5 min, reset on success or a wake: his decided exception to §3 of the principles | §9.6 |
| 7. `409 session_superseded` | Yes: the newest registration wins, the older session is told "connected elsewhere" | §6.1 |
| 8. `reticulum-post` (`[post_interface_peers]`) has no path once `enforce_signed_transit` is on. Does any relay configure it? | Not yet answered | Still open (below) |

James answered revision 3's questions the same day:

| Revision 3 asked | James decided | Revision 4 |
|---|---|---|
| 2. One-sided peerings: should a third-party relay whose URL sorts after ours be able to start a peering (a receiver-side tie-break, `409 peer_initiator_conflict`)? | "Keep it, revisit later" | §10.3 unchanged then. Revision 6 resolves it: the relay that lists the other registers (§10.3) |
| 3. Wakes to a signed gateway's unproven `peer_url`: accept, or prove the URL first? | "Confirm it first" | §9.8; A15 |
| 4. §8.5's routing cost: add gravity, or not? | "Leave it, watch it" | §11.2's Phase 1 note; §16.1.13. Gravity is the fix if it ever matters |
| 1. `reticulum-post` (`[post_interface_peers]`) | Still open | Below |

James answered revision 4's question the same day:

| Revision 4 asked | James decided | Revision 5 |
|---|---|---|
| A confirmation lasted while the URL was unchanged, so a restart was not re-confirmed, and a lapsed name behind a confirmed URL kept being woken. Re-confirm on every registration? | "Re-confirm every time" | §4.4 clears the confirmation at every signed bind; §9.8 starts a confirm at every signed registration, with the CAS on `registration_seq`; §9.8 states what ends wakes to a gateway that stops, and bounds it with one outstanding wake; §16.1.10 |

Still open:

1. **`reticulum-post` (`[post_interface_peers]`)** has no path once
   `enforce_signed_transit` is on. The live configs of both relays are
   checked for a `[post_interface_peers]` block before Phase 3c, and §11.2's
   Phase 3c gate includes that check. A relay that configures one must move
   that link to `[interfaces]` peering first.

---

## 17. Revision 2: what the review of revision 1 changed

Every finding was checked against the code at 3281ad5. All of them were
confirmed in substance and adopted, apart from the parts listed as not
adopted below.

This is revision 2's record, kept as it was written: its section and step
numbers are revision 2's. Rows marked *(rev 3)* were changed by James's
decisions of 2026-10-03, and §18 says how.

| Finding | Disposition |
|---|---|
| Critical: collation look-alike (live wake path; revision 1's confirm to the body URL; Ltok never rotated) | Confirmed in code. The collation was checked with ICU, not MySQL. §0.1 hotfix proposed; §10.1 ASCII canonical URLs and SHA-256 keys; §12.2 no free-text lookups; §10.2 calls only to configured URLs; the initiator's token rotates at every confirmed connect (§10.6). URL vectors added. |
| High: transit by label | Confirmed (`isPhpPeerInterface`, `client` gates, `shorter_path_replaced`). §4.3.1 per-client policy (new codes and 5 negative vectors); §8.1 transit rows proven by `local`, accept-listed `confirmed` or listed `signed`; §0 A4 corrected. *(rev 3: no lists, peering is open; transit by proof alone, and A4 closed on every row instead.)* |
| High: confirm tarpit, wake-back, nested deadlock; "`/v1/wake` already nests" was false (`fireAndForgetWake` does not wait) | Confirmed. Confirms and wake-backs go only to configured URLs; the receiver answers `202` and confirms from the detached runner; promotion on first use removes the ordering window; one initiator per pair (§10.3) stops two hand-offs from interleaving; the false claim is gone (§10.10). *(rev 3: the confirm goes to the canonical URL the registration names, still from the detached runner; wake-backs still only to configured relays.)* |
| Medium: A3/A6 open for identities with no signed row (natives) | Confirmed. §8.3 (seen and held) narrows it from Phase 1; the remaining race is stated in §16.1. |
| Medium: seq activity oracle | Confirmed. The challenge is 48 bytes and opaque, and steps 5 and 6 of revision 1 merged into step 6; no seq in any response. Vectors regenerated. The legacy 403-vs-200 existence oracle is kept (§16.1.4). |
| Medium: nonce not bound to the relay | Confirmed. `confirmer_url` is part of the consuming `DELETE` (§10.6). |
| Medium: 401 cannot tell lost from superseded | Confirmed. `previous_session_token_hash`, `409 session_superseded`, peer compare-and-swap (§6.1). |
| Medium: retries presented as events | Confirmed. Refused state with named events (§10.8); atomic throttle; nonce deletion by key and nonce; gateway offline in Transport (§9.6); the 900 s and 3600 s clocks removed from connect decisions. The wake-back's 2 s connect ceiling is kept and named (§10.9). *(rev 3: the gateway registers again on a 2 s to 5 min backoff, James's decided exception to §3 of the principles.)* |
| Medium: unbounded rows | Confirmed; pre-existing for legacy rows. §12.4 capacity with legacy reclaim; signed rows are never reclaimed. |
| Low: seq restart | Confirmed. §12.5 invariant, `monitor.php` rules, README warning. |
| Low: relay as challenge oracle | Confirmed. §3.2 audience from the connection's `Host`; §2.3 corrected. *(rev 3: audience dropped; A12 is an accepted risk.)* |
| Low: low-order X25519 | Confirmed (sodium throws; RNS raises). Token before bind, `400`, negative vector. |
| Low: guard after `rememberKnownDestination` | Confirmed (`request_control_plane_trait.php:19-28`). §8.4 moves the guard. |
| Low: rollout gaps | Confirmed. Phase 3 retires the legacy bridge row automatically (§4.5); Phase 3b/3c/4 gates read `/health`; `reticulum-post` listed in §1; backfill limited to `rns-js` and filled lazily (§12.3). |

**Not adopted:**

- Making the stored ratchet and `app_data` monotonic. RNS 1.5.2 does not do
  it, so it would be a parity departure. §8.4 and §16.1.7 record it.
- Gating `/v1/initialize` behind `debug.enabled`. It is the production
  rotation procedure, so it stays open, but it can no longer touch a connected
  peering (§10.8).
- Changing the collation or adding backend-specific DDL. Hex keys make that
  unnecessary (§12.2).

---

## 18. Revisions 3 to 7: James's decisions of 2026-10-03 and 2026-10-04

Rows for revisions 3 to 5 give those revisions' section numbers. Revision 6
rewrote §10, so their `§10.x` references point at text that is gone.

| Decision | What changed |
|---|---|
| **No audience / Host binding.** James: "Don't we have ssl to prevent spoofing?" | `audience` removed from the signed bytes (§3: twelve fields), the worked example (§3.1), the request (§4.1: four `registration` keys) and verification (§4.3: old step 5 gone). §3.2 now says why there is none, and what TLS does and does not do. `403 audience_mismatch` removed (§6). A12 marked accepted (§0, §16.1.8). The gateway signs no relay address (§9 step 2). The Phase 1 `Host` gate is gone (§11.2). Vectors: no `host`, no `audience-mismatch`, no audience sections (§14). |
| **Exponential backoff for the gateway's registration**, his decided exception to §3 of the principles | §9 step 6 rewritten: 2 s doubling to 5 min, reset on a success or a wake, one in flight, surfaced as ERROR and offline in Transport. `409 session_superseded` stays terminal, because it answers an exchange and re-registering would evict the newer process. The 60 s exchange back-off stays removed. §6's "stop, show" for the gateway, §13 (gateway logging) and §15 (schedule and reset tests) follow. |
| **Keep peering open** | `accepted_peer_urls`, `transit_identities`, `403 peer_not_accepted` and `403 transit_identity_not_allowed` removed (§4.3 old step 8, §6, §9 step 3, §10.2, §10.4, §11.1, §11.2). Transit by proof alone (§1, §8.1). A4 closed on every row: a seen random blob never creates or replaces a path (§8.5, citing RNS 1.5.2 and 1.1.3). The URL retire in §4.5 is allowed to any signed gateway. The confirm goes to the canonical URL the registration names (§10.5). |
| **Wake-back only between configured relays** | §10.2, §10.8 and §10.9 say a confirmed peer this relay does not configure gets no wake-back and no reconnect. §10.10 gains the one-sided receiver-reset row. Credentials go only to a row's stored canonical URL (§10.2), as d3a0eb5 does live (§0.1). |
| **Newest registration wins** | Already in revision 2 (§6.1). Checked: the gateway's `409 session_superseded` stays terminal (§9.6), and nothing in revision 3 makes a superseded holder register again. |
| **Two enforcement switches** | Already in revision 2. §11.1's config block loses the two lists; the transit switch ends unproven transit, not open peering. |
| **Confirm a gateway's wake URL first** (revision 4) | New §9.8: the relay's confirm (pending record, detached runner, the stored canonical URL only, the signed answer, the CAS) and the gateway's handler (`POST /v1/gateway/confirm`, its checks, the signed bytes, ordering, logging, a changed wake URL). The wake rule in §7.1, §8.1 and §10.2. A15 added to §0. §4.4's UPDATE clears the confirmation when the URL changes; §4.6, §12.1, §12.4 and §12.5 hold the new column, table and `/health` field; §13 the logs; §11.2 requires the handler before Phase 3 and gates on `wake_confirmed`; §11.5 rollback; §14 the `gateway_confirm` vectors (format 4); §15 the tests; §16.1.10 rewritten. |
| **Keep the initiator rule, revisit later** (revision 4) | §10.3 records it; §16.1.12 marks the gap a known limit, to revisit with POST Reticulum hosting. |
| **§8.5's cost: leave it, watch it** (revision 4) | §8.5, §11.2's Phase 1 note and §16.1.13 record it; gravity is the fix if it ever matters. |
| **`[post_interface_peers]` stays open** (revision 4) | §16.2; the live configs are checked before Phase 3c, and §11.2's Phase 3c gate includes it. |
| **A PHP relay peer registers like the gateway** (revision 6, 2026-10-04) | §10 rewritten: §10.1 kept, and gained "Where credentials go"; the identity file (§10.2); who registers and the one-link rule (§10.3); the registration and the PHP client's decrypt (§10.4); exchanges, wakes and the confirm (§10.5); events and backoff without a timer (§10.6); standing down (§10.7); events and recovery tables (§10.8, §10.9). Elsewhere: §0 (A9 to A11, A14), §1 (the PHP relay row; proofs `local` and `retired`, `confirmed` gone), §4.2, §4.3.1, §4.4 (a re-bind sets proof `signed`), §4.6, §5, §6, §6.1, §7.1, §7.2, §8.1, §9 and §9.8 (a PHP relay answers the confirm; "A URL belongs to one identity"), §11 (`register_at_peers`, `identity_path`; Phase 1 gate (d); Phase 3b rewritten; rollback), §12 (client-row columns; the `peer_registration_*` tables dropped; `closed`, `retired`), §13, §14 (format 5), §15 (`peer_link_test.php`), §16. |
| **Keep the session token encrypted** (revision 6) | §5 unchanged. §10.4 specifies the PHP client's decrypt; vectors `php_relay_peer.decrypt` and `decrypt_negative`. |
| **Switch the relay's transport id to its identity's hash, and keep the old id as its own** (revision 7, 2026-10-04, question 1) | §10.2 ("What it does", "One file per relay", "If the file is lost", creation, logging) and the new §10.2.1 (the id the relay writes, the two ids it accepts, how long `P` stays, no identity no transport, when it switches). Elsewhere: §1 (the PHP relay row), §6 (`503 relay_identity_unavailable`), §9 (the analogy with the gateway), §10.9, §11.1, §11.2 (Phase 0; Phase 1 gates (e) and (f)), §11.3, §11.5 (rollback goes back to `P`), §12.1 (`identity_hash_hex` read, never written), §12.5 (`/health`'s `transport_id` and `previous_transport_id`; `P` is database state), §13 (`[RELAY-IDENTITY]`), §14 (`php_relay_peer.transport_id`, format 6), §15 (`transport_id_test.php`, `stage_transport_id_switch`), §16.1.14. |
| **The two-way rule stands** (revision 7, question 2) | §10.3 records the acceptance, and narrows "pending" (A16, below); §10.9, §16.1.12. |
| **A confirmed wake URL belongs to one identity, gateways included** (revision 7, question 3) | §9.8 records the acceptance; a retire also clears `wake_url_proven_key` and deletes the row's confirm record. |
| **Ask the OS whether a runner is gone, never a clock, and start again if it is** (revision 7, question 4) | New §10.10 (the lock handed over at fork, `runner_alive`, the runner directory, what the host must provide, `runner-selftest`, where no clock-free answer exists). §10.5 (the spawn rule without `min_wake_interval_ms`), §10.6 (claims name a runner; a gone runner is a failed attempt; `runner_unavailable`; `GET /v1/initialize`), §10.7 (a gone stand-down runner), §10.8, §10.9, §9.8 steps 2, 3 and 6 (a gone confirm runner frees its record), §0 (A17), §11.2 (Phase 0 and 3b gates), §12.1 (`runner_id`, `exchange_pending_runner`, `gateway_wake_confirms.runner_id`; `last_exchange_*` gone), §12.4, §12.5, §13, §15 (`runner_liveness_test.php` and the dead-runner cases), §16.1.3, §16.1.12, §16.1.15, §16.1.16. |
| **Re-confirm every time** (revision 5) | §4.4: every signed re-bind sets `wake_url_confirmed_key = NULL, wake_outstanding = 0`, so the `CASE` and its `SET`-order note are gone. §9.8: a confirm at every signed registration; the record carries `registration_seq`, and step 5's `UPDATE` matches on it; "What ends wakes to a gateway that stops" and the outstanding-wake rule. §12.1 (two columns), §13, §15, §16.1.10, §16.2. No vector bytes change. |

Revision 3 also had to change these, because the decisions above required
them. James did not decide them, and §16.2 or this list is where to object:

- **Pending bounds (§10.4 step 3).** With any URL able to register, the
  pending records are bounded in all (64), not only per URL (four), since
  each one holds a detached confirm runner.
- **Capacity for peer rows (§10.4 step 4, §12.4).** The accept-list used to
  bound promotions. Now a peer registration that would create a row is
  checked against `max_interface_rows` first.
- **`peer_registration_pending.peer_url` (§12.1).** The confirm can no longer
  take its URL from the config.
- **The initiator rule (§10.3)** is stated so that a relay needs to know only
  its own config. Revision 2's "the only configuring relay initiates" needed
  knowledge a relay does not have. The gap this leaves for one-sided
  peerings is question 2 in §16.2.
- **The gateway's exchange** is not covered by the backoff: only its
  registration is (§9.6).

Revision 4's "Confirm it first" also required these, which James did not
decide:

- **The path** is `/v1/gateway/confirm`, not under `/v1/wake`, because
  today's Rust wake server treats any request containing `POST /v1/wake` as
  a wake.
- **The answer is a signature**, by the transport identity, over
  domain-separated bytes that bind the nonce, the identity, the relay and the
  URL. A nonce sent back would let any server at the URL that echoes request
  bodies confirm itself.
- **The gateway checks** that the confirm is for its own identity, from the
  relay it registers with, and for its own wake URL, so it is not a signing
  oracle.
- **Pending records:** one per gateway row and 64 in all. A newer
  registration replaces the record. A full table leaves the row unconfirmed,
  but the registration still succeeds.
- **A confirmation lasts while the URL is unchanged**: a gateway restart with
  the same URL is not confirmed again. A URL change clears it in the bind's
  UPDATE, with the `SET` order that MySQL's left-to-right evaluation needs.
  *(Superseded by revision 5: James chose "Re-confirm every time".)*
- **No confirm retry.** A failed confirm waits for the gateway's next signed
  registration (§3 of the principles).
- **One wake at confirm time** when packets are queued, so what waited moves
  at once.
- **The gateway's wake listener is bound before its first registration**
  (§5 of the principles).
- **New state:** `interfaces.wake_url_confirmed_key`, the
  `gateway_wake_confirms` table, and `/health`'s `wake_confirmed`.

Revision 5's "Re-confirm every time" also required these, which James did
not decide:

- **The stale-confirm check uses `registration_seq`, not the URL.** With the
  URL unchanged, a previous registration's confirm can land between the new
  bind and the new record, where the `DELETE` by nonce still succeeds. Only
  the seq tells the two registrations apart.
- **One outstanding wake per signed gateway row** (§9.8's wake rule). Asked
  what ends wakes to a gateway that stops altogether: nothing in the row's
  lifetime does. Signed rows are permanent, peer rows get every relayed
  announce whatever their status, pending packets never expire, and
  `dispatchWakes` wakes any peer row with pending packets. The event that
  bounds it is the gateway's own exchange: at most one wake that left between
  two of its exchanges. The cost: a wake that left but was lost delays
  relay-to-gateway traffic until the gateway's next exchange.
- **New state:** `interfaces.wake_outstanding` and
  `gateway_wake_confirms.registration_seq`.

Revision 6's decisions also required these, which James did not decide:

- **The one-link rule for two-way configs** (§10.3). Every relay registers at
  every relay it configures. The later-sorted relay of a pair stands down
  while it holds the earlier relay's registration, confirmed or being
  confirmed. *(James accepted it in revision 7, which narrowed "being
  confirmed", A16.)* It refines the rule proposed with the decision in three
  ways:
  - a pending confirm counts as held, so the earlier relay's re-registration
    (which clears its confirmation) does not make the later relay register
    and stand down again each time;
  - the same rule stops the later relay from registering in the first place,
    not only from keeping a client row, which would otherwise loop
    (register, stand down, register);
  - the stand-down pushes what is queued before its goodbye.
- **A goodbye closes a signed transit row** (status `closed`) until its next
  bind. A transit row ignores `offline`, so without this a stood-down link
  would stay active at the other side.
- **The client row** (§10.4): its `interface_id` derived from its URL key, so
  that concurrent first registrations create it once; `registered_as`, to
  notice a replaced identity file; and the first success retiring this
  relay's own legacy rows for that URL.
- **A URL belongs to one identity** (§9.8). Confirming a URL retires every
  other signed `reticulum-php` row for it, keeping identity and seq. Without
  it, a lost identity file leaves a permanent dead row at every peer. It
  applies to gateways as well. *(James accepted it in revision 7.)*
- **`register_at_peers`**, one mode per relay (§11.1), so the live legacy
  peering moves over in one step with nothing mixed, and rolls back by
  switching it off.
- **The wake handler spawns the exchange** instead of exchanging inline
  (§10.5). This also ends §16.1.6 for signed links.
- **The spawn rule for the client's exchange runner** (§10.5). A spawn is
  skipped only while an earlier runner has been spawned but has not started
  its POST, for at most `min_wake_interval_ms`. This is not a claim, so a dead
  runner cannot wedge the link, and not a plain rate gate either, because
  that would drop a wake that arrives just after a runner finished, leaving
  B's packet waiting for A's next own exchange. Registration, on the other
  hand, is single-flight with a claim, because two concurrent registrations
  of one identity would supersede each other. *(Revision 7 replaced the
  `min_wake_interval_ms` ceiling with §10.10's lock, James's question 4.)*
- **A challenge `404` from a peer is a failure**, not a legacy fallback, while
  `register_at_peers` is on (§10.6). Phase 3b needs both relays on this code.
- **`allow_loopback_http_peers` is removed.** No relay sends credentials to a
  peer's URL any more, and the client's `node_url` scheme is the operator's
  choice (§10.1).
- **`mode` 1** for a PHP relay's registration. The peer fields stay required
  and random, as for the gateway, though nothing presents them.
- **The relay's transport id is unchanged** (§10.2; §16.2, question 1).
  *(Revision 7: James chose to switch it, §10.2.1.)*

Revision 7's decisions also required these, which James did not decide.
§16.2 asks about the first five:

- **The OS check is a lock handed to the runner at fork** (§10.10), not the
  runner's process id that James gave as an example. A process id can be
  reused, telling the runner from a stranger needs `/proc`'s command line,
  which macOS staging lacks, and a nonce the runner writes when it starts
  cannot tell, until it is written, a runner still starting from one that
  died before writing it. The lock has none of these problems and
  needs no extension. It needs `proc_open`, `/bin/sh`, and a runner
  directory on local disk, which `runner-selftest` checks. There is no
  fallback, and §10.10 says where no clock-free answer exists.
- **A gone registration runner is a failed attempt under the backoff**
  (§10.6), so the restart James asked for comes at the first ingest request
  after the delay (2 s after a first death), or at once on a wake. Starting
  again in the very request that found it gone would restart a runner that
  dies the same way every time at the rate requests arrive.
- **"Pending" counts only for an identity that has proven the URL** (§10.3,
  A16), with the new column `wake_url_proven_key`, set by §9.8 step 5, kept
  by a re-bind, cleared by a retire. Revision 6's rule counted any pending
  confirm, and anyone can register a row naming a peer's URL.
- **A gone stand-down runner completes the stand-down without it** (§10.7):
  the row is deleted, what it still held is dropped and counted, and no
  goodbye is sent. Running it again would retry an exchange and a goodbye.
- **No identity, no transport** (§10.2.1): `503 relay_identity_unavailable`
  on every ingest endpoint, never an id made up or the pre-switch id used
  alone. The identity file's directory is created if missing, since a
  missing directory would now stop the relay.
- **The same principle for the confirm runner** (§9.8). Revision 6 never
  freed the record of a confirm runner that died, which counted toward the
  64 and as "pending" in §10.3 (A17). A gone confirm runner is a failed
  confirm and is not started again (§3 of the principles).
- **An exchange runner gives up its lock file once it has started** (§10.5),
  because nothing checks it after that, so one that dies mid-exchange
  leaves no file behind.
- **When the transport id switches: Phase 1**, with the code, and no switch
  in the config (§11.2). Accepting `P` makes it invisible to every
  neighbour, so it needs no step of its own. Phase 1 gains gates (e) and (f).
- **`P` is `transport_state.identity_hash_hex` itself**, read and never
  written, rather than a copy under a new key. A rollback to bae739a finds
  it where old code left it, and a DB reset forgets it with everything else.
- **`[RELAY-IDENTITY] loaded` is gone.** Each PHP request is its own
  process, and every ingest request now loads the identity, so it would log
  a line per request. `/health` shows the hash as `transport_id`.
- **The legacy wake runners are left as they are** (§16.1.15): they go with
  the legacy code after Phase 3c.
