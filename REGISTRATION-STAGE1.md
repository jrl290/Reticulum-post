# Stage 1: browsers sign their registration

> Read [`../DESIGN_PRINCIPLES.md`](../DESIGN_PRINCIPLES.md) first. Every rule
> below follows it: events, not timers; no retries; no timeouts as a fix;
> strict ordering; §1's 5 seconds.

**Status:** specification, 2026-10-05. Not built. James chose on 2026-10-05
to ship signed registration in stages, each with its own spec, build, staging
run and deploy ("Stages, browsers first (Recommended)", §18). This is Stage 1:
the browser signs its registration with its own identity key, the takeover
fix he chose on 2026-10-02. [`REGISTRATION.md`](REGISTRATION.md) (revision
10) is the full design and the roadmap for Stage 2 (gateways) and Stage 3
(PHP node to PHP node peering); for browsers, where the two differ, this file
holds.

**Normative for** Reticulum-post (the PHP node) and Retichat-js (the browser:
`lib/rns/interfaces/post_interface.js`, `lib/connect_policy.js`, and what
`app.js` shows). **Vectors:**
[`php/tests/vectors/registration_vectors.json`](php/tests/vectors/registration_vectors.json),
format 6, unchanged (§17). MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

## 1. Glossary

### 1.1 James's words

| Word | Meaning |
|---|---|
| **PHP node** | A Reticulum-post installation. It runs only while it handles an HTTP request: no listening port, no background process apart from the hourly storage reclaim. |
| **Browser** | Retichat-js, the web client. |
| **Gateway** | The PostInterface of a Reticulum-rust or Python rnsd, joining an RNS network to a PHP node. The live one runs on James's NAS. |
| **Challenge** | The PHP node hands out a one-time code, which a signed registration must sign (§3). |
| **Register** | The browser proves its identity with a signature and receives a session (§4, §5). |
| **Exchange**, **Poll** | One POST that moves packets both ways; exchanges on a beat (§6). |
| **Wake** | The PHP node tells a gateway or another PHP node "come and get them". Browsers are never woken. |
| **Goodbye** | The browser tells the PHP node it is leaving (§6). |
| **Session lost** | The PHP node does not know the session and answers `401`; the browser registers again (§7). |
| **Superseded** | A newer registration of the same identity replaced this session; the PHP node answers `409` and the browser stops (§8). |
| **Address check** | Proof that the web address a gateway or PHP node gives for its wakes belongs to its identity: Stage 2. Browsers are never woken. |

### 1.2 Other words this file uses

| Word | Meaning |
|---|---|
| **Identity** | An RNS identity: an X25519 and an Ed25519 key pair. Its **public key** is 64 bytes, X25519 then Ed25519; its **identity hash** `H` is `SHA-256(public key)[:16]` (RNS 1.5.2 `Identity.hash`), so `H` proves itself. |
| **Row** | The PHP node's record of one registration, in its `interfaces` table. A **browser row** is a row whose `client` is `rns-js`. |
| **Session** | The interface id and session token a browser receives when it registers and presents on every exchange and goodbye. |
| **Signed row** | A row made by a verified signed registration. It holds `H`, the public key and the registration count. |
| **Registration count** | `registration_seq`: how many signed registrations the row has had; 0 when there is no signed row. Each success adds one; it never goes back. |
| **Legacy registration**, **legacy row** | Today's unsigned registration, and a row it makes. |
| **Claim** | The identity hash a legacy browser registration names in `metadata.identity_hash`. Nothing proves it. |
| **Binding** | A `local_destinations` entry: the PHP node delivers a destination's packets on that row. Only browser rows make bindings, from their own announces. |
| **Node secret** | The PHP node's key for its challenges (§3). |
| **Enforcement switch** | `[registration] enforce_signed_registration`. Off, the default: the PHP node **accepts both** signed and legacy browser registrations. On: signed only (§13). |
| **Transit mode** | RNS interface mode 3 (access point), 5 (boundary) or 6 (gateway), in which an interface carries other nodes' traffic. |
| **Peering** | How retichat.com and selectiv carry each other's traffic: each registers at the other the legacy way, and wakes it. |
| **The two hosts** | retichat.com (**production**, MySQL 8.4) and selectivesubconscious.com, **selectiv** (James's staging server, MariaDB 11.4), one PHP node each on cPanel shared hosting. |
| **Private staging** | `staging.sh` with `STAGING_PHP=local` on James's Mac: a PHP node under `php -S` on 127.0.0.1, the local gateway, harness browsers. Never either host. |
| **Phase 0 to 3** | The steps of Stage 1's rollout (§13), not REGISTRATION.md's phases. |
| **Stale sweep** | Today's housekeeping that marks a row offline when nothing was heard from it for `interface_stale_after_seconds` (15 s on selectiv, 300 s on retichat.com), then removes its bindings and paths. |
| **A1 to A15** | Attacks, by REGISTRATION.md §19's labels; §16 says what Stage 1 closes. |

Names in `code` are literal (columns, config keys, error codes, functions).
Tags in square brackets are log lines (§11). The vector file keeps an older
word: its `relay` means PHP node.

## 2. What Stage 1 changes, and what it leaves as today

**Changes.**

1. **The browser signs.** It fetches a challenge, signs its registration with
   its identity key, and gets its session token back encrypted to that key.
   The PHP node derives `H` from the public key, checks the challenge and the
   signature, and binds the row by `H`, spending the count (§3 to §5).
2. **Legacy rows claiming that identity are removed, never adopted** (§4.5).
3. **Newest wins.** A registration that replaces a session makes the older
   token earn `409` Superseded, and the older browser stops and says why (§8).
   `401` means only Session lost (§7).
4. **A browser row carries only its own identity's announces, and never a
   transit mode** (§4.3, §4.6, §9).
5. **The enforcement switch** ends legacy browser registrations on a date
   James sets (§13). Schema, logging and `/health` follow (§11, §12).

**Left as today.**

- **Gateways** register unsigned (`reticulum-php` in wake mode,
  `rns-post-interface` in poll mode), are found by their exact `peer_url`,
  and are woken and exchange as today; a signed registration from anything
  but a browser gets `400 unknown_client` (§4.3). Stage 2.
- **Peering** (`connectToPeer`, the exchange inside the `/v1/wake` handler,
  the hourly repair of a dead session): Stage 3. **Paths and announces** on
  rows that are not browser rows (REGISTRATION.md §12.5): Stage 2.
- **Calls to other hosts.** Stage 1 adds no outbound call and moves none, so
  whether the PHP node's other calls run before or after the answer
  (REGISTRATION.md open question 20) does not arise.
- **Exchange, Poll, Goodbye**, the stale sweep, maintenance, the storage
  reclaim, the random transport id (Stage 3), and unbounded rows (§16 item 5).
- **The browser's** one connected tab per identity (`ActiveTab`), its goodbye
  beacon, and its wait of 5 s before it tries again after a network failure
  or a 5xx. That wait is a retry in the sense of the principles' §3;
  REGISTRATION.md open question 17.3 asks whether it stays.
- **The live peer-repair bug** (`Storage` calls `$this->log()`, which only
  `HttpApi` has, `request_php_wake_trait.php:704`) is fixed on its own
  (James, 2026-10-05: "Fix and deploy (Recommended)").

## 3. Challenge

```
POST /v1/interfaces/challenge          {"public_key": "<128 hex>"}
POST /v1/interfaces/challenge          {"identity_hash": "<32 hex>"}
GET  /v1/interfaces/challenge?public_key=<128 hex>
GET  /v1/interfaces/challenge?identity_hash=<32 hex>

200 {"status": "challenge", "version": 1, "identity_hash": "<32 hex>", "challenge": "<96 hex>"}
```

Exactly one of `public_key` or `identity_hash`, in lower-case hex; anything
else, an extra key included, gets `400 bad_challenge_request`. The browser
POSTs its public key; GET is for operators. Both carry
`Cache-Control: no-store`, since a cached challenge would turn into two
`409`s. The answer says nothing about the row: not its count, not whether it
exists. A PHP node without Stage 1 answers `404`, the only status on which a
browser registers the legacy way (§10).

```
H          = the identity hash (16 bytes), from public_key or as given
count      = registration_seq of the row whose identity_hash = H, or 0 if there is none
nonce      = 16 random bytes (CSPRNG)
mac        = HMAC-SHA256(node_secret, "reticulum-post/challenge/v1" || H || u64be(count) || nonce)
challenge  = nonce(16) || mac(32)
```

The domain is those 27 ASCII bytes; every other part has a fixed width;
`u64be` is unsigned 64-bit big-endian. The count is bound into the MAC but
never sent. The challenge is **stateless**: no table of codes, no expiry, no
sweep.

**The node secret** is 32 random bytes, made on first use and kept as hex in
`transport_state` under `registration_challenge_secret_hex` (INSERT-or-ignore,
then SELECT, so concurrent first requests agree); checking a challenge never
creates it. It never appears in `/health`, `/debug`, the monitor, a log line
or an answer. A database reset rotates it (`clearAllData()` empties
`transport_state`), and every outstanding challenge dies with it.

**Single use.** A successful signed registration moves the row from `count`
to `count + 1` (§4.4), so every challenge bound to the old count fails for
good: a captured body works at most once, and its replayer cannot decrypt the
token (§5). That holds while the count never goes back (§12). A challenge
never used stays valid until the count moves or the secret rotates; using it
needs the private key.

## 4. Register

### 4.1 The request

```json
POST /v1/interfaces/register
{"name": "Retichat Web", "bitrate": 1000000, "mtu": 500,
 "metadata": {"client": "rns-js", "implementation": "PostInterface", "mode": 1},
 "registration": {"version": 1, "public_key": "<128 hex>",
                  "challenge": "<96 hex, verbatim from §3>", "signature": "<128 hex>"}}
```

A body with `registration` takes the signed path; any other is a legacy
registration (§4.6). `registration` holds exactly those four keys, `version`
1 (revision 2's `audience` is a fifth key: `400 bad_registration`). The
metadata may hold only the signed keys (`client`, `mode`, `transport`,
`peer_url`, `peer_interface_id`, `peer_session_token`), `implementation` (at
most 64 bytes, never acted on) and `identity_hash` (if present it MUST equal
`H`; never stored). Any other key gets `400 unsigned_metadata`: the PHP node
never acts on a value the signature does not cover.

### 4.2 Signed bytes

```
lp(x)  = u16be(len(x)) || x

signed = lp("reticulum-post/register/v1")          -- 26 bytes
      || lp(challenge)                             -- 48 bytes, exactly as received
      || lp(public_key)                            -- 64 bytes
      || lp(utf8(name))
      || lp(u64be(bitrate))
      || lp(u32be(mtu))
      || lp(utf8(metadata.client))
      || lp(u8(metadata.mode))
      || lp(utf8(metadata.transport          or ""))
      || lp(utf8(metadata.peer_url           or ""))
      || lp(utf8(metadata.peer_interface_id  or ""))
      || lp(utf8(metadata.peer_session_token or ""))

signature = Ed25519-sign(ed25519 private key, signed)   -- RNS Identity.sign, 64 bytes
```

REGISTRATION.md's one layout for every client, so Stage 2 changes no byte;
a browser signs the last four fields as empty (`0000` each). No JSON is
signed; values are read from the decoded body before any normalisation. No
address of the PHP node is signed (James: "Don't we have ssl to prevent
spoofing?"; §16 item 6). Worked example: REGISTRATION.md §4.3.1, vector
`browser-first`. The browser builds these bytes in one function,
`signRegistration()`, and signs nothing received apart from the challenge in
its field; no RNS signature can begin with them, since each starts with a
16- or 32-byte hash or key.

### 4.3 Checks, in order

Cheapest first. Nothing is written before step 8.

| Step | Check | On failure |
|---|---|---|
| 1 | Shape: the `registration` object (§4.1); `name` a non-empty JSON string of valid Unicode, at most 255 bytes as UTF-8; `bitrate` and `mtu` JSON integers from 1 to 2^31 − 1 (what today's `INT` columns hold); `mode` a JSON integer from 1 to 7; `client` a non-empty string of at most 64 bytes; `challenge`, `public_key`, `signature` lower-case hex of 96, 128, 128 characters. Strings, booleans and floats such as `1e6` are refused. | `400 bad_registration` |
| 2 | Metadata keys within §4.1's set | `400 unsigned_metadata` |
| 3 | `H = SHA-256(public_key)[:16]`; `metadata.identity_hash`, if present, equals `H` | `400 identity_hash_mismatch` |
| 4 | `client` is `rns-js`; then `mode` is 1, 2, 4 or 7, not a transit mode; then `transport` and the three `peer_*` fields are empty (absent, `null` or `""`) | `400 unknown_client`, then `transit_mode_not_allowed`, then `metadata_not_allowed` |
| 5 | Read the row with `identity_hash = H` (its count, or 0); recompute the MAC over `H`, that count and the challenge's nonce; compare in constant time | `409 stale_challenge` |
| 6 | `sodium_crypto_sign_verify_detached(signature, signed, public_key[32:64])`, over bytes rebuilt from the received body | `403 bad_registration_signature` |
| 7 | A fresh session token, encrypted to `public_key[0:32]` (§5); an all-zero X25519 result (a low-order key) fails | `400 bad_registration` |
| 8 | The bind (§4.4) | `409 stale_challenge` |

Step 5 fails alike for a challenge issued before the count moved, by another
PHP node, for another identity, under a rotated secret, or altered.

**One more round after `409 stale_challenge`**, for another registration of
the identity, or a database reset, landing between challenge and
registration: the browser fetches ONE new challenge and registers ONCE more;
a second `409` is terminal (§10). A protocol step with a fixed bound of one,
as in digest authentication, not a retry loop.

### 4.4 The bind

The row is found only by `identity_hash = :h`: its own column, UNIQUE,
lower-case hex only, so no collation folds two values together.

- **Count 0 (no signed row): INSERT** a row with a fresh `interface_id` (16
  random bytes, hex), status `online`, `identity_hash = H`, the public key,
  `registration_seq = 1` and `registration_proof = 'signed'`. A unique-key
  conflict means another registration of `H` won: `409 stale_challenge`,
  never a second INSERT.
- **Count n > 0: UPDATE in place**, with the count step 5 read;
  `rowCount() = 1` is required, otherwise `409 stale_challenge`.
  `:old_token_sha256` is the SHA-256 hex of the token the row held when step 5
  read it (§8). The statement always changes `registration_seq` and
  `session_token`, so MySQL's affected rows equal its matched rows.

  ```sql
  UPDATE interfaces
     SET previous_session_token_hash = :old_token_sha256, session_token = :token,
         name = :name, bitrate = :bitrate, mtu = :mtu, status = 'online',
         metadata_json = :metadata_json, last_seen_at = :last_seen_at,
         updated_at = :updated_at, registration_seq = :next_count
   WHERE identity_hash = :h AND registration_seq = :count AND identity_public_key = :pub
  ```

The row keeps its `interface_id`, so its queue, paths and bindings survive a
reload; `metadata_json` holds only `client`, `implementation` and `mode`. No
placeholder appears twice. Every write goes through
`Database::executeWithRetry`, today's floor against deadlocks; Stage 1 opens
no transaction.

### 4.5 Legacy rows claiming the identity are removed, never adopted

A legacy claim lives in `claimed_identity_hash`, never in `identity_hash`
(§4.6), so a signed registration never lands on a legacy row. After every
successful bind for `H` (the INSERT, and the UPDATE too, which catches a
legacy row that raced in), the PHP node removes every row with
`claimed_identity_hash = H` and `registration_proof = 'none'`: first its
traffic, each step a statement on an index (§12), then the row:

1. its bindings (`local_destinations`);
2. the `path_entries` through it; the `reverse_path_entries` and
   `link_transport_entries` received on it, then those sent out on it (one
   `DELETE` per column);
3. its `outbound_packets`, selected by `interface_id` and deleted by primary
   key in ascending order, then its `outbound_batches`.

Nothing passes to the signed row: those packets were queued to a row whose
owner was never proven (A7). Logged `[REG-RETIRE] identity=<H> rows=<n>
dropped=<m>` when `n ≥ 1`; with no such row it costs one indexed SELECT. A
database error here answers `500` after the bind, and the next registration
removes the rows. Whoever held a removed row gets `401`; an old page then
registers the legacy way and gets `403 identity_requires_signature`.

### 4.6 Legacy registration while the switch is off

A body without `registration` whose `client` is `rns-js`, in order:

1. Mode 3, 5 or 6: `400 transit_mode_not_allowed` (accepted today).
2. The switch on: `403 signature_required`.
3. The claim is `metadata.identity_hash` when it is 32 lower-case hex; a
   malformed claim is no claim, logged `[REG-BAD-IDENTITY]` as today.
4. A signed row has `identity_hash = claim`: `403 identity_requires_signature`.
5. A legacy row has `claimed_identity_hash = claim` (the most recently seen,
   if a rollback left several): re-bind it in place as today, with a new
   plaintext token, and set `previous_session_token_hash` to the old token's
   hash, so the older session earns `409` (§8). Otherwise INSERT a legacy row
   with `claimed_identity_hash = claim`.
6. Store neither `metadata.identity_hash` nor `metadata.wake_url` (the latter
   logged `[REG-WAKE-URL-IGNORED]`, as today); log `[REG-LEGACY]`.

The answer is today's, with a plaintext `session_token`. The `LIKE` lookup on
`metadata_json` (`interfaceByIdentityHash`) is deleted; a claim is found only
by `claimed_identity_hash = :claim`, and only browser rows carry one. So
another `client`'s legacy registration can no longer re-bind a browser row by
naming its identity hash (A8): the hash is ignored and logged
`[REG-CLAIM-IGNORED]`, and the rest runs as today (a `reticulum-php` row
re-bound by its exact `peer_url`, anything else a new row). Gateways send no
`identity_hash`.

## 5. The answer and its encrypted token

A signed registration is answered only like this; it MUST NOT contain
`session_token` or `registration_seq`:

```
200 {"status": "registered", "interface_id": "<32 hex>", "identity_hash": "<H, 32 hex>",
     "session_token_encrypted": "<hex>", "idle_exchange_interval_ms": 1000,
     "max_batch_packets": 64, "max_packet_bytes": 500}
```

The session token is a fresh `bin2hex(random_bytes(32))`, as today, sent only
as RNS `Identity.encrypt(utf8(token))` to the browser's public key, with no
ratchet (the derivation `request_lxmf_handoff_trait.php` already uses):

```
eph       = a fresh X25519 key pair
shared    = X25519(eph_private, public_key[0:32])        -- all zeros: §4.3 step 7
derived   = HKDF-SHA256(ikm = shared, salt = H, info = "", L = 64)
hmac_key  = derived[0:32]        aes_key = derived[32:64]
iv        = 16 random bytes
ct        = AES-256-CBC(aes_key, iv, PKCS7(utf8(token)))
blob      = eph_public(32) || iv(16) || ct || HMAC-SHA256(hmac_key, iv || ct)(32)   -- 160 bytes
```

**The browser** decrypts with its identity (`Identity.decrypt`,
`lib/rns/identity.js`). The plaintext MUST be 64 lower-case hex and the
answer's `identity_hash` its own; otherwise, an HMAC failure included, it
stops and says so (§10), and never looks for a plaintext token. James, asked
whether to keep the encryption given HTTPS and single-use challenges: "Keep
it" (§18). It makes a replayed or forwarded body worthless (§16 item 6).

## 6. Exchange, Poll and Goodbye

Unchanged: `POST /v1/interfaces/exchange` (and `/tx`, and `/poll` for
poll-mode gateways) with today's fields and delivery batches, every
`idle_exchange_interval_ms` and at once when the browser has something to
send; and on `pagehide` the goodbye beacon, `POST /v1/interfaces/goodbye
{"interface_id", "session_token"}`, after which the row is offline and its
bindings and paths are gone. Only the check of the session changes (§7, §8):
a goodbye with a superseded token gets `409` and changes nothing, so a
closing old tab never takes the newer session's bindings.

**The browser's §1 assertions.** Every challenge, register and exchange is a
network send under §1 of the principles: the browser times each POST to its
answer, and an answer later than 5 s is logged as a §1 violation
(`console.error`, the line carrying `// NEVER REMOVE EVER — see
DESIGN_PRINCIPLES.md §1`) and still decides. Today none is asserted. A failed
exchange is not made again because it failed; its packets are reported lost.

## 7. Session lost (401)

`authenticateInterface(id, token)`, on `/exchange`, `/tx`, `/poll` and
`/goodbye`, answers in this order:

1. no row `id`: **`401`**;
2. a legacy browser row while the switch is on: **`401`**, whatever the token;
3. `token` equals the row's `session_token` (`hash_equals`): success, as
   today. A legacy browser row with no claim yet (written by old code after a
   rollback) gets `claimed_identity_hash` from its metadata here;
4. `SHA-256(token)` equals the row's `previous_session_token_hash`: **`409
   session_superseded`** (§8);
5. anything else: **`401`**.

`401 {"error":"unauthorized"}` comes only from these steps; register and
challenge never answer `401` or `session_superseded`. **The browser**, on
`401`, registers again (challenge, then register) at once, once per run, and
reports that exchange's packets lost, as today. It acts on the status and
code alone; today's match on the text "Invalid interface credentials" goes.

## 8. Superseded (409)

The PHP node writes `previous_session_token_hash` exactly when a registration
replaces the token of the same row: a signed re-bind (§4.4) and a legacy
browser re-bind (§4.6). Nothing else writes it: not a goodbye, and not a
gateway's or PHP node's legacy re-bind, whose replaced token keeps today's
`401`. So a token earns `409` only from a newer registration of its own row.
Newest wins (James: "Newest wins (Recommended)").

```
409 {"error": "session_superseded",
     "message": "This identity connected from another tab or device. Reload to connect here."}
```

**The browser** stops: no exchange, no registration, no 5 s wait; its held
packets are reported lost; the message is shown under its status dot. A
reload or an explicit reconnect registers again, and the other side then gets
the message. An old page (Retichat-js 90640bf) does not know `409`: it tries
the exchange again every 5 s with the same token, never registering, so it
evicts nobody, and shows only the red dot. Today two holders of one identity
evict each other with every `401`.

`[SESSION-SUPERSEDED] interface=<id8>` is logged at most once per row per
token: the row keeps the last logged token's hash (`superseded_logged_hash`),
set by a compare-and-swap on its own `interface_id`, never the request's
string, which a case-folding collation matches in several spellings.

## 9. The browser-row announce rule

It applies to every announce received on a browser row, path responses
included, in every mode, signed or legacy. It runs inside
`processAcceptedAnnounce`, right after `AnnounceValidator::validate` and
before `rememberKnownDestination`, the binding, the path update, announce
caching and forwarding, so both of its callers get it.

```
I        = SHA-256(the announce's public key)[:16]
owner(R) = R.identity_hash             if R is a signed row
         = R.claimed_identity_hash     if R is a legacy browser row, the switch is off,
                                          and no row has identity_hash = R.claimed_identity_hash
         = none                        otherwise
accept   ⇔ owner(R) ≠ none, I = owner(R), and, for a legacy row, the announce is neither seen nor held
```

- **Seen:** its random blob is already recorded for that destination
  (`path_entries.random_blobs_json`), or its packet hash is the one
  `known_destinations` remembers for it: a replay. No timer is involved.
- **Held:** another row already holds the destination: a binding on another
  row, or a usable path entry through another row.

An announce not accepted is dropped whole: no remembered key, ratchet or
`app_data`, no binding, no path update, no announce cache, no forwarding (its
`inbound_packets` history row says refused, and nothing serves it). Logged
`[ANNOUNCE-FOREIGN] interface=<id8> dest=<hash> identity=<8 hex>
owner=<8 hex|none>` or `[ANNOUNCE-LEGACY-REFUSED] interface=<id8>
dest=<hash> reason=<seen|held>`. `owner(R)` is read as the announce arrives,
so a legacy row loses its claim the moment its identity signs here.

Nothing legitimate breaks: the browser announces only its own identity's
destinations (`lxmf.delivery`, `rfed.delivery`); a distro's announce goes to
RFed inside an RNS link request and reaches the PHP node through the gateway.
Today's move of a binding between browser rows then only happens between rows
of one owner, as at a reload. The rule runs in every mode, so an old legacy
row with a transit mode is covered. Other rows follow today's rules. What
"held" costs is open question 2; a signed row is never subject to it.

## 10. Errors

Every 4xx and 5xx body that carries an `error` is `{"error": "<code>",
"message": "<one line for a person>"}`. The browser acts on status and code.

| Status | `error` | Raised when | The browser |
|---|---|---|---|
| 400 | `bad_challenge_request` | a challenge request without exactly one well-formed key or hash | stops, says why |
| 400 | `bad_registration` | a malformed `registration` object or signed field; a key that cannot receive a token | stops, says why |
| 400 | `unsigned_metadata` | a metadata key outside §4.1's set | stops, says why |
| 400 | `identity_hash_mismatch` | `metadata.identity_hash` ≠ `H` | stops, says why |
| 400 | `unknown_client` | a signed registration whose `client` is not `rns-js` | stops, says why |
| 400 | `transit_mode_not_allowed` | `rns-js` in mode 3, 5 or 6, signed or legacy | stops, says why |
| 400 | `metadata_not_allowed` | a signed `rns-js` registration with `transport` or a `peer_*` field | stops, says why |
| 403 | `bad_registration_signature` | the signature does not verify | stops, says why |
| 403 | `identity_requires_signature` | a legacy registration claiming an identity that has signed here | stops, says "reload this page" |
| 403 | `signature_required` | a legacy browser registration while the switch is on | stops, says "reload this page" |
| 409 | `stale_challenge` | the challenge does not verify against this PHP node, identity and count; or the bind race was lost | ONE new challenge, ONE more registration; a second `409` stops, says why |
| 401 | `unauthorized` | `/exchange`, `/tx`, `/poll`, `/goodbye`: §7 | registers again |
| 409 | `session_superseded` | the same endpoints: the token is the row's previous one | stops with §8's message |
| 404 | (any) | the challenge, at a PHP node without Stage 1 | registers the legacy way |

**"Stops, says why":** no further automatic registration, and no 5 s wait;
the reason reaches the page through the interface's `down` event and is shown
as text under the status dot, where a blocked exchange is shown today; a
reload or an explicit reconnect starts again. The browser also stops, saying
why, on a token that does not decrypt or another `identity_hash` (§5), and
when its page gave it no signing identity (an `app.js` older than Stage 1):
it then asks the challenge by `identity_hash`, registers the legacy way only
on `404`, and otherwise stops: "This page is out of date. Reload it to
connect."

A network failure or a 5xx is no protocol answer and keeps today's handling:
the attempt's packets are reported lost, and the next attempt comes after the
5 s wait, or at once on an `online` or `visible` event. Any other 4xx is
handled as today on an exchange, and stops, says why, on the challenge or the
registration. Old pages know none of these codes (§8).

## 11. Logging

Stage 1's lines go through `error_log()`, as today's `[REG-BAD-IDENTITY]` and
`[WAKE-DROP]` do, into PHP's error log beside `index.php`. REGISTRATION.md
§15's single logger is not part of Stage 1, and no gate reads a log.

| Tag | When |
|---|---|
| `[REG-SIGNED] identity=<H> interface=<id8> <created\|rebound>` | a signed registration bound |
| `[REG-REFUSED] <status> <error> client=<c> [identity=<H>]` | every 4xx and 5xx of challenge and register |
| `[REG-LEGACY] client=rns-js action=<created\|rebound> interface=<id8>` | a legacy browser registration accepted |
| `[REG-RETIRE] identity=<H> rows=<n> dropped=<m>` | §4.5 removed legacy rows |
| `[REG-CLAIM-IGNORED] client=<c>` | another client's legacy registration carried `identity_hash` |
| `[REG-BAD-IDENTITY]`, `[REG-WAKE-URL-IGNORED]` | as today |
| `[SESSION-SUPERSEDED] interface=<id8>` | §8, once per row per token |
| `[ANNOUNCE-FOREIGN]`, `[ANNOUNCE-LEGACY-REFUSED]` | §9 |

Logs MUST NOT contain session tokens, signatures, challenges or the node
secret; they give identity hashes in full and interface ids as 8 hex. Since
these lines say who registered here and when, the log file MUST NOT be served
over HTTP (§13, before Phase 1).

## 12. Schema and `/health`

Added in `request_schema_trait.php`; its fingerprint changes, so
`migrateIfNeeded()` runs the migration once on each node. All additive; none
of REGISTRATION.md §14.1's other objects exists in Stage 1.

| Object | Definition |
|---|---|
| `interfaces.identity_hash` | `VARCHAR(32) DEFAULT NULL`, with `CREATE UNIQUE INDEX idx_interfaces_identity_hash ON interfaces (identity_hash)` (several NULLs are allowed on MySQL 8.4, MariaDB 11.4 and SQLite) |
| `interfaces.identity_public_key` | `VARCHAR(128) DEFAULT NULL` |
| `interfaces.registration_seq` | `BIGINT NOT NULL DEFAULT 0`: the count |
| `interfaces.registration_proof` | `VARCHAR(16) NOT NULL DEFAULT 'none'`: `none` or `signed` |
| `interfaces.claimed_identity_hash` | `VARCHAR(32) DEFAULT NULL`, with `idx_interfaces_claimed_identity` |
| `interfaces.previous_session_token_hash` | `VARCHAR(64) DEFAULT NULL` (§8) |
| `interfaces.superseded_logged_hash` | `VARCHAR(64) NOT NULL DEFAULT ''` (§8) |
| indexes for §4.5 | `idx_outbound_packets_iface ON outbound_packets (interface_id, acked_at)`, `idx_path_entries_iface ON path_entries (interface_id)`, `idx_reverse_path_received ON reverse_path_entries (received_interface_id)`, `idx_link_transport_received ON link_transport_entries (received_interface_id)`, `idx_link_transport_outbound ON link_transport_entries (outbound_interface_id)`. Without them each removal scans whole tables, and Phase 2 makes one removal per user. `local_destinations` and `outbound_batches` are already indexed by `interface_id`. |
| `transport_state` row | `registration_challenge_secret_hex` (§3) |

**Backfill**, in PHP at every migration, idempotent, with no `LIKE`:
`claimed_identity_hash` for legacy `rns-js` rows, from a top-level
`metadata.identity_hash` of 32 lower-case hex; the key leaves `metadata_json`
at the row's next write. **Lookups never compare free text:** under
MySQL's and MariaDB's `utf8mb4_unicode_ci`, `é = e` (SQLite compares bytes),
so every lookup Stage 1 adds uses lower-case hex checked by shape, and a
static test keeps any SQL from comparing `metadata_json` with request values.

**Operator rules** (the README gains them):

- **The count never goes back.** A signed row is deleted only together with a
  rotation of the node secret, in the same session:
  `DELETE FROM transport_state WHERE state_key = 'registration_challenge_secret_hex'`.
  Otherwise its count would restart at 0, and a body already used at a low
  count would work once more. `clearAllData()` does both.
- **`monitor.php`'s clear MUST stop at the first failed `DELETE`**, so it
  never empties `interfaces` while `transport_state` survives. Today it goes
  on (it answers only where `[debug] enabled` is set).
- **SQL:** every value bound; no backslash in a SQL string literal; no named
  placeholder twice in one statement (MySQL's native prepares fail with HY093
  where SQLite accepts it: the 2026-09-23 outage); every statement runs on
  SQLite, MySQL 8.4 (open question 3) and MariaDB 11.4 (selectiv, Phase 1).

**`/health`** is public, and its fields are an allowlist
(`health_allowlist_test.php`). Stage 1 adds one object, and lists no identity
hash, token, key or browser row:

```
"registration": {"version": 1, "schema_migrated": true, "enforce_signed_registration": false,
                 "browsers_online": {"signed": 0, "legacy": 0}}
```

`version` 1 says the node runs Stage 1. `schema_migrated` is true exactly
when `schema_meta`'s `migration` fingerprint equals this code's (the SHA-1 of
the deployed `request_schema_trait.php`), so it reads false after a failed
migration, when the old fingerprint is still recorded and every request
re-runs the migration. `enforce_signed_registration` is the switch as
loaded; `browsers_online` counts online signed rows, and online legacy rows
with a claim.

## 13. Rollout

```toml
[registration]
enforce_signed_registration = false   # browsers only. James turns it on, on a date he sets.
```

It is read like the node's other switches (`Config::configBoolOrDefault`:
`false`, `no`, `off`, `0` or empty is off, and anything else on), and
`/health` shows what the node loaded; off takes effect at once. It is turned
on by James's date and positive evidence (Phase 3), never by `[REG-LEGACY]`
going quiet: anyone can keep that line busy.

Every gate is checkable from outside, with no credentials: `/health`,
`verify-live-stamp.sh` (Reticulum-post), Retichat-js's `verify-deploy.sh`,
`curl`, a browser, and `tools/stage1_probe.py` (§17.3), which registers test
identities of its own and checks every answer. Each phase also passes the
existing deploy gates (a green suite, staging, lint, a rollback copy, a swap
in one step, verification, the stamp; Retichat-js's boot gate and CSP check).

**Phase 0: private staging**, on James's Mac only: the PHP suite on SQLite
and, as open question 3 decides, MySQL 8.4; Retichat-js's full suite; then
`staging.sh` with `STAGING_PHP=local` and the local gateway registering the
legacy way, running §14's stages, the existing ones (`stage_browser.mjs`, 3
to 7, `stage_large.mjs`) and `tools/stage1_probe.py http://127.0.0.1:8080`.

**Before Phase 1, on each host:** `https://<host>/reticulum/error_log` and
`…/reticulum/var/router.log` must not answer `200` to `curl` (a `200` means
the file is served, which leaks today's lines already; Stage 1 waits on that
host until James makes it refuse them). For retichat.com, the MySQL 8.4 run
of open question 3 must have passed; until then Stage 1 goes to selectiv
only. Optional, with James's database access: `SELECT COUNT(*)` of the tables
§12 indexes, to size the index builds the first request makes.

**Phase 1: the PHP node, accepting both.** `./deploy.sh <ref> selectiv`,
then, after the MySQL proof, retichat.com; the switch stays off. Gates on each
node: (a) `./verify-live-stamp.sh <ref> <node>` passes; (b) `/health` shows
`registration.version: 1`, `schema_migrated: true` and
`enforce_signed_registration: false` (`schema_migrated: false` means every
request re-runs the migration, the 2026-09-24 load: roll back at once); (c)
`tools/stage1_probe.py https://<host>/reticulum` passes; (d) nothing else
moved: in `/health` the gateway's and the other PHP node's rows keep
advancing `last_seen_at`, `rx_packets` and `tx_packets`, and the site's live
page (still 90640bf) loads and turns green.

**Phase 2: the browser signs.** Retichat-js to a site the same day its PHP
node passed Phase 1, so that legacy tabs, and §9's cost, last hours, not
days: selectiv as open question 1 allows, retichat.com after its node. Gates
on each site: (a) Retichat-js's `./verify-deploy.sh <ref> <site>` passes byte
for byte, on selectiv again hours later, where a foreign `app.js` has replaced
verified deploys before; (b) a fresh load registers signed and turns green,
and `/health` shows `browsers_online.signed` of at least 1; (c) the same
identity opened in a second browser profile makes the first page show §8's
message and stop. **What it costs**, once per identity per PHP node: the first
signed registration makes a new row and removes the legacy one (§4.5); the
page's announce, sent as it registers, makes the bindings and paths again;
packets queued on the old row at that moment are dropped; old tabs of the
identity elsewhere get `401`, then `403 identity_requires_signature`, and
show offline until reloaded.

**Phase 3: enforcement, on James's date.** On each host, a hand edit of its
config: `enforce_signed_registration = true`. Before it, the same day,
Retichat-js's `verify-deploy.sh` shows a signing build on the sites that use
that node, and `/health`'s `browsers_online` is read, for James's judgement
only. Gates: `/health` shows `enforce_signed_registration: true`;
`tools/stage1_probe.py --enforced` passes; a signed page still loads green.

**Rollback.** A PHP node goes back to b6c7809 by `deploy.sh`'s rollback copy.
Old code ignores the new columns and the switch; a signed session keeps
working (old code compares only the token); a browser that registers again
meets `404` at the challenge and registers the legacy way, into a new row,
since no Stage 1 row keeps `identity_hash` in its metadata. Going forward
again, the migration runs and the backfill fills the claims old code wrote.
The rollback reopens A1, A3, A6 and A8 on that node; the UNIQUE index never
conflicts, since old code never writes `identity_hash`. The browser goes back
to 90640bf at any time before Phase 3; after it, turn the switch off first.

## 14. Required tests

Each fails before its fix and passes after (§10 of the principles). "Today"
is Reticulum-post main (b6c7809's code) and Retichat-js 90640bf. A test that
waits does so on an event, with a bound that only fails it.

**Reticulum-post** (real traits; SQLite in memory, or `php -S`):

- **`signed_registration_test.php`:** the challenge (no count, its `400`s);
  an INSERT at count 0 and a re-bind in place (same `interface_id`, new token,
  previous hash); a replay, the other node's challenge and a lost bind race
  `409`, the race leaving one row; a tampered field `403`; an `audience` key,
  a low-order key and `bitrate` 2^31 `400`; signed `reticulum-php` and
  `rns-post-interface` `400 unknown_client`; no refusal writes anything, not
  even the node secret; the answer has no plaintext token or count. *Today:*
  no challenge; a body with `registration` gets a plaintext token.
- **`registration_vectors_test.php`:** §15's browser vectors through the real
  code, the encrypted token byte for byte; it names each vector it skips.
  *Today:* no signed path.
- **`session_superseded_test.php`:** after a signed and after a legacy browser
  re-bind the old token gets `409` with §8's message; an older or unknown
  token `401`; a gateway's legacy re-bind still `401`; the log line once per
  row per token, also under seven case variants of the id with a case-folding
  collation; the switch on: a legacy browser row `401`, a signed row
  unaffected. *Today:* the replaced token gets `401`.
- **`registration_rebind_rules_test.php`:** a legacy claim of a signed
  identity, `'%'` and `'_%'` never touch the signed row (A1); a legacy
  `rns-post-interface` registration naming a browser's identity hash makes its
  own row (A8); no identity field in `metadata_json`; legacy rows claiming an
  identity that signs are removed with their traffic; legacy mode 3, 5 or 6
  `400`; the switch refuses legacy browsers only; no `LIKE` on
  `metadata_json` in `php/src`. *Today:* A8 re-binds the browser's row; mode 6
  is accepted.
- **`announce_row_identity_test.php`:** a victim's announce replayed through
  another browser row, signed or legacy with a made-up claim, moves neither
  its binding nor its packets; a legacy row binds nothing held elsewhere or
  seen; a dropped announce leaves `known_destinations` untouched and is neither
  cached nor forwarded; a browser's own announces still bind; a gateway row's
  behave as today. *Today:* the replay moves the binding.
- **`registration_http_test.php`** (`php -S`): the challenge by GET and POST
  with `no-store`; `{error, message}` bodies; the answer as sent;
  `/exchange`, `/tx`, `/poll`, `/goodbye` answer `409` and `401` as §7 says,
  register and challenge never; no log line holds a token, signature,
  challenge or the secret. *Today:* no challenge route.
- **`schema_migration_marker_test.php`:** §12's objects, the UNIQUE index
  enforced, the backfill (idempotent, `rns-js` only), the claim filled at first
  authentication, a b6c7809 database migrated cleanly, and `schema_migrated`
  false after one failed statement. *Today:* none exists.
- **`health_allowlist_test.php`:** §12's object, and still no identity hash,
  token or browser row. *Today:* no `registration`.
- **`clear_all_data_test.php`:** `clearAllData()` empties `transport_state`
  and `interfaces` (passes today: it pins); with a SQLite trigger failing only
  the `transport_state` `DELETE`, `monitor.php`'s clear leaves `interfaces`
  alone. *Today:* it goes on.
- **Extended:** `deadlock_retry_coverage_test.php`,
  `unique_named_placeholders_test.php` and
  `no_backslash_in_sql_literals_test.php` cover the new trait and SQL;
  `interface_identity_rebind_test.php` (3281ad5's hotfix) and
  `wake_url_path_removed_test.php` read a claim from `claimed_identity_hash`.
  Every other test stays as it is.

**Retichat-js:**

- **`post_interface_signed.test.mjs`:** challenge, sign, decrypt; one more
  round after `409 stale_challenge`, a stop after a second; Superseded stops
  with its message and sends nothing more; terminal codes stop without the
  5 s wait; a challenge `404` leads to the legacy registration; a `401`
  registers signed once per run; a bad token or another `identity_hash` stops;
  a page with only a hash registers legacy on `404` and otherwise stops "out
  of date"; §6's assertions with a test clock, each answer still deciding.
  *Today:* no challenge; a plaintext token is read.
- **`registration_vectors.test.mjs`:** `signRegistration()` reproduces
  `browser-first`'s and `browser-reregister`'s bytes and signatures, their
  tokens decrypt, and both `tokens_negative` fail, against a copy of the
  vector file whose SHA-256 the test pins. *Today:* no `signRegistration()`.
- **A page test** (like `exchange_truth.test.mjs`): `app.js` gives the
  interface `IdMgr.id` and shows a stop's reason under the status dot.
  *Today:* it passes `IdMgr.hash`, and `down` only sets "offline".
- **`exchange_url_policy.test.mjs`:** `EXCHANGE_PATHS` has
  `/v1/interfaces/challenge`, which `.htaccess` allows on both nodes.
  *Today:* the path is missing.

**Private staging** (`staging.sh`, Phase 0): `stage_takeover` (the A1, A3 and
A6 probes succeed against b6c7809's code and fail against Stage 1);
`stage_signed_browser` (harness browsers register signed and exchange direct
and propagated messages; a second browser context of one identity supersedes
the first, which shows §8's message and stops, and whose goodbye then changes
nothing); `stage_mixed` (a 90640bf page beside a Stage 1 page; with the
switch on, the old page gets `401`, then `403 signature_required`, and the
signed one goes on). Stages wait on events, never on a sleep, one at a time.

## 15. Vectors

`php/tests/vectors/registration_vectors.json`, format 6, SHA-256
`7d2bcfee1742a6421a05e2b212c04182cc94247d53128ad91d35139fb07304ef`, made by
`tools/registration_vectors.py` from RNS 1.5.2 and checked independently by
`tools/check_registration_vectors.php` (384 checks). Stage 1 changes no byte.
It pins the `identities` `browser`, `other`, `lowx` and `gateway` (only to
fail decrypting a browser's token); `relays.A` and `relays.B` (node secrets);
the `challenges` of `browser`, `other` and `lowx`; the `registrations`
`browser-first` (count 0 → 1) and `browser-reregister` (1 → 2, a non-ASCII
name); both `tokens_negative`; and fourteen `negative` vectors, each failing
the step of §4.3 it names: `tampered-name`, `tampered-bitrate`,
`wrong-key-signature`, `replay-after-success`, `other-relay-mac`,
`challenge-for-other-identity`, `altered-challenge-nonce`,
`identity-hash-mismatch`, `unsigned-metadata`, `uppercase-public-key`,
`browser-transit-mode`, `browser-with-peer-url`, `unknown-client`,
`low-order-x25519-key`.

Stage 2 pins the rest: the gateway and PHP-node registrations and negatives,
`registration-capacity` (Stage 1 has no cap), `url_canonical`,
`gateway_confirm` and `php_relay_peer`. The file and its tools cite
REGISTRATION.md revision 8's section numbers, which REGISTRATION.md §18 maps.
Both checks run before every commit that touches the protocol.

## 16. Residual risks until Stage 2

Stage 1 closes, for browsers: A1 (re-binding a browser's row by posting its
identity hash) and A6 (replaying a victim's announces through a row with a
made-up claim), for every identity that has signed at that PHP node and for
all once the switch is on; and at once A3 (replaying a victim's signed
announce through one's own browser row), A7 (a signed registration inheriting
a legacy row that claimed its identity) and A8 (claiming a browser's identity
under another `client`). What stays exposed:

1. **Gateway and peering rows are re-bound by their address (A5).** Anyone
   can POST an unsigned `reticulum-php` registration naming the live
   gateway's `peer_url` or the other PHP node's `host_url`, and take the row
   with a new token. The real one gets `401`, registers again and takes it
   back, and the two alternate; meanwhile the stranger collects what was
   queued there (end-to-end encrypted: delivery denied, metadata seen). As
   today, until Stage 2 (gateways) and Stage 3 (peering).
2. **Anyone can still make an unsigned `reticulum-php` or
   `rns-post-interface` row.** Its announces skip §9 (they never make
   bindings, as today), can move paths with a lowered hop count (A4), and are
   forwarded under this node's transport id at least every 300 s; its wakes go
   to whatever address it named (A15). Rows of other `client` values keep
   today's rules too. Until Stage 2.
3. **Legacy browser rows, until Phase 3.** A user who has not signed at a PHP
   node can still be taken over there the legacy way. §9 leaves one race:
   someone hears a native user's fresh announce and delivers it through a
   legacy row before the node reaches that destination any other way.
4. **An existence oracle, until Phase 3:** a legacy registration claiming `H`
   gets `403 identity_requires_signature` when `H` has signed here.
5. **Rows are unbounded (A14).** Signed rows, like legacy rows today, are
   never deleted by the code; a stranger makes one per new key, for two cheap
   requests. A cap on browsers alone would let a flood of unsigned gateway
   rows lock new browsers out, so the cap waits for Stage 2, which can cover
   every client. Deleting signed rows by hand needs the secret rotated (§12).
   Every refusal is logged, so a stranger can grow the error log, as
   malformed claims already can.
6. **A12.** A PHP node the user chose could fetch another node's challenge
   and forward the user's signature. Accepted while nobody can choose a PHP
   node but James's two: the web's CSP `connect-src` allows only the page's
   origin and the two hosts' `/reticulum/`. The encrypted token keeps the
   session from the forwarder.
7. **Unchanged by Stage 1:** a restored database backup brings back an old
   secret and old counts, so each captured body in that range replays once
   (its replayer cannot decrypt the token; the session it supersedes is told
   so); a valid replayed announce can roll back a remembered ratchet through
   a row §9 does not cover, as RNS 1.5.2 remembers every valid copy; and the
   stale sweep still decides by a clock whether a browser row is active.

## 17. Implementation delta

### 17.1 Reticulum-post

The implementation branch `signed-registration` (a65be65: 18 commits on
d828e0a, built against REGISTRATION.md revision 5) predates e3c05ea and
b6c7809, so it still carries the `wake_url` path and the TCP bridge that main
has removed. Start a new branch from main (87c6bee) and carry these over by
hand; do not rebase.

| Commit | Stage 1 keeps | Stage 1 drops |
|---|---|---|
| f7a9353 | `registration_protocol.php` (`lp`, `u64be`, the identity hash, the challenge's MAC, `signedBytes`, `encryptToken`); from `request_registration_trait.php`, `issueChallenge` and the secret, `registerFromBody`, `registerSigned`, `retireSquattedRows`, the legacy browser path on `claimed_identity_hash`, `authenticateInterface` with `409`, `[REG-REFUSED]`; the challenge route; the `[registration]` switch; §12's columns and backfill; `monitor.php`'s `break` (that line only, not the three tables it adds to `$TABLES`); `registration_vectors_test`, `stubs/registration_fixture.php` | canonical `peer_url` and `peer_url_key`; `retireLegacyUrlRows` and every change to the legacy `reticulum-php` path; the nonce refusal; `enforce_signed_transit`, `allow_loopback_http_peers`, `max_interface_rows` and capacity; `peer_state`, `wake_url_confirmed_key`, `wake_outstanding`; the tables `peer_registration_nonces`, `peer_registration_pending`, `gateway_wake_confirms`; the `dispatchWakes` skip; `/health`'s per-row fields |
| 60b883a, 9f8bcfe, ef83be2 | their browser tests (§14); `config.template.toml`'s `[registration]`; the README's rule for deleting identity rows; `monitor.php`'s case, with a SQLite trigger in place of `DROP TABLE gateway_wake_confirms` | `peer_url_canonical_test`; the gateway, `enforce_signed_transit`, capacity and nonce cases; the `409` that f7a9353's `peer_session_rotation_test` expects for a legacy `reticulum-php` re-bind (it keeps today's `401`) |
| 2f169dc, 0fbc2bf, daff4a5 | all: `{error, message}` bodies, writes on `executeWithRetry`, the claim filled at first authentication | — |
| 8248c2d | §9 for browser rows (`request_announce_guard_trait.php`, its place in `processAcceptedAnnounce`), its browser tests, `stubs/announce_fixture.php` | the rules for gateway and PHP-node rows ("transit by proof", "always active"), the seen-blob path rule, and their test changes |
| 21be17d, 2eed8c4 | the once-per-token log keyed on the row's own id (moved to `superseded_logged_hash`); the guard that stops a kept test's `php -S` | — |
| 744048d, c3eab2f, e8ec7b3, 7990c69, 69af93d, 3929fa9, 36d8e7f, a65be65 | — (36d8e7f's `stubs/trigger_pdo.php`, if a race test needs it) | all: the three tables, path rules, the address check, nonce peering, runners, wakes |

Nothing is kept dormant; Stage 2 takes its parts from the branch with its own
spec. **Changed** from the branch: only `rns-js` signs; no capacity step;
§4.5's removal deletes nothing from `wake_events` and runs on §12's indexes;
the bind writes no wake column; messages say "PHP node", never "relay";
other clients' legacy registrations run as on main, apart from §4.6's ignored
`identity_hash`.

### 17.2 Retichat-js (no branch yet; from main 90640bf)

- **`lib/rns/interfaces/post_interface.js`:** the constructor takes the
  identity (an object that signs and decrypts), or only a hash from an old
  `app.js` (§10). Registration becomes the challenge, `signRegistration()`,
  the registration, §5's decrypt and checks; one more round after `409
  stale_challenge`; §10's stops end the interface as `block()` does, report
  its packets lost and emit `down` with the reason; `401` by status only;
  §6's assertions.
- **`app.js`:** `new PostInterface(name, url, IdMgr.id)`, and a stop's reason
  shown under the status dot, where `EXCHANGE_BLOCKED_NOTICE` is.
  **`lib/connect_policy.js`:** `/v1/interfaces/challenge` joins
  `EXCHANGE_PATHS`. **`.htaccess`:** unchanged; its `connect-src` already
  allows `/reticulum/` on both nodes. §14's tests and the vector copy.

### 17.3 Tooling

- **`tools/stage1_probe.py`** (Reticulum-post, new), on `.venv/bin/python`
  (RNS 1.5.2) and `tools/registration_vectors.py`'s `signed_bytes` and
  `reference_decrypt`, with two test identities kept outside every repository
  (`~/.reticulum-post-probe/`, mode 0700). Given a node's base URL it checks
  `/health`'s `registration`; the challenge with `no-store`; a signed
  registration with no plaintext token, which decrypts; an exchange; a second
  registration, after which the first token gets `409 session_superseded`
  and the second `200`; the first body replayed `409 stale_challenge`; an
  unknown session `401`; a legacy claim of the second identity `200` and of
  the first `403 identity_requires_signature` (with `--enforced`, both `403
  signature_required`); goodbyes. It prints each step, never a token, exits 0
  only when all pass, and re-binds the same two rows every run.
- **`staging.sh`** (`test-harnesses/staging/`): `stage_takeover`,
  `stage_signed_browser`, `stage_mixed`, and a way to serve the 90640bf client
  beside the working copy.
- **MySQL 8.4 for the suite**, as open question 3 decides: one database
  fixture for every PHP test (`RETICULUM_TEST_DB=sqlite|mysql|mariadb`), and
  `deploy.sh`'s suite step on SQLite and MySQL 8.4, refusing a red or missing
  MySQL run (REGISTRATION.md §22.5 (a), (b)).

## 18. Decisions

Times are UTC, from the session's record. Where James picked an offered
option, the question is quoted as asked, "relay" included.

| When | What he was answering | James | Where |
|---|---|---|---|
| 2026-10-02 22:30 | (his own words, after asking "What is relay-takeover?") | "Browser signs its registration with its own identity key" | §2, §4 |
| 2026-10-02 23:18 | "The '%' wildcard bug lets anyone re-bind some browser's relay row right now, with no knowledge at all. Hotfix it immediately, ahead of the full signing work?" | "Hotfix now (Recommended)" (3281ad5, live) | §4.6 |
| 2026-10-02 23:18 | "Replay protection for a signed browser registration — how should the relay know a signature is fresh?" | "Can we do a standard challenge and signing?" | §3 |
| 2026-10-03 02:38 | "When two devices or tabs hold the same identity on one relay, the spec has the newest registration win and the older one stop with 'connected elsewhere' (instead of both evicting each other forever). OK?" | "Newest wins (Recommended)" | §8 |
| 2026-10-03 02:43 | "1. Sign the relay address the browser actually connected to (stops a rogue relay proxying your registration)?" | "Don't we have ssl to prevent spoofing?" | §4.2, §16 item 6 |
| 2026-10-03 02:43 | "4. Separate enforcement switches for browsers and for gateways/relay peers?" | "Yes (Recommended)" | §13 |
| 2026-10-04 03:39 | "Should the session token still come back encrypted to the registrant's key, given HTTPS and single-use challenges already cover it?" | "Keep it (Recommended)" | §5 |
| 2026-10-04 11:27 | "... May I start Docker Desktop and pull the official mysql:8.4 and mariadb:11.4 images from Docker Hub (about 1 GB together) to run the relay's tests on both before Phase 1?" | "Selectiv is the staging server" (not an approval of the download: open question 3) | §1.2, §13 |
| 2026-10-04 11:27 | (answering another question) | "... I don't like the term "relay". Let's call it "PHP node". That distinguishes it from browser and gateway" | §1 |
| 2026-10-04 12:11 | the explanation of 11:57 UTC, which set out a registration's steps: challenge, register, the checks, the bind that spends the count and removes unsigned rows claiming the identity, the answer with the token encrypted, the address check, then exchanges until a goodbye, a `401` or a `409` | "This all looks great." | §1, §3 to §8 |
| 2026-10-05 14:49 | "How should the signed registration go forward?", offered as "Narrow the spec to Stage 1 (browsers sign), finish its few questions, then build, stage and deploy it. Gateways and PHP-node peering follow as Stages 2 and 3, each with its own spec and questions." | "Stages, browsers first (Recommended)" | this file |
| 2026-10-05 14:49 | "Fix the live peer-repair bug (the request that repairs a dead peering session fails with a 500) now, as its own small change?" | "Fix and deploy (Recommended)" | §2 |

**This file's own choices**, which James may overrule: the challenge is
stateless (§3); only `rns-js` signs in Stage 1, others get `400
unknown_client` (§4.3); `bitrate` and `mtu` stop at 2^31 − 1 (§4.3); a
legacy browser re-bind also earns the older token `409` (§4.6); a removed
legacy row's queue is dropped, not handed over (§4.5); legacy browser rows
are also refused seen or held announces (§9); no cap on rows until Stage 2
(§16 item 5); logs through `error_log()`, and a served log file holds
Phase 1 on that host (§11, §13); a probe with test identities checks each
node (§17.3).

## 19. Open questions for James

1. **selectiv's foreign `app.js` at Phase 2.** An `app.js` from 1 August keeps
   replacing verified deploys on selectiv, from a source not yet found. It
   gives the connection only the identity hash, so it cannot sign. Once
   Phase 2 reaches selectiv, whenever it reappears it never registers and
   shows only "offline", for every user; the reason reaches only the console,
   a reload serves the same file, and the PHP node logs nothing, so only
   Retichat-js's `verify-deploy.sh <ref> selectiv` sees it.
   - (a) Hold Phases 2 and 3 on selectiv until the source is found.
     Meanwhile every selectiv tab stays legacy, so the announces of any
     identity also used on retichat.com or in a native app, yours included,
     are refused there (§9), and selectiv cannot stage the signed browser.
   - (b) Go ahead: run `verify-deploy.sh` after each deploy to selectiv, again
     hours later, and whenever a selectiv tab shows offline; redeploy when it
     fails. While the old file is served, every selectiv user is offline.
   - (c) Let a page with no signing identity register the legacy way until
     Phase 3, so the old file keeps working until then. Cost: a new `app.js`
     that failed to hand over its identity would also go legacy without a
     sound until Phase 3 cut it off (§14's page test guards against that).

   **Recommendation: (b).** selectiv is the staging server and should run
   what production will run; (b)'s failure is visible and ends with a
   redeploy. Keep looking for the source, including other machines that
   deploy there.

2. **An old tab whose announces the PHP node refuses.** A legacy tab whose
   identity another row already holds (§9's "held": your native app, reached
   through the gateway, say) keeps a green dot, because its exchanges work. It
   still sends and receives propagated messages, but direct messages for its
   identity at this PHP node go to your other device (after a move between
   PHP nodes, along the old path for up to 7 days), and the page says nothing.
   It affects tabs loaded before Phase 2 and not reloaded since; a reload
   after Phase 2 cures it, and Phase 3 ends it.
   - (a) Accept it.
   - (b) Refuse such a tab: its registration, and its exchanges once a hold
     begins, get `403` with a new code. The old page then shows a red dot with
     no reason (no deployed page shows a refusal's message), tries again every
     5 s, and loses sending and propagated delivery until reloaded.

   **Recommendation: (a).** (b) takes everything from the tab and still tells
   its user only "offline".

3. **How MySQL 8.4 is proven before retichat.com.** Every test runs on
   SQLite, and the 2026-09-23 outage shipped past a green SQLite suite; MySQL
   in the staging chain was agreed after it. selectiv proves MariaDB 11.4,
   not MySQL. Your "Selectiv is the staging server" answered the question
   about downloading the images, so it was not a yes.
   - (a) A `mysql:8.4` container on your Mac: start Docker Desktop and
     download the official image (several hundred MB). `deploy.sh` then runs
     the PHP suite on SQLite and on MySQL 8.4, and refuses to deploy on a red
     or missing MySQL run.
   - (b) Another MySQL 8.4 server that you name, with the same `deploy.sh`
     step.

   Until you answer, Stage 1 goes to selectiv only. **Recommendation: (a).**
