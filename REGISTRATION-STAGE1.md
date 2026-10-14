# Stage 1: browsers sign their registration

> Read [`../DESIGN_PRINCIPLES.md`](../DESIGN_PRINCIPLES.md) first. Every rule
> below follows it (events, not timers; no timeouts as a fix; strict
> ordering; §1's 5 seconds), and its §3, no retries, with three exceptions,
> each named where it applies: the browser's backoff after a network failure
> or a 5xx (2 s, doubling, capped at 5 min), a retry and a timer that James
> decided on 2026-10-14 (§2, §10, open question 4); the one extra round after
> `409 stale_challenge`, among the steps James approved on 2026-10-04 at
> 12:11 UTC (§4.3); and the database helper's re-runs after a deadlock or a
> lock-wait timeout, inherited from today's code (§2, §18). The principles'
> §3 records both browser exceptions.

**Status:** specification, revision 3, 2026-10-14: revision 2 (58c5008) with
James's answers to the five open questions of §19. Not built. James chose on
2026-10-05 to ship signed registration in stages, each with its own spec,
build, private staging run (Phase 0) and deploy ("Stages, browsers first
(Recommended)", §18). This is Stage 1: the browser signs its registration
with its own identity key, the takeover fix he chose on 2026-10-02.
[`REGISTRATION.md`](REGISTRATION.md) (revision 10) is the full design and the
roadmap for Stage 2 (gateways) and Stage 3 (PHP node to PHP node peering);
for browsers, where the two differ, this file holds.

**For James.** You answered the five questions of §19 on 2026-10-14; §18
records your answers, and §19 keeps the questions with each answer at its
start. One thing stays open: how MySQL 8.4 is proven before retichat.com gets
Stage 1 (§19, question 3); until then Stage 1 goes to selectiv only (§13).
What you do is in §13: before the first deploy to each host, make it refuse
the two log files (the lines are there); later, the enforcement date and each
host's config edit. The choices this file made that you may overrule are at
the end of §18; this revision adds one: an `online`, `visible` or `pageshow`
event makes the browser's next attempt at once without resetting its backoff
(§10). What
stays exposed until Stage 2 is §16. §3 to §7, §11, §12, §14, §15 and §17 are
for the build.

**Normative for** Reticulum-post (the PHP node) and Retichat-js (the browser:
`lib/rns/interfaces/post_interface.js`, `lib/connect_policy.js`, and what
`app.js` shows). **Vectors:**
[`php/tests/vectors/registration_vectors.json`](php/tests/vectors/registration_vectors.json),
format 6, unchanged (§15). MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

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
| **Session lost** | The PHP node no longer accepts the session and answers `401`; the browser registers again (§7). |
| **Superseded** | A newer signed registration of the same identity replaced this session; the PHP node answers `409` and the browser stops (§8). |
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
| **Bind** | A signed registration's write of `H`'s row (§4.4): an INSERT at count 0, or an UPDATE of that row with a new session token. Either way the count goes up by one. James's step 4, "Bind" (§18, 2026-10-04 12:11). A bind makes no local destination; the browser's announce does (§9). |
| **Re-bind** (logged `rebound`) | Any registration that gives an existing row a new session token: a signed bind of an existing row (§4.4), a legacy browser re-bind (§4.6 step 5), or, as today, a gateway's or PHP node's legacy registration matched by its exact `peer_url`. Only the signed kind moves the count. |
| **Local destination** | A `local_destinations` entry: the PHP node delivers that destination's packets on that row. Only browser rows have them, made from their own announces (`registerLocalDestinationIfOwnInterface`). |
| **Node secret** | The PHP node's key for its challenges (§3). |
| **Enforcement switch** | `[registration] enforce_signed_registration`. Off, the default: the PHP node **accepts both** signed and legacy browser registrations. On: signed only (§13). |
| **Transit mode** | RNS interface mode 3 (access point), 5 (boundary) or 6 (gateway), in which an interface carries other nodes' traffic. A registration's `mode` is read as the node's runtime reads it (`interfaceMode()`: `(int)` of a scalar), so `"6.0"`, `" 6"`, `"+6"` and `"6abc"` are 6, and the row stores that integer (the review of stage1-sign, 2026-10-14). |
| **Peering** | How retichat.com and selectiv carry each other's traffic: each registers at the other the legacy way, and wakes it. |
| **The two hosts** | retichat.com (**production**, MySQL 8.4) and selectivesubconscious.com, **selectiv** (James's staging server, MariaDB 11.4), one PHP node each on cPanel shared hosting. |
| **Private staging** | `staging.sh` with `STAGING_PHP=local` on James's Mac: a PHP node under `php -S` on 127.0.0.1, the local gateway, and browsers driven by the harness scripts in `test-harnesses/`. Never either host. |
| **Phase 0 to 3** | The parts of Stage 1's rollout (§13), not REGISTRATION.md's phases. |
| **Maintenance pass** | `runMaintenance`, today's housekeeping, which the requests that move packets (exchange, tx, poll, wake) run at most once every 2 s per host. Stage 1 adds nothing to it. |
| **Stale sweep** | The maintenance pass's steps that mark a row offline once nothing was heard from it for `interface_stale_after_seconds` (15 s on selectiv, 300 s on retichat.com), and remove its local destinations and paths once it has been offline that long again: after about 30 s of silence on selectiv, 10 minutes on retichat.com. |
| **A1 to A15** | Attacks, by REGISTRATION.md §19's labels; §16 says what Stage 1 closes. |

Names in `code` are literal (columns, config keys, error codes, functions).
Tags in square brackets are log lines (§11). The vector file keeps an older
word: its `relay` means PHP node.

## 2. What Stage 1 changes, and what it leaves as today

**Changes.**

1. **The browser signs.** It fetches a challenge, signs its registration with
   its identity key, and gets its session token back encrypted to that key.
   The PHP node derives `H` from the public key, checks the signature and the
   challenge, and binds `H`'s row, spending the count (§3 to §5).
2. **Legacy rows claiming that identity are removed, never adopted** (§4.5);
   a legacy row still claiming an identity that has signed here gets `401`
   (§7).
3. **Newest wins between signed sessions.** On a signed row every token but
   the current one earns `409` Superseded, and the older browser stops and
   says why (§8). A legacy re-bind keeps today's `401`. `401` means only
   Session lost (§7).
4. **A browser row carries only its own identity's announces, and never a
   transit mode** (§4.3, §4.6, §9).
5. **The enforcement switch** ends legacy browser registrations on a date
   James sets (§13). Schema, logging and `/health` follow (§11, §12), and
   `deploy.sh` builds the schema before the code that reads it goes live
   (§13).
6. **The browser backs off.** After a network failure, a 5xx, or a 4xx on
   an exchange that §10 does not list, its next attempt (challenge,
   registration or exchange) comes after 2 s, doubling, capped at 5 min, and
   any success, an exchange or a registration, resets it; today it waits a
   fixed 5 s. James decided it on 2026-10-14 (open question 4, then "Any
   success resets it"), and the principles' §3 records it (§10).

**Left as today.**

- **Gateways** register unsigned (`reticulum-php` in wake mode,
  `rns-post-interface` in poll mode), are found by their exact `peer_url`,
  and are woken and exchange as today; a signed registration from anything
  but a browser gets `400 unknown_client` (§4.3). Stage 2.
- **Peering** (`connectToPeer`, the exchange inside the `/v1/wake` handler,
  the hourly repair of a dead session): Stage 3. **Paths and announces** on
  rows that are not browser rows (REGISTRATION.md §12.5): Stage 2.
- **Calls to other hosts.** Stage 1 adds no outbound call and moves none.
  Wakes still go out before the answer, one after another, as today, so a
  browser's exchange still waits through each wake it sets off, and a slow
  wake address can now trip §6's assertion. James's decision of 2026-10-04
  to send wakes after the answer (REGISTRATION.md §2.5) ships with Stage 2;
  the exchange a woken PHP node makes stays with peering (Stage 3). When the
  PHP node's other calls run (REGISTRATION.md open question 20) does not
  arise.
- **Exchange, Poll, Goodbye**, the stale sweep, the maintenance pass, the
  storage reclaim, the random transport id (Stage 3), and unbounded rows (§16
  item 5).
- **The browser's** one connected tab per identity (`ActiveTab`) and its
  goodbye beacon. Its fixed 5 s wait gives way to the backoff (item 6).
- **The database helper.** Stage 1's writes, like every hot-path write
  today, go through `Database::executeWithRetry`. It runs a statement again
  after MySQL error 1213 (deadlock) or 1205 (lock wait timeout, 50 s by
  default), up to three times, sleeping 100, 200 and 400 ms: a retry in the
  sense of the principles' §3. `database.php`'s header argues the 1213 case
  (InnoDB undid the statement; the cure is lock order), but that is not one
  of James's decided exceptions, and nothing argues the 1205 case, a re-run
  after a timeout that can stretch one registration to about 200 s and that
  §6's assertion would log. Stage 1 neither changes the helper nor avoids it
  (§4.4, §18).
- **The peer-repair fix** James chose ("Fix and deploy (Recommended)") is
  2b2ad9c, live on both nodes since 2026-10-05 (then c37b08f; 50c870b on
  2026-10-14). Stage 1 is built
  on it (§17.1) and never rolls back past it (§13).

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
exists; nor does a refused registration, since the signature is checked
before the challenge (§4.3). A PHP node without Stage 1 answers `404`, the
only status on which a browser registers the legacy way (§10). A challenge
POST by `identity_hash` adds one to `/health`'s `hash_only_challenges` (§12):
only a page with no signing identity asks that way (§10), so a rise says an
old `app.js` is being served somewhere.

```
H          = the identity hash (16 bytes), from public_key or as given
count      = registration_seq of the row whose identity_hash = H, or 0 if there is none
nonce      = 16 random bytes (CSPRNG)
mac        = HMAC-SHA256(node_secret, "reticulum-post/challenge/v1" || H || u64be(count) || nonce)
challenge  = nonce(16) || mac(32)
```

The domain is those 27 ASCII bytes; every other part has a fixed width;
`u64be` is unsigned 64-bit big-endian. The count is in the MAC but never
sent. The challenge is **stateless**: no table of codes, no expiry, no sweep.

**The node secret** is 32 random bytes, made on first use and kept as hex in
`transport_state` under `registration_challenge_secret_hex` (INSERT-or-ignore,
then SELECT, so concurrent first requests agree); checking a challenge never
creates it. It never appears in `/health`, `/debug`, the monitor, a log line
or an answer. A database reset rotates it (`clearAllData()` empties
`transport_state`), and every outstanding challenge dies with it.

**Single use.** A successful signed registration moves the row from `count`
to `count + 1` (§4.4), so every challenge made at the old count fails for
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
`peer_url`, `peer_interface_id`, `peer_session_token`), `implementation` (a
string of at most 64 bytes, never acted on) and `identity_hash` (if present
it MUST equal `H`; never stored). Any other key gets `400 unsigned_metadata`:
the PHP node never acts on a value the signature does not cover.

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
address of the PHP node is signed, now or in a later version of the
browser's registration: James decided on 2026-10-14 to rely on Reticulum's
security (open question 5; §16 item 6). Worked example: REGISTRATION.md
§4.3.1, vector `browser-first`. The browser builds these bytes in one
function, `signRegistration()`, and signs nothing received apart from the
challenge in its field; no RNS signature can begin with them, since each
starts with a 16- or 32-byte hash or key.

### 4.3 Checks, in order

Cheapest first: the signature needs no database read, the challenge two.
Nothing is written before step 8.

| Step | Check | On failure |
|---|---|---|
| 1 | Shape: the `registration` object (§4.1); `name` a non-empty JSON string of valid Unicode, at most 255 bytes as UTF-8; `bitrate` and `mtu` JSON integers from 1 to 2^31 − 1 (what today's `INT` columns hold); `mode` a JSON integer from 1 to 7; `client` a non-empty string of at most 64 bytes; `implementation`, `transport`, `peer_url`, `peer_interface_id` and `peer_session_token` each absent, `null`, or a JSON string of valid Unicode of at most 64, 64, 512, 64 and 128 bytes as UTF-8; `challenge`, `public_key`, `signature` lower-case hex of 96, 128, 128 characters. Strings, booleans and floats such as `1e6` where an integer belongs, and numbers, booleans, arrays and objects where a string belongs, are refused. | `400 bad_registration` |
| 2 | Metadata keys within §4.1's set | `400 unsigned_metadata` |
| 3 | `H = SHA-256(public_key)[:16]`; `metadata.identity_hash`, if present, equals `H` | `400 identity_hash_mismatch` |
| 4 | `client` is `rns-js`; then `mode` is 1, 2, 4 or 7, not a transit mode; then `transport` and the three `peer_*` fields are empty (absent, `null` or `""`) | `400 unknown_client`, then `transit_mode_not_allowed`, then `metadata_not_allowed` |
| 5 | `sodium_crypto_sign_verify_detached(signature, signed, public_key[32:64])`, over bytes rebuilt from the received body | `403 bad_registration_signature` |
| 6 | Read the row with `identity_hash = H` (its count, or 0); recompute the MAC over `H`, that count and the challenge's nonce; compare in constant time | `409 stale_challenge` |
| 7 | A fresh session token, encrypted to `public_key[0:32]` (§5); an all-zero X25519 result (a low-order key) fails | `400 bad_registration` |
| 8 | The bind (§4.4) | `409 stale_challenge` |

Step 6 fails alike for a challenge issued before the count moved, by another
PHP node, for another identity, under a rotated secret, or altered. The
signature is checked before the challenge so that a request without `H`'s
private key gets `403` whatever the count, learns nothing about the row, and
reads no row or secret; a correctly signed body over an old challenge (the
browser's own, or a replayed one) gets `409`.

**One more round after `409 stale_challenge`.** The browser fetches one new
challenge and registers once more, and only once; a second `409` stops it
(§10). James approved this step on 2026-10-04 ("If the code is out of date,
the connecting side fetches a new one and tries once more", §18), and the
principles' §3 records it with the browser's backoff (§10). Its causes are
events: another tab or device of the identity binding between this browser's
challenge and its registration; this browser's own registration, abandoned
by `check()` or `disconnect()`, which the PHP node still completed; or a
database reset by the operator.

### 4.4 The bind

The row is found only by `identity_hash = :h`: its own column, UNIQUE,
lower-case hex only, so no collation folds two values together.

- **Count 0 (no signed row): INSERT** a row with a fresh `interface_id` (16
  random bytes, hex), status `online`, `identity_hash = H`, the public key,
  `registration_seq = 1` and `registration_proof = 'signed'`. A unique-key
  conflict means another registration of `H` won: `409 stale_challenge`,
  never a second INSERT.
- **Count n > 0: UPDATE in place**, with the count step 6 read;
  `rowCount() = 1` is required, otherwise `409 stale_challenge`.
  `:old_token_sha256` is the SHA-256 hex of the token the row held when step 6
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

The row keeps its `interface_id`, so its queue, paths and local destinations
survive a reload; `metadata_json` holds only `client`, `implementation` and
`mode`. No placeholder appears twice. Every write goes through
`Database::executeWithRetry` (§2). Each is one autocommit statement, so
InnoDB undoes all of it on 1213 or 1205 and a re-run leaves nothing
half-done; a duplicate key (1062) on the count-0 INSERT is never re-run and
answers `409 stale_challenge`. Stage 1 opens no transaction.

### 4.5 Legacy rows claiming the identity are removed, never adopted

A legacy claim lives in `claimed_identity_hash`, never in `identity_hash`
(§4.6), so a signed registration never lands on a legacy row. After every
successful bind for `H` (the INSERT, and the UPDATE too, which catches a
legacy row that raced in), the PHP node removes every row with
`claimed_identity_hash = H` and `registration_proof = 'none'`: first its
traffic, each step a statement on an index (§12), then the row:

1. its local destinations (`local_destinations`);
2. the `path_entries` through it; the `reverse_path_entries` and
   `link_transport_entries` received on it, then those sent out on it (one
   `DELETE` per column);
3. its `outbound_packets`, selected by `interface_id` and deleted by primary
   key in ascending order, then its `outbound_batches`.

Nothing passes to the signed row: those packets were queued to a row whose
owner was never proven (A7). Logged `[REG-RETIRE] identity=<H> rows=<n>
dropped=<m>` when `n ≥ 1`; with no such row it costs one indexed SELECT. A
database error here is logged `[REG-RETIRE] identity=<H> failed=<table>`, and
the registration is still answered as §5 says: the bind has succeeded, and
the next bind of `H` runs the removal again. Meanwhile those rows are inert:
§9 gives them no owner, §4.6 refuses their claim, and §7 answers their
holders `401`. Whoever held a removed row gets `401`; an old page then
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
   plaintext token and `previous_session_token_hash` NULL. The replaced token
   then gets `401`, and an old page registers again at once, as after a
   gateway's legacy re-bind and for the reason REGISTRATION.md §4.10 gives: a
   client that does not know `409` would stay down after one unsigned
   registration. If the `UPDATE` changes no row (a signed registration's
   §4.5 removed it after it was read), go back to step 4. Otherwise INSERT a
   legacy row with `claimed_identity_hash = claim`.
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
it" (§18). It keeps the token from anyone who replays a captured body (§3)
or holds only a copy of the answer, such as a log that records answers. It
does not keep it from the PHP node the browser uses: the browser sends the
token to that node, in plain text inside HTTPS, on every exchange and goodbye
(§6), as today. So it does not change A12 (§16 item 6). The browser keeps
the token in memory only: it never writes it to storage, and removes the
entry older builds wrote there (review of 2026-10-14: a stored token
outlives the tab, and nothing read it).

## 6. Exchange, Poll and Goodbye

Unchanged: `POST /v1/interfaces/exchange` (and `/tx`, and `/poll` for
poll-mode gateways) with today's fields and delivery batches, every
`idle_exchange_interval_ms` and at once when the browser has something to
send; and on `pagehide` the goodbye beacon, `POST /v1/interfaces/goodbye
{"interface_id", "session_token"}`, after which the row is offline and its
local destinations and paths are gone. Only the check of the session changes
(§7, §8): a goodbye with a token a signed re-bind replaced gets `409` and
changes nothing, so a closing old tab never takes the newer session's local
destinations; a goodbye with a replaced token of a legacy row gets `401` and
changes nothing, as today.

**The browser's §1 assertions.** Every challenge, register and exchange is a
network send under §1 of the principles: the browser times each POST to its
answer, and an answer later than 5 s is logged as a §1 violation
(`console.error`, the line carrying `// NEVER REMOVE EVER — see
DESIGN_PRINCIPLES.md §1`) and still decides. A request with no answer 5 s
after it was sent is logged then, once, by a watch that decides nothing and
ends at the answer, an abort or a stop, so a request abandoned or never
answered is said too (as `Link.requestLog`'s watch, Retichat-js f54d7cd). Today none is asserted. The
goodbye beacon has no answer to time (`navigator.sendBeacon` reports only
that the body was queued), so the stale sweep stays its backstop; the
keepalive fetch used only where `sendBeacon` is missing does get an answer
and is timed like the others. The probe times every request it makes,
goodbyes included (§17.3). A failed exchange is not made again because it
failed; its packets are reported lost.

## 7. Session lost (401)

`authenticateInterface(id, token)`, on `/exchange`, `/tx`, `/poll` and
`/goodbye`, reads the row in one statement, with whether a signed row holds
its claim (a correlated `EXISTS` on the UNIQUE `identity_hash` index), and
answers in this order:

1. no row `id`: **`401`**;
2. a legacy browser row while the switch is on: **`401`**, whatever the token;
3. `token` equals the row's `session_token` (`hash_equals`): success, as
   today, except for a legacy browser row whose claim is a signed row's
   `identity_hash`, which gets **`401`**, with nothing written but its claim.
   The claim is `claimed_identity_hash` or, while that is empty (a row old
   code wrote after a rollback), the one this step fills from the row's
   metadata. Such a row is left by a rollback and forward again, by a legacy
   INSERT that lost the race with §4.4's, or by a failed §4.5 removal. A
   Stage 1 page answers the `401` by signing, which removes the row (§4.5);
   an old page then gets `403 identity_requires_signature`;
4. any other token on a signed row: **`409 session_superseded`** (§8);
5. anything else: **`401`** (another token on a legacy row, or on a row of
   another client, as today).

`401 {"error":"unauthorized"}` comes only from these steps; register and
challenge never answer `401` or `session_superseded`.

**The browser**, on `401`, reports that exchange's packets lost and registers
again (challenge, then register) at once, as today, with no backoff: a `401`
is a protocol answer, not a failure (§10). That is at most one registration
per `401`: a `401` on the first exchange of a session the browser has just
made by a signed registration stops it, saying why (§10), with no backoff. A
session made the legacy way (after a challenge `404`) registers again at
every `401`, as today, so it stays in old pages' position (§8), and a
stranger's legacy re-bind at a PHP node without Stage 1 cannot stop it. It acts on the status and
code alone; today's match on the text "Invalid interface credentials" goes.

## 8. Superseded (409)

The PHP node writes `previous_session_token_hash` exactly when a signed
re-bind replaces a row's token (§4.4). No legacy re-bind writes it (a
browser's, a gateway's or a PHP node's), and no goodbye does. A signed row's
token changes only by a signed re-bind: a goodbye keeps it, §4.5 never
removes a signed row, and interface ids are 16 random bytes, never reused. So
any token on a signed row other than its current one was superseded, or
forged, and earns `409` (§7 step 4). Newest wins (James: "Newest wins
(Recommended)").

```
409 {"error": "session_superseded",
     "message": "This identity connected from another tab or device. Reload to connect here."}
```

**The browser** stops: no exchange, no registration, no backoff; its held
packets are reported lost; the message is shown under its status dot (§10).
A reload or an explicit reconnect registers again, and the other side then
gets the message.

**Old pages.** An old page (Retichat-js f54d7cd or earlier) never meets `409`: it
registers the legacy way, and a legacy re-bind keeps today's `401`. So two
old pages of one identity keep evicting each other with every `401`, as
today, until each is reloaded onto a signing page after Phase 2; then newest
wins. A Stage 1 page that registered the legacy way (only after a challenge
`404`) is in the same position at that PHP node.

**Logging.** `[SESSION-SUPERSEDED] interface=<id8>` is written only for the
token the last signed re-bind replaced (its SHA-256 equals
`previous_session_token_hash`), once per row per token: the row keeps the
last logged hash in `superseded_logged_hash`, set by a compare-and-swap on
its own `interface_id`, never on the request's string, which a case-folding
collation matches in several spellings:

```sql
UPDATE interfaces SET superseded_logged_hash = :new_hash
 WHERE interface_id = :id AND superseded_logged_hash <> :logged_hash
```

with both hashes bound to that SHA-256. Older tokens get the `409` with no
line, so pages repeating different stale tokens cannot fill the log.

## 9. The browser-row announce rule

It applies to every announce received on a browser row, path responses
included, in every mode, signed or legacy. It runs inside
`processAcceptedAnnounce`, right after `AnnounceValidator::validate` and
before `rememberKnownDestination`, the local destination, the path update,
announce caching and forwarding, so both of its callers get it.

```
I        = SHA-256(the announce's public key)[:16]
owner(R) = R.identity_hash             if R is a signed row
         = R.claimed_identity_hash     if R is a legacy browser row, the switch is off,
                                          and no row has identity_hash = R.claimed_identity_hash
         = none                        otherwise
accept   ⇔ owner(R) ≠ none, I = owner(R), and, for a legacy row, the announce is neither seen nor held
```

- **Seen:** its random blob is recorded for that destination
  (`path_entries.random_blobs_json`), or its packet hash is the one
  `known_destinations` remembers for it (the last accepted announce's): a
  replay.
- **Held:** another row already holds the destination: a local destination
  on another row, or a usable (unexpired) path entry through another row.

"Seen" and "held" read records that other parts of the node remove: the
stale sweep removes a quiet row's paths, with their blobs, and its local
destinations (about 30 s after the peering row's last exchange on selectiv,
about 10 minutes for retichat.com's gateway row); expiry stops a path
counting as held; the storage budget can prune `known_destinations`. After
that, a legacy row claiming the identity passes with any of its announces
except the newest the node remembers (§16 item 3).

An announce not accepted is dropped whole: no remembered key, ratchet or
`app_data`, no local destination, no path update, no announce cache, no
forwarding. Its `inbound_packets` row says `refused`, and nothing serves it:
a cache request that replays it relays nothing, and a new row is seeded only
with copies that were accepted (§17.1). A copy whose row is gone (§4.5, the
stale sweep) answers a cache request as not cached: replayed through a row
that no longer exists, it would skip this check and make a path to an
interface that does not exist (the review of stage1-sign, 2026-10-14). Logged `[ANNOUNCE-FOREIGN]
interface=<id8> dest=<hash> identity=<8 hex> owner=<8 hex|none>` or
`[ANNOUNCE-LEGACY-REFUSED] interface=<id8> dest=<hash> reason=<seen|held>`.
`owner(R)` is read as the announce arrives, so a legacy row loses its claim
the moment its identity signs here.

Nothing legitimate breaks: the browser announces only its own identity's
destinations (`lxmf.delivery`, `rfed.delivery`); a distro's announce goes to
RFed inside an RNS link request and reaches the PHP node through the gateway.
Today's move of a local destination between browser rows then only happens
between rows of one owner, as at a reload. The rule runs in every mode, so an
old legacy row with a transit mode is covered. Other rows follow today's
rules. What "held" costs an old tab is open question 2, and James accepted it
on 2026-10-14 ("Accept it (Recommended)"); a signed row is never subject to
it.

## 10. Errors

Every 4xx and 5xx body that carries an `error` is `{"error": "<code>",
"message": "<one line for a person>"}`. The browser acts on status and code.

| Status | `error` | Raised when | The browser |
|---|---|---|---|
| 400 | `bad_challenge_request` | a challenge request without exactly one well-formed key or hash | stops, says why |
| 400 | `bad_registration` | a malformed `registration` object, signed field or `implementation`; a key that cannot receive a token | stops, says why |
| 400 | `unsigned_metadata` | a metadata key outside §4.1's set | stops, says why |
| 400 | `identity_hash_mismatch` | `metadata.identity_hash` ≠ `H` | stops, says why |
| 400 | `unknown_client` | a signed registration whose `client` is not `rns-js` | stops, says why |
| 400 | `transit_mode_not_allowed` | `rns-js` in mode 3, 5 or 6, signed or legacy | stops, says why |
| 400 | `metadata_not_allowed` | a signed `rns-js` registration with `transport` or a `peer_*` field | stops, says why |
| 403 | `bad_registration_signature` | the signature does not verify | stops, says why |
| 403 | `identity_requires_signature` | a legacy registration claiming an identity that has signed here | only pages older than Stage 1 get it; they show "offline" |
| 403 | `signature_required` | a legacy browser registration while the switch is on | the same |
| 409 | `stale_challenge` | the challenge does not verify against this PHP node, identity and count; or the bind race was lost | one new challenge, one more registration; a second `409` stops: "Another registration of this identity got in first. Reload to connect here." |
| 401 | `unauthorized` | `/exchange`, `/tx`, `/poll`, `/goodbye`: §7 | registers again; a `401` on the first exchange of a new signed session stops: "The PHP node dropped this connection as soon as it was made. Reload to connect." |
| 409 | `session_superseded` | the same endpoints: any token but the current one on a signed row | stops with §8's message |
| 404 | (any) | the challenge, at a PHP node without Stage 1 | registers the legacy way |

**"Stops, says why":** no further automatic registration, and no backoff.
The interface takes its stopped state first, then emits `down` if it has
not (so an older `app.js` served with this lib, by `deploy.sh`'s lib-first
copy or a browser's cache, shows offline, as §13's watch expects), then
`stopped(reason)` exactly once, whatever `down` has said before; the reason is a sentence for a person (§8's for
`session_superseded`, this table's where it gives one, otherwise the
answer's `message`), never the raw error text. `app.js` keeps it as its own
state, a status `stopped` that `_applyStatusDot` redraws after every render,
as it does `blocked`, and from then on ignores the interface's `up` and
`down`, as it does once blocked. A reload or an explicit reconnect starts
again. `down` keeps today's contract (at most once until the next `up`) and
its test; `block()` emits no `stopped`, since `app.js` says why itself; and
`exchangeBlocked` is not reused, since Settings shows it as the policy error
on the exchange URL, with a cure that does not apply. The browser also stops,
saying why, on a token that does not decrypt or another `identity_hash`
(§5), and when its page gave it no signing identity (an `app.js` older than
Stage 1): it then asks the challenge by `identity_hash`, registers the legacy
way only on `404`, backs off on no protocol answer (below), and otherwise
stops: "This page is out of date. Reload it
to connect."

**The backoff.** A network failure, a 5xx, or a 2xx whose body is not JSON
(a captive portal's page, a PHP error page) is no protocol answer: the
attempt's packets are reported lost, and the next attempt (challenge,
registration or exchange) comes after a backoff of 2 s, doubling after each
failure, capped at 5 min, and reset by any success, an exchange or a
registration (James, 2026-10-14: "Any success resets it"; after a network
drop the session is still valid, so the next attempt is usually an
exchange). A 4xx that this table does not list counts as such a failure on
an exchange, and stops, says why, on the challenge or the registration. An
`online`, `visible` or `pageshow` event makes the next attempt at once,
without resetting the backoff (this file's choice, §18), so a failure after
it waits the next step. A `401` is a protocol answer, not a failure: the
browser registers again at once (§7).
The codes that stop end the attempts with no wait. The failure is still
surfaced: the status dot shows offline while it lasts. James decided the
backoff on 2026-10-14 ("Back off 2 s to 5 min", open question 4), in place
of today's fixed 5 s wait, which old pages keep; the principles' §3 records
it, with the one extra round after `409 stale_challenge` (§4.3). Old pages
know none of these codes (§8).

## 11. Logging

Stage 1's lines go through `error_log()`, as today's `[REG-BAD-IDENTITY]` and
`[WAKE-DROP]` do, into PHP's error log beside `index.php`. REGISTRATION.md
§15's single logger is not part of Stage 1, and no gate reads a log.

| Tag | When |
|---|---|
| `[REG-SIGNED] identity=<H> interface=<id8> <created\|rebound>` | a signed registration bound |
| `[REG-REFUSED] <status> <error> client=<c> [identity=<H>]` | every 4xx and 5xx of challenge and register; §4.6's two `403`s once per row and count (below) |
| `[REG-LEGACY] client=rns-js action=<created\|rebound> interface=<id8>` | a legacy browser registration accepted |
| `[REG-RETIRE] identity=<H> rows=<n> dropped=<m>`, `[REG-RETIRE] identity=<H> failed=<table>` | §4.5 removed legacy rows, or failed to |
| `[REG-CLAIM-IGNORED] client=<c>` | another client's legacy registration carried `identity_hash` |
| `[REG-BAD-IDENTITY]`, `[REG-WAKE-URL-IGNORED]` | as today |
| `[SESSION-SUPERSEDED] interface=<id8>` | §8 |
| `[ANNOUNCE-FOREIGN]`, `[ANNOUNCE-LEGACY-REFUSED]` | §9 |

**An old page stuck behind a `403`** (`identity_requires_signature` after
Phase 2, `signature_required` after Phase 3) registers again every 5 s while
it runs: about 17,000 lines a day per tab, sharing the log's 16 MB budget
with the lines James reads. So before logging either, the PHP node reads the
claim's row in one indexed lookup (the signed row by `identity_hash`, else
the newest legacy row by `claimed_identity_hash`) with its
`refusal_logged_seq`, and logs only when this changes the row:

```sql
UPDATE interfaces SET refusal_logged_seq = :seq
 WHERE interface_id = :id AND registration_seq = :row_seq AND refusal_logged_seq <> :logged_seq
```

with all three bound to the row's count: once per registration count of a
signed row, once per legacy row (whose count stays 0). When the column
already holds the count, nothing is written. A claim with no row, or no
valid claim, is logged every time, as `[REG-BAD-IDENTITY]` is today. The
answer is the same either way.

Logs MUST NOT contain session tokens, signatures, challenges or the node
secret; they give identity hashes in full and interface ids as 8 hex. Since
these lines say who registered here and when, the log file MUST NOT be served
over HTTP (§13, before Phase 1).

## 12. Schema and `/health`

Added in `request_schema_trait.php`. All additive; none of REGISTRATION.md
§14.1's other objects exists in Stage 1. On the two hosts no request builds
them: `deploy.sh` builds them before the swap (§13), and a request that
arrives before the new version is recorded runs a `migrate()` that finds them
all and builds nothing.

| Object | Definition |
|---|---|
| `interfaces.identity_hash` | `VARCHAR(32) DEFAULT NULL`, with `CREATE UNIQUE INDEX idx_interfaces_identity_hash ON interfaces (identity_hash)` (several NULLs are allowed on MySQL 8.4, MariaDB 11.4 and SQLite) |
| `interfaces.identity_public_key` | `VARCHAR(128) DEFAULT NULL` |
| `interfaces.registration_seq` | `BIGINT NOT NULL DEFAULT 0`: the count |
| `interfaces.registration_proof` | `VARCHAR(16) NOT NULL DEFAULT 'none'`: `none` or `signed` |
| `interfaces.claimed_identity_hash` | `VARCHAR(32) DEFAULT NULL`, with `idx_interfaces_claimed_identity` |
| `interfaces.previous_session_token_hash` | `VARCHAR(64) DEFAULT NULL` (§8) |
| `interfaces.superseded_logged_hash` | `VARCHAR(64) NOT NULL DEFAULT ''` (§8) |
| `interfaces.refusal_logged_seq` | `BIGINT NOT NULL DEFAULT -1` (§11) |
| indexes for §4.5 | `idx_outbound_packets_iface ON outbound_packets (interface_id, acked_at)`, `idx_path_entries_iface ON path_entries (interface_id)`, `idx_reverse_path_received ON reverse_path_entries (received_interface_id)`, `idx_link_transport_received ON link_transport_entries (received_interface_id)`, `idx_link_transport_outbound ON link_transport_entries (outbound_interface_id)`. Without them each removal scans whole tables, and Phase 2 makes one removal per user. `local_destinations` and `outbound_batches` are already indexed by `interface_id`. |
| `transport_state` rows | `registration_challenge_secret_hex` (§3); `hash_only_challenges`, a count (§3, `/health`) |

**The schema version.** `migrateIfNeeded()` compares the recorded value with
a literal the running code carries, `schemaVersion()`, for example
`'stage1-1'` (a method, since a trait constant needs PHP 8.2 and the floor is
8.1), in place of today's SHA-1 of the trait file on disk. Today's value can
be recorded by old code: for a moment after a swap, opcache may still run the
old compiled trait, which hashes the new file, runs its own old `migrate()`,
succeeds and records the new file's hash, so the new code never migrates (no
column, every exchange `500`, `schema_migrated` true). Old code records SHA-1
values, which never equal the literal, so the next Stage 1 request migrates.
A guard test pins the pair (version, SHA-1 of the trait with the literal
masked): a change to the trait without a new version fails. `ensureIndexes`
SHOULD read the existing indexes once (`information_schema.STATISTICS` on
MySQL and MariaDB, `PRAGMA index_list` on SQLite) and create only the missing
ones, so a re-run takes no metadata lock.

**The migration's locks.** On MySQL and MariaDB each DDL statement takes an
exclusive metadata lock on its table, at its start or its end, and while it
waits for one every new statement on that table waits behind it: a statement
waiting on a row lock holds its table for up to `innodb_lock_wait_timeout`
(50 s), and MariaDB's own `lock_wait_timeout` is a day. So `migrate()` runs
its DDL with `lock_wait_timeout = 2`, once each, with no retry (§3): a
statement that cannot have its lock within 2 s fails the migration, `index.php
migrate` exits non-zero and `deploy.sh` stops before the swap with the live
code untouched, to be run again. Each table's missing columns are added by
one `ALTER` with `ALGORITHM=INSTANT`, and the indexes are built with
`ALGORITHM=INPLACE LOCK=NONE`, so a server that cannot do either online
refuses at once instead of copying or locking the table (the review of
stage1-sign, 2026-10-14).

**Backfill**, in PHP at every migration, idempotent, with no `LIKE`:
`claimed_identity_hash` for legacy `rns-js` rows, from a top-level
`metadata.identity_hash` of 32 lower-case hex; the key leaves `metadata_json`
at the row's next write. **Lookups never compare free text:** under MySQL's
and MariaDB's `utf8mb4_unicode_ci`, `é = e` (SQLite compares bytes), so every
lookup Stage 1 adds uses lower-case hex checked by shape. No SQL compares
`metadata_json` with a value from a request; the one comparison on
`metadata_json` left in `php/src` is `recentNodeInterfacesByStatus`'s `LIKE
:poll_gateway`, bound to a constant, which only narrows `/health`'s scan
before the exact check of the decoded `client` (§14).

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
                 "browsers_online": {"signed": 0, "legacy": 0}, "hash_only_challenges": 0}
```

`version` 1 says the node runs Stage 1. `schema_migrated` is true exactly
when the recorded version is this code's and a probe finds §12's objects: a
zero-row `SELECT` of the new columns from `interfaces` (`LIMIT 0`, the same
on all three engines), and `idx_interfaces_identity_hash` unique (`SHOW
INDEX` with `Non_unique = 0` on MySQL and MariaDB, `PRAGMA index_list` with
`unique = 1` on SQLite). The probe is needed: `ensureIndexes` treats errors
1061, 1072 and 1146 as harmless, so `migrate()` can report a clean run without
the index. A query of this object that fails reports `schema_migrated: false`
rather than answering `500`. `enforce_signed_registration` is the switch as
loaded; `browsers_online` counts online signed rows, and online legacy rows
with a claim. `hash_only_challenges` counts challenge POSTs by
`identity_hash` since the last database reset, each adding one by a single
upsert on `executeWithRetry` that runs on all three engines; GETs and the
probe, which asks by key, do not move it.
A rise is a prompt to run Retichat-js's `verify-deploy.sh`, never a gate:
anyone can POST one.

## 13. Rollout

**selectiv only, for now.** James decided on 2026-10-14 ("selectiv only, for
now", open question 3) that Phases 1 to 3 go to selectiv alone.
retichat.com's PHP node stays on today's code, and with it today's takeover
risk (§16 item 3), until MySQL 8.4 is proven; how it is proven is still open
(§19, question 3). The web client is one build on both hosts: at
retichat.com's PHP node the challenge answers `404`, the only status on which
a browser registers the legacy way (§3, §10), so a page registers there as
today, whichever site served it. No phase below goes to retichat.com until
MySQL 8.4 is proven, and meanwhile no deploy there may carry Stage 1's code:
`./deploy.sh` with no node deploys to both, so a Stage 1 ref is deployed by
naming selectiv.

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
identities of its own, checks every answer, and fails on any answer later
than 5 s. Gates run in the order listed. Each deploy (Phases 1 and 2) also
passes `deploy.sh`'s gates: a clean tree, a green suite, the release exported
from git and uploaded to `~/reticulum-incoming`, lint on every node, a
rollback copy, a swap in one step, verification and the stamp; Retichat-js's
deploy passes its boot gate and CSP check.

**A new deploy step: the schema before the swap.** On each node, after the
lint and before any swap, `deploy.sh` runs `php ~/reticulum-incoming/index.php
migrate --project-root <realpath of ~/public_html/reticulum>` (a new CLI
mode; the uploaded release holds no config), under `trap '' HUP`, since a
dropped connection would roll an index build back. It runs the uploaded
release's `migrate()` against the live database and then §12's probe, prints
each object it builds
and how long that took, records no version, and exits non-zero on any error
or a failed probe; the deploy then stops with nothing swapped. Old code keeps
serving meanwhile and ignores the new objects. A ref whose `index.php` has no
migrate mode (any before Stage 1, on a rollback) skips the step.
`migrateIfNeeded()` stays in the request path for a fresh or restored
database and for private staging.

**Phase 0: private staging**, on James's Mac only: the PHP suite on SQLite
and, as open question 3 decides, MySQL 8.4; Retichat-js's full suite; then
`staging.sh` with `STAGING_PHP=local` and the local gateway registering the
legacy way, running §14's four new harness scripts, then the existing
`test-harnesses/staging/stage_browser.mjs`,
`test-harnesses/distro-pipeline/stage3.mjs` to `stage7.mjs` and
`test-harnesses/staging/stage_large.mjs`, and `tools/stage1_probe.py
http://127.0.0.1:8080`.

**Before Phase 1, on each host:**

- `https://<host>/reticulum/error_log` and `…/reticulum/var/router.log` must
  not answer `200` to `curl`. A `200` means the file is served, which leaks
  today's lines already, and Stage 1 waits on that host until it refuses
  them. The cure is James's, by hand: `deploy.sh` ships only `*.php` and
  `lib/*.php`, removes only its `RETIRED` list and never touches dotfiles.
  For example, add `RedirectMatch 404 ^/reticulum/(error_log|var/)` to
  `~/public_html/reticulum/.htaccess`; the proof is both `curl`s answering
  `403` or `404`.
- On 2026-10-14 selectiv answered `403` for `error_log` but `200` for
  `var/router.log` (5 KB, written that day) and for `var/` itself, an Apache
  directory listing naming `reticulum-php.sqlite` (3.5 MB, 19 July), which
  it also serves: a copy of a PHP node database, whose tables hold session
  tokens and PHP-node peer tokens in plain text (the node compares them with
  `hash_equals`) and the identity hashes and announces of those who
  registered (its contents were not read). So before Phase 1 there, besides the `RedirectMatch`: the
  copy leaves the web root, `curl` of `var/` and of the file answers `403`
  or `404`, and James decides whether any token in the copy can still work
  on the live database. retichat.com, the same day: `error_log` `403`, but
  `var/` listed and its `router.log` (360 KB, written that hour) served; its
  SQLite files there are empty.
- Record the commit `/health` names (`build.commit`; 50c870b on both nodes
  on 2026-10-14). It is that node's rollback target.
- For retichat.com, the MySQL 8.4 run of open question 3 must have passed;
  until then Stage 1 goes to selectiv only.

**Phase 1: the PHP node, accepting both.** `./deploy.sh <ref> selectiv`,
run from a checkout of `<ref>` (the suite tests the working tree, so the
suite that passes is the code shipped); the switch stays off. Gates:

- (a0) `git merge-base --is-ancestor <the recorded commit> <ref>` succeeds,
  so the ref carries everything live there. `deploy.sh` SHOULD make this a
  refusal of its own, bypassed only by `DEPLOY_ROLLBACK=1`, which it records
  in `.deploy.log` like `DEPLOY_ALLOW_DIRTY`; a `/health` that names no commit
  stops the deploy for James to decide.
- (a) `./verify-live-stamp.sh <ref> <node>` passes.
- (b) `/health` shows `registration.version: 1`, `schema_migrated: true` and
  `enforce_signed_registration: false`. False means §12's objects are
  missing: roll back at once.
- (c) `tools/stage1_probe.py https://<host>/reticulum` passes, every answer
  within 5 s.
- (d) Nothing else moved: in `/health` the gateway's and the other PHP node's
  rows keep advancing `last_seen_at`, `rx_packets` and `tx_packets`;
  Retichat-js's `./verify-deploy.sh <live ref> <site>` passes (f54d7cd since
  2026-10-14; on selectiv a failure means the old `app.js` is back: redeploy
  the live ref before reading the rest, and before Phase 2); and the live
  page loads and turns green.

**The swap's seconds.** `deploy.sh` renames `lib/` before the top-level
files, and opcache may recheck each file on its own clock (`revalidate_freq`,
2 s by default), so for milliseconds, or up to about 2 s, a request can run
Stage 1's `index.php` with today's `lib/` or the reverse. Either is a fatal
error, answered `500`, since Stage 1 moves `registerInterface` and
`authenticateInterface` between traits. Browsers and gateways take a `5xx`
as a failure and come back at their next cycle, and no data is damaged.
Accepted (the review of stage1-sign, 2026-10-14): an `index.php` check of a
release constant in `lib/` would answer `503` instead, which changes nothing
for a client. The manual rollback `deploy.sh` prints (`cp -r
~/reticulum-rollback/*`) has the same seconds.

**Phase 2: the browser signs.** Retichat-js to selectiv the same day its PHP
node passed Phase 1, so that legacy tabs, §9's cost and §16 item 3 last
hours, not days. Gates: (a) Retichat-js's `./verify-deploy.sh <ref> selectiv`
passes byte for byte, and again hours later, since a foreign `app.js` has
replaced verified deploys there before (below); (b) a fresh load registers
signed and turns green, its console shows no §1 line from §6's assertions,
and `/health` shows `browsers_online.signed` of at least 1; (c) the same
identity opened in a second browser profile makes the first page show §8's
message and stop. **What it costs**, once per identity per PHP node: the
first signed registration makes a new row and removes the legacy one (§4.5);
the page's announce, sent as it registers, makes the local destinations and
paths again; packets queued on the old row at that moment are dropped; old
tabs of the identity elsewhere get `401`, then `403
identity_requires_signature`, and show offline until reloaded, each asking
again every 5 s while it runs (logged once per count, §11). §4.5's `DELETE`s
run on a node's database once at the probe's first run there (§17.3), and
then for every user at Phase 2; a failure costs no session (§4.5) and is
logged `failed=`.

**Verify often** (James, 2026-10-14: "Go ahead, verify often
(Recommended)", open question 1). A page served with selectiv's foreign
`app.js` cannot sign and never turns green (§10), so while that file is
served every selectiv user is offline. Retichat-js's `./verify-deploy.sh
<ref> selectiv` runs after each deploy to selectiv, again hours later,
whenever a selectiv tab shows offline and whenever `/health`'s
`hash_only_challenges` rises (§12); when it fails, the ref is deployed
again. The search for the file's source goes on, including other machines
that deploy there.

**Phase 3: enforcement, on James's date.** On selectiv, a hand edit of its
config: `enforce_signed_registration = true`. Before it, the same day,
Retichat-js's `verify-deploy.sh` shows a signing build on the sites that use
that node, and `/health`'s `browsers_online` is read, for James's judgement
only. Gates: `/health` shows `enforce_signed_registration: true`;
`tools/stage1_probe.py --enforced` passes; a signed page still loads green.
Old tabs still open get `401`, then `403 signature_required`, and ask again
every 5 s while they run (logged once per row, §11).

**Rollback of a PHP node.** It goes back to the commit recorded before its
Phase 1, never to b6c7809 or any commit without 2b2ad9c: by `deploy.sh`'s
rollback copy if Stage 1's deploy was the node's last (then
`./verify-live-stamp.sh <recorded> <node>`, since the copy carries the old
stamp), otherwise by `DEPLOY_ROLLBACK=1 ./deploy.sh <recorded> <node>`. Old
code ignores the new columns, indexes and the switch; a signed session keeps
working (old code compares only the token); a browser that registers again
meets `404` at the challenge and registers the legacy way, into a new row,
since no Stage 1 row keeps `identity_hash` in its metadata. The UNIQUE index
never conflicts, since old code never writes `identity_hash`. The rollback
reopens A1, A3, A6 and A8 on that node. Going forward again, the objects are
already there; a legacy row old code wrote for an identity that has signed
here gets `401` at its first exchange (§7 step 3), so a Stage 1 page signs at
once and an old page shows offline until reloaded; a device still holding the
signed row's older token gets `409`.

**The browser goes back only with its PHP nodes.** After Phase 2, a page that
cannot sign must never be served to a site whose pages register at a PHP
node that holds signed rows: §4.6 step 4 refuses it (step 2 with the switch
on), signed rows survive every code and switch change, and an old page answers
the `403` with a red dot, no reason, and a new registration every 5 s that a
reload does not end. Turning the switch off does not undo step 4. So a
browser problem after Phase 2 is fixed forward, or rolled back in this order:
first every PHP node the site's pages register at (the one in `config.json`,
and the other host's for users who saved its URL in Settings, which the CSP
allows), so Stage 1 pages get `404` at the challenge and register the legacy
way; then the browser goes back to the live ref recorded before Phase 2. Forward again goes the other way,
browser first: a node that went first would refuse every old page of an
identity that had signed. Deleting signed rows with the node secret (§12) is
no browser-only rollback, since a Stage 1 tab still open answers its `401` by
signing again at count 0. A browser-only rollback would need James's
decision (a new switch, or dropping §4.6 step 4 at question 2's cost); this
file offers none.

## 14. Required tests

Each fails before its fix and passes after (§10 of the principles). "Today"
is the live code, read from both nodes on 2026-10-14: Reticulum-post 50c870b
(b6c7809's registration code with 2b2ad9c's logging fix) and Retichat-js
f54d7cd. A test that waits does so on an event,
with a bound that only fails it.

**Reticulum-post** (real traits; SQLite in memory, or `php -S`):

- **`signed_registration_test.php`:** the challenge (no count, its `400`s);
  an INSERT at count 0 and a re-bind in place (same `interface_id`, new token,
  previous hash); a replay, the other node's challenge and a lost bind race
  `409`, the race leaving one row; a tampered field `403`; a body without a
  valid signature over a challenge whose count has since moved `403`, not
  `409`; an `audience` key, a low-order key, `bitrate` 2^31, a 65-byte or
  numeric `implementation` and a `transport` of `5` `400 bad_registration`;
  signed `reticulum-php` and `rns-post-interface` `400 unknown_client`; no
  refusal writes anything, not even the node secret; the answer has no
  plaintext token or count; a bind whose §4.5 removal fails still answers its
  encrypted token and logs `failed=`. *Today:* no challenge; a body with
  `registration` gets a plaintext token.
- **`registration_vectors_test.php`:** §15's browser vectors through the real
  code, the encrypted token byte for byte; it names each vector it skips.
  *Today:* no signed path.
- **`session_superseded_test.php`:** after a signed re-bind the old token
  gets `409` with §8's message, and so do tokens two and three re-binds old
  and a random token on that row; only the immediately previous token is
  logged, once per row per token, also under seven case variants of the id
  with a case-folding collation. A legacy browser re-bind gives the replaced
  token `401`, stores no previous hash, and the replaced holder's next legacy
  registration takes the row back; a gateway's legacy re-bind still `401`;
  an unknown interface `401`. The switch on: a legacy browser row `401`, a
  signed row unaffected. *Today:* every replaced token gets `401`.
- **`registration_rebind_rules_test.php`:** a legacy claim of a signed
  identity, `'%'` and `'_%'` never touch the signed row (A1); a legacy
  `rns-post-interface` registration naming a browser's identity hash makes its
  own row (A8); no identity field in `metadata_json`; legacy rows claiming an
  identity that signs are removed with their traffic; legacy mode 3, 5 or 6
  `400`, in every spelling the runtime reads as one (`6.0`, `"6.0"`, `" 6"`,
  `"6abc"`, `"+6"`, `5.0`, `"3 "`), at registration and at a re-bind, and the
  modes accepted are stored as the integer the runtime reads; a legacy re-bind
  whose `UPDATE` a signed registration's §4.5 overtook answers `403
  identity_requires_signature` (and, with no signed row, makes a new row), never
  `200` for a gone row; the switch refuses legacy browsers only. With the switch off, a
  legacy row claiming a signed identity (written as old code writes it, with
  `H` only in `metadata_json`, and with the claim filled) gets `401` with its
  own token, with nothing written but the claim, and the next signed
  registration removes it (`[REG-RETIRE] rows=1`); a legacy row of an
  identity that never signed still gets `200`. N legacy registrations
  claiming a signed identity log one `[REG-REFUSED]` line and write once; a
  new signed registration allows one more; with the switch on, one per legacy
  row. No SQL in `php/src` compares
  `metadata_json` with a value from a request: the test finds every
  comparison on `metadata_json` (`LIKE`, `=`, `IN` or a JSON function) and
  allows exactly one, `recentNodeInterfacesByStatus`'s `LIKE :poll_gateway`,
  bound to a constant (§12). *Today:* A8 re-binds the browser's row; mode 6
  is accepted; the old-code row gets `200`; every refusal is logged; the scan
  finds `interfaceByIdentityHash`'s `LIKE :hash_pattern`.
- **`announce_row_identity_test.php`:** a victim's announce replayed through
  another browser row, signed or legacy with a made-up claim, moves neither
  its local destination nor its packets; a legacy row gets no local
  destination for one held elsewhere or seen; a dropped announce leaves
  `known_destinations` untouched and is neither cached nor forwarded; a
  `CACHE_REQUEST` for a legacy browser row's own earlier announce, which §9
  now finds seen, queues no announce on any row (no `relay_announce`), and
  its verdict is `miss`; a `CACHE_REQUEST` for a copy whose row §4.5 removed
  is a miss that queues nothing and makes no path, while a path request is
  answered from that copy as before; a row registered after a refused copy of `D`'s
  announce is seeded with `D`'s last accepted copy, not the refused one; a
  browser's own announces still make local destinations; a gateway row's
  behave as today. A stated residual (§16 item 3): once the stale sweep has
  removed the path through a peering row, an older announce through a legacy
  row claiming the identity makes a local destination there, while the newest
  remembered one is refused. *Today:* the replay moves the local destination;
  the cache replay is relayed to every other row.
- **`registration_http_test.php`** (`php -S`): the challenge by GET and POST
  with `no-store`; `hash_only_challenges` moved by a POST by hash, not by key
  or GET; `{error, message}` bodies; the answer as sent; `/exchange`, `/tx`,
  `/poll`, `/goodbye` answer `409` and `401` as §7 says, register and
  challenge never; no log line holds a token, signature, challenge or the
  secret. *Today:* no challenge route.
- **`schema_migration_lock_wait_test.php`** (new; a recording connection
  standing in for MySQL, since the suite has none): on `mysql`, the session's
  `lock_wait_timeout` is read, set to 2 before the first DDL statement and put
  back after the last; each table's missing columns are one `ALTER` with
  `ALGORITHM=INSTANT`, each index `ALGORITHM=INPLACE LOCK=NONE`; a re-run
  issues no `ALTER` and no `CREATE INDEX`; a `1205` on a statement stops the
  migration there with no retry, records no version, and `index.php migrate`
  exits `1` with its line; SQLite gets none of it. Reclaim's `OPTIMIZE TABLE`
  runs under the same ceiling.
- **`schema_migration_marker_test.php`** (extended): §12's objects, the
  UNIQUE index enforced, the backfill (idempotent, `rns-js` only), the claim
  filled at first authentication, a 50c870b database migrated cleanly. With
  `schema_meta` holding the SHA-1 of the deployed trait file (what old cached
  code writes after a swap), `migrateIfNeeded()` still builds §12's objects;
  an older version recorded migrates, its own skips; `schema_migrated` false
  before and true after, and false after one failed statement or with the
  UNIQUE index missing. The CLI migrate mode builds every object on a 50c870b
  database and records nothing, and a `migrate()` after it adds nothing. The
  guard on (version, masked trait hash). *Today:* the fingerprint is the
  file's SHA-1, and the seeded case skips the migration.
- **`health_allowlist_test.php`:** §12's object, and still no identity hash,
  token or browser row. *Today:* no `registration`.
- **`clear_all_data_test.php`:** `clearAllData()` empties `transport_state`
  and `interfaces` (passes today: it pins); with a SQLite trigger failing only
  the `transport_state` `DELETE`, `monitor.php`'s clear leaves `interfaces`
  alone. *Today:* it goes on.
- **`deploy_never_mixes_releases_test.php`** (extended): a failing pre-swap
  migrate stops the deploy with nothing swapped and the stamps and rollback
  copies unchanged; a ref without the migrate mode skips the step; a ref that
  does not descend from the node's commit is refused without
  `DEPLOY_ROLLBACK=1`. *Today:* no such step.
- **`unique_named_placeholders_test.php`** (extended): it scans (a) the
  literal text of every `->prepare(` argument, read with `token_get_all`
  (inline, concatenated, and wrapped by `insertOrSql` or `upsertSql`), each
  ternary branch apart; (b) today's `$var =` … `->prepare($var)` blocks, for
  statements built with `.=`, without gating on `looksLikeSql()`; and (c)
  every string under `php/src` that holds a named placeholder, array
  elements included, or it fails on a `->prepare($var)` it cannot resolve.
  Self-tests, each failing today: §8's compare-and-swap written inline with
  one placeholder twice; an inline concatenation; a wrapped literal; a
  statement array prepared in a `foreach`. The 2026-09-23 and ternary
  self-tests stay. *Today:* the scanner passes all four.
- **Extended as they are:** `deadlock_retry_coverage_test.php` and
  `no_backslash_in_sql_literals_test.php` cover the new trait and SQL;
  `interface_identity_rebind_test.php` (3281ad5's hotfix) and
  `wake_url_path_removed_test.php` read a claim from `claimed_identity_hash`.
  Every other test stays as it is.

**Retichat-js:**

- **`post_interface_signed.test.mjs`:** challenge, sign, decrypt; one more
  round after `409 stale_challenge`, and a stop with its own text after a
  second; a registration abandoned by `check()` that binds between the new
  challenge and the new registration still connects, with no stop;
  Superseded stops with its message and sends nothing more; terminal codes
  stop with no backoff; each stop emits `stopped` once, also after a
  network failure then `409` Superseded, and after a `401` then two `409
  stale_challenge`; a challenge `404` leads to the legacy registration; a
  `401` registers signed at once, and a `401` on that new session's first
  exchange stops; a bad token or another `identity_hash` stops; a page with
  only a hash registers legacy on `404` and otherwise stops "out of date";
  §6's assertions with a test clock, the keepalive goodbye included, each
  answer still deciding. *Today:* no challenge; a plaintext token is read.
- **`post_interface_backoff.test.mjs`:** with a test clock, consecutive
  failures (a network failure, a 5xx, a 4xx on an exchange that §10 does not
  list), on the challenge, the registration or an exchange, wait 2, 4, 8 … s
  before the next attempt, capped at 300 s; a successful exchange resets the
  wait to 2 s, and so does a successful registration; an `online`, `visible`
  or `pageshow` event makes the next attempt at once and leaves the backoff
  where it was, so a failure after it waits the next step; a `401` registers
  again at once with no backoff; terminal codes stop with no backoff.
  *Today:* every wait is 5 s.
- **`registration_vectors.test.mjs`:** `signRegistration()` reproduces
  `browser-first`'s and `browser-reregister`'s bytes and signatures, their
  tokens decrypt, and both `tokens_negative` fail, against a copy of the
  vector file whose SHA-256 the test pins. *Today:* no `signRegistration()`.
- **A page test** (like `exchange_truth.test.mjs`): `app.js` gives the
  interface `IdMgr.id` in the trailing options argument, the third staying
  the hash string; a stop's reason shows under the status dot, survives a
  re-render, and is not replaced by a later `down` or `up`. *Today:* it
  passes `IdMgr.hash`, and `down` only sets "offline".
- **`exchange_url_policy.test.mjs`:** `EXCHANGE_PATHS` has
  `/v1/interfaces/challenge`, which `.htaccess` allows on both nodes.
  *Today:* the path is missing.

**Harness scripts for private staging** (Phase 0):

- **`stage_takeover`:** the A1, A3 and A6 probes against an identity that
  has signed succeed on today's code (50c870b) and fail on Stage 1.
- **`stage_signed_browser`:** harness browsers register signed and exchange
  direct and propagated messages; three contexts of one identity settle on
  the newest, in any order; a superseded context shows §8's message and
  stops, and its goodbye then changes nothing; a context two registrations
  stale, woken by a `visible` event, shows §8's message and never registers.
- **`stage_mixed`:** an old page (`staging.sh export Retichat-js f54d7cd`
  and `HARNESS_WEB_ROOT`) beside a Stage 1 page. A stranger's legacy re-bind
  of the old page's row is undone at that page's next exchange. Once a Stage
  1 page of identity X has signed, an old page of X gets `403
  identity_requires_signature` and asks again every 5 s, logged once. With
  the switch on, an old page gets `401`, then `403 signature_required`, and
  the signed one goes on.
- **`stage_rollback`** (`STAGING_PHP_FRESH=0 STAGING_PHP_REF=<ref>
  staging.sh up` keeps the database across refs): a signed page connects; the
  node is served from today's code (50c870b) and the page reloads (challenge `404`, legacy
  registration); the node is served from Stage 1 again, and the page's next
  exchange gets `401`, it signs, `[REG-RETIRE] rows=1` is logged, its
  announce makes its local destination and a direct message reaches it. Then
  §13's rollback of node and browser in its order, and forward again browser
  first, with the identity reachable after each step.

Each script waits on events (log lines, page events), never on a sleep, and
they run one at a time.

## 15. Vectors

`php/tests/vectors/registration_vectors.json`, format 6, SHA-256
`7d2bcfee1742a6421a05e2b212c04182cc94247d53128ad91d35139fb07304ef`, made by
`tools/registration_vectors.py` from RNS 1.5.2 and checked independently by
`tools/check_registration_vectors.php` (384 checks). Stage 1 changes no byte:
no address is signed (§4.2). It pins the `identities` `browser`,
`other`, `lowx` and `gateway` (only to fail decrypting a browser's token);
`relays.A` and `relays.B` (node secrets); the `challenges` of `browser`,
`other` and `lowx`; the `registrations` `browser-first` (count 0 → 1) and
`browser-reregister` (1 → 2, a non-ASCII name); both `tokens_negative`; and
fourteen `negative` vectors, each failing the check of §4.3 it names:
`tampered-name`, `tampered-bitrate`, `wrong-key-signature`,
`replay-after-success`, `other-relay-mac`, `challenge-for-other-identity`,
`altered-challenge-nonce`, `identity-hash-mismatch`, `unsigned-metadata`,
`uppercase-public-key`, `browser-transit-mode`, `browser-with-peer-url`,
`unknown-client`, `low-order-x25519-key`. The tools' reference verifiers
check the challenge before the signature, revision 10's order; no negative
fails both checks, so §4.3's order changes no outcome.

Stage 2 pins the rest: the gateway and PHP-node registrations and negatives,
`registration-capacity` (Stage 1 has no cap), `url_canonical`,
`gateway_confirm` and `php_relay_peer`. The file and its tools cite
REGISTRATION.md revision 8's section numbers, which REGISTRATION.md §18 maps.
Both checks run before every commit that touches the protocol.

## 16. Residual risks until Stage 2

Stage 1 closes, for browsers: A1 (re-binding a browser's row by posting its
identity hash, which any announce reveals) and A6 (replaying a victim's
announces through a row with a made-up claim), for every identity that has
signed at that PHP node and for all once the switch is on; and at once A3
(replaying a victim's signed announce through one's own browser row), A7 (a
signed registration inheriting a legacy row that claimed its identity), A8
(claiming a browser's identity under another `client`) and A13 (what a
challenge or a refused signed registration reveals about the row: nothing,
§3, §4.3). It closes them at selectiv only: retichat.com's PHP node keeps
today's code until MySQL 8.4 is proven (James, 2026-10-14: "selectiv only,
for now", §13), so there it closes none of them yet, and item 3's takeover
stays as today for every user. What stays exposed:

1. **Gateway and peering rows are re-bound by their address (A5).** Anyone
   can POST an unsigned `reticulum-php` registration naming the live
   gateway's `peer_url` or the other PHP node's `host_url`, and take the row
   with a new token. The real one gets `401`, registers again and takes it
   back, and the two alternate; meanwhile the stranger collects what was
   queued there (end-to-end encrypted: delivery denied, metadata seen). As
   today, until Stage 2 (gateways) and Stage 3 (peering).
2. **Anyone can still make an unsigned `reticulum-php` or
   `rns-post-interface` row.** Its announces skip §9 (they never make local
   destinations, as today), can move paths with a lowered hop count (A4), and
   are forwarded under this node's transport id at least every 300 s; its
   wakes go to whatever address it named (A15), before the answer of
   whichever request runs the wake pass, a browser's exchange included (A11,
   §2). Rows of other `client` values keep today's rules too. Until Stage 2.
3. **Legacy browser rows (A1), until the identity signs at that PHP node,
   and for all until Phase 3.**
   - Anyone who knows a user's identity hash (any announce of theirs reveals
     it) can send one legacy registration claiming it. That re-binds the
     user's legacy row in place (§4.6 step 5), with no key and no announce.
     The row keeps its `interface_id`, so the stranger's session takes over
     its local destinations, the paths through it and its queued packets, and
     collects what the PHP node delivers there while the row holds them
     (end-to-end encrypted: delivery denied, metadata seen).
   - As today, and as in item 1, the two alternate: the user's page gets
     `401`, registers again at once and takes the row back, and the stranger
     holds it only by registering again.
   - After Phase 2 the user's reload signs and ends it: §4.5 removes the row,
     and a later legacy claim gets `403 identity_requires_signature`. During
     Phase 1, and at retichat.com's PHP node, which keeps today's code until
     MySQL 8.4 is proven (§13), the reload re-binds the row the legacy way,
     and one more request takes it again.
   - Separately, any identity that has not signed at that PHP node, every
     native user included, can be given a local destination on a stranger's
     legacy row whenever the node holds no local destination or usable path
     for it: never reached, swept, expired or pruned (§9). Any captured
     announce of that identity works except the newest the node remembers. It
     lasts until the destination's next announce reaches the node another
     way, and can be repeated after every quiet spell. Until Stage 2, item 2's
     A4 already lets anyone take such a destination's path at will through an
     unsigned `reticulum-php` row, so this is a second route, not new reach;
     once Stage 2 closes A4 it is the route left until Phase 3, which bears
     on James's Phase 3 date. A record no clock removes (the newest emission
     time accepted per destination) would close it; that is left for Stage 2.
4. **An existence oracle, until Phase 3.** A legacy registration claiming `H`
   gets `403 identity_requires_signature` if `H` has ever signed at this PHP
   node (a signed row is never deleted), and `200` otherwise. So anyone can
   learn, for any identity hash, whether its owner has used a signing web
   page here. Which identities are browsers here right now is already
   visible to every browser registered here, through the announces the PHP
   node relays to all its rows and the 64 most recent it sends a new row; the
   oracle adds only that its answer lasts and can be asked at any time. The
   signed path gives no such answer (§4.3). The distinct `403` stays: a `200`
   would give an old tab of a signed identity a green dot while §9 refuses
   its announces.
5. **Rows are unbounded (A14).** Signed rows, like legacy rows today, are
   never deleted by the code. A legacy row of any client costs one request
   and no key (a legacy registration with no matching claim INSERTs one); a
   signed row costs two cheap requests and a fresh key. A cap on browsers
   alone would let a flood of unsigned gateway rows lock new browsers out, so
   the cap waits for Stage 2, which can cover every client. Deleting signed
   rows by hand needs the secret rotated (§12). Every refusal is logged (an
   old page's repeated `403`s once per row or count, §11), so a stranger can
   grow the error log, as malformed claims already can.
6. **A12, accepted by James on 2026-10-14** (open question 5): "the verdict
   was to rely on Reticulum's security for PHP nodes. A compromised node
   still can only manifest as a black hole. It can't actually manipulate the
   messages. This is a standard risk of Reticulum." The PHP node a
   page uses could fetch another PHP node's challenge for the user's key,
   have the browser sign it and forward the body. The other node then binds
   the identity there, and the identity's own session there gets `409`; and
   since the browser sends the decrypted token to the node it registered
   through at every exchange, the forwarder holds the identity's session at
   the other node and can take its inbound there (delivery denied, metadata
   seen, payloads end-to-end encrypted). The encrypted token does not change
   this (§5). Today nobody can choose a PHP node but James's two (the web's
   CSP `connect-src` allows only the page's origin and the two hosts'
   `/reticulum/`), so this needs one of them compromised. His answer rests on
   Reticulum's security, not on that, so no test pins `connect-src` to the
   two hosts, and no address is signed, now or in a later version of the
   browser's registration (§4.2).
7. **Unchanged by Stage 1:** a restored database backup brings back an old
   secret and old counts, so each captured body in that range replays once
   (its replayer cannot decrypt the token; the session it supersedes is told
   so), and a browser whose row came back holding an older token is told
   Superseded and must reload, where today it registers again unseen; a valid
   replayed announce can roll back a remembered ratchet through a row §9 does
   not cover, as RNS 1.5.2 remembers every valid copy; and the stale sweep
   still decides by a clock whether a browser row is active.

## 17. Implementation delta

### 17.1 Reticulum-post

The implementation branch `signed-registration` (a65be65: 18 commits on
d828e0a, built against REGISTRATION.md revision 5) predates e3c05ea, b6c7809
and 2b2ad9c: it still carries the `wake_url` path and the TCP bridge that
main has removed, and the guarded `$this->log()` calls that 2b2ad9c made
`error_log()`. Start a new branch from main at c37b08f or later (it carries
2b2ad9c, live on both nodes, and its stricter static check) and carry these
over by hand; do not rebase. Take 8248c2d's change to
`processAcceptedAnnounce` (`request_control_plane_trait.php`) as hunks, never
as the branch's whole file.

| Commit | Stage 1 keeps | Stage 1 drops |
|---|---|---|
| f7a9353 | `registration_protocol.php` (`lp`, `u64be`, the identity hash, the challenge's MAC, `signedBytes`, `encryptToken`); from `request_registration_trait.php`, `issueChallenge` and the secret, `registerFromBody`, `signedBodyHasShape`, `registerSigned`, `retireSquattedRows`, the legacy browser path on `claimed_identity_hash` (without its write of `previous_session_token_hash`), `authenticateInterface` (reworked as §7 says), `[REG-REFUSED]`; the challenge route; the `[registration]` switch; §12's columns and backfill; `monitor.php`'s `break` (that line only, not the three tables it adds to `$TABLES`); `registration_vectors_test`, `stubs/registration_fixture.php` | canonical `peer_url` and `peer_url_key`; `retireLegacyUrlRows` and every change to the legacy `reticulum-php` path; the nonce refusal; `enforce_signed_transit`, `allow_loopback_http_peers`, `max_interface_rows` and capacity; `peer_state`, `wake_url_confirmed_key`, `wake_outstanding`; the tables `peer_registration_nonces`, `peer_registration_pending`, `gateway_wake_confirms`; the `dispatchWakes` skip; `/health`'s per-row fields |
| 60b883a, 9f8bcfe, ef83be2 | their browser tests (§14), with `session_superseded_test` section (2)'s legacy `409`s (the `rns-js` one and the `reticulum-php` one) made `401`s; `config.template.toml`'s `[registration]`; the README's rule for deleting identity rows; `monitor.php`'s case, with a SQLite trigger in place of `DROP TABLE gateway_wake_confirms` | `peer_url_canonical_test`; the gateway, `enforce_signed_transit`, capacity and nonce cases; the `409` that f7a9353's `peer_session_rotation_test` expects for a legacy `reticulum-php` re-bind (it keeps today's `401`) |
| 2f169dc, 0fbc2bf, daff4a5 | all: `{error, message}` bodies, writes on `executeWithRetry`, the claim filled at first authentication | — |
| 8248c2d | §9 for browser rows (`request_announce_guard_trait.php`, its place in `processAcceptedAnnounce`); `replayCachedAnnouncePacket` relaying only `validated` or `path_updated` (main relays anything but `invalid`, so a refused replay would reach every other row); `cachedAnnounceRecordByPacketHash` skipping `refused` copies; its browser tests, `stubs/announce_fixture.php` | the rules for gateway and PHP-node rows ("transit by proof", "always active"), the seen-blob path rule, and their test changes |
| 21be17d, 2eed8c4 | the once-per-token log keyed on the row's own id (moved to `superseded_logged_hash`); the guard that stops a kept test's `php -S` | — |
| 744048d, c3eab2f, e8ec7b3, 7990c69, 69af93d, 3929fa9, 36d8e7f, a65be65 | — (36d8e7f's `stubs/trigger_pdo.php`, if a race test needs it) | all: the three tables, path rules, the address check, nonce peering, runners, wakes |

Nothing is kept dormant; Stage 2 takes its parts from the branch with its own
spec. **Changed** from the branch: only `rns-js` signs; no capacity step; the
signature is checked before the challenge (§4.3); a legacy browser re-bind
writes no previous hash, a signed row answers `409` to every token but its
own, and a legacy row whose identity has signed gets `401` (§7, §8); a bind
whose removal fails still answers (§4.5); §4.5's removal deletes nothing from
`wake_events` and runs on §12's indexes; the bind writes no wake column; the
schema version is a literal (§12); messages say "PHP node", never "relay";
other clients' legacy registrations run as on main, apart from §4.6's ignored
`identity_hash`. **New**, in no commit of the branch:
`refusal_logged_seq` and its rule (§11); `hash_only_challenges` and
`schema_migrated`'s probe (§12); the `migrate` CLI mode (which skips
`initializeRuntime`'s own `migrateIfNeeded()`), `deploy.sh`'s step and its
ancestry refusal (§13); `seedInterfaceWithCachedAnnounces` taking, for each
destination, its newest copy whose `announce_status` is `validated` or
`path_updated` (today the newest accepted packet, whatever its status, so a
refused copy would be seeded; §9); the extended placeholder scanner (§14).

### 17.2 Retichat-js (branch `stage1-sign`, from main f54d7cd)

- **`lib/rns/interfaces/post_interface.js`:** the constructor takes the
  identity (an object that signs and decrypts), or only a hash from an old
  `app.js` (§10). Registration becomes the challenge, `signRegistration()`,
  the registration, §5's decrypt and checks; one more round after `409
  stale_challenge`; §10's stops end the interface as `block()` does, report
  its packets lost and emit `stopped(reason)` once; `401` by status only, at
  most one registration per `401` (§7); §6's assertions; §10's backoff in
  place of the fixed 5 s wait (`RECONNECT_WAIT_MS`).
- **`app.js`:** `new PostInterface(name, url, IdMgr.hash, undefined, {
  identity: IdMgr.id })`. The third argument stays the hash string: an
  interface older than Stage 1 (f54d7cd) sends its third argument as
  `metadata.identity_hash` through `JSON.stringify`, and an Identity
  serializes its private keys, so a page running this `app.js` with an old
  lib (a rollback, `deploy.sh`'s lib-first copy, a cached module) would send
  them to the PHP node (review of 2026-10-14). The constructor refuses a
  third argument that is not a string or null. And a `stopped`
  handler: the reason kept as its own state with the status `stopped`, shown
  under the status dot by `_applyStatusDot` after every render (where
  `EXCHANGE_BLOCKED_NOTICE` is shown, never in `exchangeBlocked`), after which
  `up` and `down` are ignored. **`lib/connect_policy.js`:**
  `/v1/interfaces/challenge` joins `EXCHANGE_PATHS`. **`.htaccess`:**
  unchanged; its `connect-src` already allows `/reticulum/` on both nodes.
  §14's tests and the vector copy.

### 17.3 Tooling

- **`tools/stage1_probe.py`** (Reticulum-post, new), on `.venv/bin/python`
  (RNS 1.5.2) and `tools/registration_vectors.py`'s `signed_bytes` and
  `reference_decrypt`, with two test identities kept outside every repository
  (`~/.reticulum-post-probe/`, mode 0700). Given a node's base URL it checks
  `/health`'s `registration`; the challenge, asked by key, with `no-store`;
  while its first identity has not yet signed at that node, a legacy
  registration claiming it (`200`), whose session gets `401` once the
  signed registration has removed its row (§4.5's statements, run once on
  that node's database); a signed registration with no plaintext token, which
  decrypts; an exchange; a second and a third registration, after which the
  first and second tokens get `409 session_superseded` and the third `200`;
  the first body replayed
  `409 stale_challenge`; an unknown session `401`; a legacy claim of the
  second identity `200` and of the first `403 identity_requires_signature`
  (with `--enforced`, both `403 signature_required`); goodbyes. It times every
  request from send to answer and prints each step with its milliseconds,
  never a token; it cuts no request off and sends none again, and exits
  non-zero, naming the step, if any answer came after 5 s or any check
  failed. It re-binds the same two rows every run.
- **`staging.sh`** (`test-harnesses/staging/`): the four harness scripts of
  §14, and today's client (f54d7cd) served beside the working copy (`staging.sh
  export Retichat-js f54d7cd`, `HARNESS_WEB_ROOT`).
- **`deploy.sh`:** the migrate step and the ancestry refusal (§13), with
  their tests (§14).
- **MySQL 8.4 for the suite**, before retichat.com gets Stage 1, in the way
  open question 3 has still to settle: one database fixture for every PHP
  test (`RETICULUM_TEST_DB=sqlite|mysql|mariadb`), and `deploy.sh`'s suite
  step on SQLite and MySQL 8.4, refusing a red or missing MySQL run
  (REGISTRATION.md §22.5 (a), (b)).

## 18. Decisions

Times are UTC, from the session's record; none was recorded for the answers
of 2026-10-14. Where James picked an offered option, the question is quoted
as asked, "relay" included.

| When | What he was answering | James | Where |
|---|---|---|---|
| 2026-10-02 22:30 | (his own words, after asking "What is relay-takeover?") | "Browser signs its registration with its own identity key" | §2, §4 |
| 2026-10-02 23:18 | "The '%' wildcard bug lets anyone re-bind some browser's relay row right now, with no knowledge at all. Hotfix it immediately, ahead of the full signing work?" | "Hotfix now (Recommended)" (3281ad5, live) | §4.6 |
| 2026-10-02 23:18 | "Replay protection for a signed browser registration — how should the relay know a signature is fresh?" | "Can we do a standard challenge and signing?" | §3 |
| 2026-10-03 02:38 | "When two devices or tabs hold the same identity on one relay, the spec has the newest registration win and the older one stop with 'connected elsewhere' (instead of both evicting each other forever). OK?" | "Newest wins (Recommended)" | §8 |
| 2026-10-03 02:43 | "1. Sign the relay address the browser actually connected to (stops a rogue relay proxying your registration)?" | "Don't we have ssl to prevent spoofing?" A question, never answered: it was recorded as a decision a minute later. The 2026-10-04 00:41 report told him no address is signed and why, not that TLS leaves A12 open. Open question 5, which he answered on 2026-10-14 (the last row). | §4.2, §16 item 6, §19 |
| 2026-10-03 02:43 | "4. Separate enforcement switches for browsers and for gateways/relay peers?" | "Yes (Recommended)" | §13 |
| 2026-10-04 03:39 | "Should the session token still come back encrypted to the registrant's key, given HTTPS and single-use challenges already cover it?" | "Keep it (Recommended)". Its option text said the encryption "also covers the accepted case of a registration passed along by someone in the middle"; it does not (§5). It still guards against replays and copied answers, so the answer stands. | §5 |
| 2026-10-04 11:27 | "... May I start Docker Desktop and pull the official mysql:8.4 and mariadb:11.4 images from Docker Hub (about 1 GB together) to run the relay's tests on both before Phase 1?" | "Selectiv is the staging server" (not an approval of the download: open question 3) | §1.2, §13 |
| 2026-10-04 11:27 | "Should wakes move to background runners, as confirms already do?" | "Spawning a background process is heavy. Wakes should be as light as possible because it is mid exchange and there will be many of them to multiple connections. They should be sent and then forgotten as soon as possible without waiting for any response." | §2 (Stage 2) |
| 2026-10-04 11:27 | (answering another question) | "... I don't like the term "relay". Let's call it "PHP node". That distinguishes it from browser and gateway" | §1 |
| 2026-10-04 12:11 | the explanation of 11:57 UTC, which set out a registration's steps: challenge, register, the checks ("If the code is out of date, the connecting side fetches a new one and tries once more"), the bind that spends the count and removes unsigned rows claiming the identity, the answer with the token encrypted, the address check, then exchanges until a goodbye, a `401` or a `409` | "This all looks great." | §1, §3 to §8 |
| 2026-10-04 12:13 | why wakes went before the answer, and sending them after it | "Excellent. Let's continue as planned" | §2 (Stage 2) |
| 2026-10-05 14:49 | "How should the signed registration go forward?", offered as "Narrow the spec to Stage 1 (browsers sign), finish its few questions, then build, stage and deploy it. Gateways and PHP-node peering follow as Stages 2 and 3, each with its own spec and questions." | "Stages, browsers first (Recommended)" | this file |
| 2026-10-05 14:49 | "Fix the live peer-repair bug (the request that repairs a dead peering session fails with a 500) now, as its own small change?" | "Fix and deploy (Recommended)" (2b2ad9c, live on both nodes since 2026-10-05) | §2, §17.1 |
| 2026-10-14 | "selectiv's foreign `app.js` at Phase 2" (§19, question 1) | "Go ahead, verify often (Recommended)": option (b); (a) and (c) are not taken | §13, §16 item 3, §19 |
| 2026-10-14 | "An old tab whose announces the PHP node refuses" (§19, question 2) | "Accept it (Recommended)": option (a) | §9, §19 |
| 2026-10-14 | "How MySQL 8.4 is proven before retichat.com" (§19, question 3) | "selectiv only, for now": Phases 1 to 3 go to selectiv alone, and retichat.com's PHP node stays on today's code until MySQL 8.4 is proven; how it is proven stays open | §13, §16, §17.3, §19 |
| 2026-10-14 | "The browser's wait of 5 s" (§19, question 4) | "Back off 2 s to 5 min": option (b), now recorded in the principles' §3 | header, §2, §10, §14, §17.2, §19 |
| 2026-10-14 | "The browser's backoff (2 s doubling to 5 min) resets only on a successful registration. After a network drop the session is still valid, so the next attempt is an exchange, and a successful exchange wouldn't reset it: separate drops over hours would grow an open tab's wait toward 5 min. What should reset the wait to 2 s?" | "Any success resets it (Recommended)": a successful exchange or registration | §2, §10, §14, §19, the principles' §3 |
| 2026-10-14 | "Sign the address of the PHP node?" (§19, question 5) | "the verdict was to rely on Reticulum's security for PHP nodes. A compromised node still can only manifest as a black hole. It can't actually manipulate the messages. This is a standard risk of Reticulum." No address is signed. | §4.2, §14, §15, §16 item 6, §19 |

**This file's own choices**, which James may overrule:

- The challenge is stateless (§3); only `rns-js` signs in Stage 1, others get
  `400 unknown_client` (§4.3); `bitrate` and `mtu` stop at 2^31 − 1 (§4.3).
- The signature is checked before the challenge, so a request without the
  key learns nothing about the row (§4.3); the 11:57 explanation listed the
  code first.
- **A legacy browser re-bind keeps today's `401`, as a gateway's does**
  (§4.6, §8). An old page does not know `409`: with it, one unsigned request
  would leave a user's page offline with no reason until reloaded, while a
  stranger's session took its deliveries. The cost: two old pages of one
  identity keep evicting each other, as today, until they are reloaded onto
  the signing page; "Newest wins" then holds between signed sessions. If you
  want the `409` kept for legacy re-binds, §16 item 3 must say that a legacy
  takeover lasts until its victim reloads.
- A signed row answers `409` to every token but its own (§7, §8); a legacy row
  whose identity has signed here gets `401` (§7); a browser whose new
  session's first exchange gets `401` stops (§7).
- A removed legacy row's queue is dropped, not handed over, and a bind whose
  removal fails still answers (§4.5); legacy browser rows are also refused
  seen or held announces (§9); no cap on rows until Stage 2 (§16 item 5).
- Stage 1's writes stay on `Database::executeWithRetry`, like every other
  hot-path write, and changing the helper (dropping 1205; lock order) is its
  own change (§2, §4.4). The alternative: Stage 1's statements run once, so a
  deadlock answers `5xx` and the browser's backoff follows (§10).
- Logs through `error_log()`; a served log file holds Phase 1 on that host;
  §4.6's two `403`s logged once per row or count (§11, §13).
- `deploy.sh` builds the schema before the swap and refuses a ref that does
  not descend from the live commit (§13); `/health` counts challenges asked by
  hash (§12); a probe with test identities checks each node (§17.3).
- **New in revision 3:** an `online`, `visible` or `pageshow` event (today's
  code reconnects at once on all three) makes the browser's next attempt at
  once without resetting its backoff, so a failure after it
  waits the next step (§10). You decided the backoff (question 4), not this.
  The alternatives: the event also resets the backoff to 2 s, or the browser
  waits the backoff out, up to 5 min after its tab comes back. The
  principles' §3 states this with the backoff, so overruling it changes that
  text too.

## 19. Open questions for James

James answered all five on 2026-10-14 (§18). Each question is kept below as
it was asked, for the record, with his answer at its start. One thing stays
open: how MySQL 8.4 is proven before retichat.com gets Stage 1 (question 3's
candidates).

Questions 1 to 3 depend on each other: 3 decides whether retichat.com gets
Stage 1 at all, 1 what selectiv runs, and 2's cost lasts as long as 1 lets old
pages live. Read 3, then 1, then 2.

1. **Answered 2026-10-14:** (b), "Go ahead, verify often (Recommended)".
   Retichat-js's `verify-deploy.sh <ref> selectiv` runs after each deploy to
   selectiv, again hours later, whenever a selectiv tab shows offline and
   whenever `/health`'s `hash_only_challenges` rises; a failure means a
   redeploy; the search for the source goes on, including other machines
   that deploy there (§13). Options (a) and (c) are not taken.

   **selectiv's foreign `app.js` at Phase 2.** An `app.js` from 1 August keeps
   replacing verified deploys on selectiv (twice so far: 5 hours after one, 83
   minutes after another), from a source not yet found. It gives the connection
   only the identity hash, so it cannot sign. Once Phase 2 reaches selectiv,
   whenever it reappears its pages never turn green; the reason reaches only
   the console, and a reload serves the same file. `/health`'s
   `hash_only_challenges` rises (§12), and Retichat-js's `verify-deploy.sh
   <ref> selectiv` proves it.
   - (a) Hold Phases 2 and 3 on selectiv until the source is found. Meanwhile
     every selectiv tab stays legacy: those whose identity is also used on
     retichat.com or in a native app, yours included, keep a green dot while
     direct messages for them at selectiv go to the other device, and nothing
     on the page says so, for the whole hold (question 2); and every selectiv
     user stays open to §16 item 3. selectiv cannot try the signing browser
     before retichat.com, and with question 3 unanswered no site gets it:
     Stage 1 is then Phase 1 on selectiv alone, with §9's cost and none of
     the signing.
   - (b) Go ahead: run `verify-deploy.sh` after each deploy to selectiv,
     again hours later, whenever a selectiv tab shows offline and whenever
     `hash_only_challenges` rises; redeploy when it fails. While the old file
     is served, every selectiv user is offline.
   - (c) Let a page with no signing identity register the legacy way until
     Phase 3. It connects only identities that never signed at selectiv's
     node: everyone who loaded a verified page there since Phase 2, the
     identity Phase 2's gates use included, gets `403
     identity_requires_signature` (§4.6 step 4) and is as offline as under
     (b). Of the rest, those whose identity is also on retichat.com or a
     phone have question 2's cost until Phase 3; the others get a green dot
     on a page that calls `LXMF.senderNameFromFields`, gone from the lib,
     before storing each incoming direct message, so those messages are
     never stored and nothing says so. Such pages stay open to §16 item 3
     until Phase 3, and a new `app.js` that lost its identity would also go
     legacy unheard (§14's page test guards against that).

   **Recommendation: (b).** selectiv is the staging server and should run
   what production will run; (b)'s failure is visible and ends with a
   redeploy, while (a)'s loss is silent. Keep looking for the source,
   including other machines that deploy there.

2. **Answered 2026-10-14:** (a), "Accept it (Recommended)" (§9).

   **An old tab whose announces the PHP node refuses.** A legacy tab whose
   identity another row already holds (§9's "held": your native app, reached
   through the gateway, say) keeps a green dot, because its exchanges work.
   It still sends and receives propagated messages, but direct messages for
   its identity at this PHP node go to your other device, or, if you used
   this identity at the other PHP node before, to that node along the path
   this one learnt then, until that path expires
   (`path_expiry_default_seconds`, 7 days), and the page says nothing. It
   affects tabs loaded before Phase 2 and not reloaded since. A reload after
   Phase 2 cures it, except on selectiv: under 1(a) it lasts the whole hold,
   since selectiv then runs Phase 1 without Phase 2 or 3, and under 1(c) it
   lasts until Phase 3 for anyone served the old file, since a reload serves
   the same file. Only 1(b) keeps it to hours there. Phase 3 ends it.
   - (a) Accept it.
   - (b) Refuse such a tab: its registration, and its exchanges once a hold
     begins, get `403` with a new code. The old page then shows a red dot with
     no reason (no deployed page shows a refusal's message), tries again every
     5 s, and loses sending and propagated delivery until reloaded.

   **Recommendation: (a).** (b) takes everything from the tab and still tells
   its user only "offline".

3. **Answered 2026-10-14:** "selectiv only, for now". Stage 1's Phases 1 to
   3 go to selectiv alone; retichat.com's PHP node stays on today's code, and
   with it today's takeover risk (§16 item 3), until MySQL 8.4 is proven. The
   web client is one build on both hosts: at retichat.com the challenge
   answers `404`, so the browser registers there the legacy way (§13).
   **Still open: how MySQL 8.4 is proven.** The candidates now (the options
   below are as first asked): (a) a local MySQL 8.4 install on your Mac,
   which `deploy.sh` starts for the test run and stops afterwards; (b)
   Docker, as in the first option below (on 2026-10-07 you said "Don't build
   the docker testing", about load tests); (c) a MySQL 8.4 server you name,
   as in the second option below.

   **How MySQL 8.4 is proven before retichat.com.** Every test runs on
   SQLite, and the 2026-09-23 outage shipped past a green SQLite suite;
   afterwards "MySQL in the staging chain, and the PHP suite on both engines
   in deploy.sh" was agreed. selectiv proves MariaDB 11.4, not MySQL. Your
   "Selectiv is the staging server" answered the question about downloading
   the images, so it was not a yes.
   - (a) A `mysql:8.4` container on your Mac: start Docker Desktop and
     download the official image (several hundred MB). `deploy.sh` then runs
     the PHP suite on SQLite and on MySQL 8.4, and refuses to deploy on a red
     or missing MySQL run.
   - (b) Another MySQL 8.4 server that you name, with the same `deploy.sh`
     step.

   Either way, from then on every `deploy.sh` run, hotfixes and rollbacks by
   ref included, needs that MySQL 8.4 reachable or it refuses: with (a),
   Docker Desktop running on your Mac; with (b), your server up.
   `DEPLOY_SKIP_TESTS=1` stays the loud, logged bypass for an emergency (it
   skips the whole suite), and the rollback copy (§13) needs neither. Until
   you answer, Stage 1 goes to selectiv only. **Recommendation: (a).**

4. **Answered 2026-10-14:** (b), "Back off 2 s to 5 min". After a network
   failure, a 5xx, or a 4xx on an exchange that §10 does not list, the next
   attempt (challenge, registration or exchange) comes after 2 s, doubling,
   capped at 5 min, reset by any success, an exchange or a registration
   ("Any success resets it", asked the same day). An `online`, `visible` or
   `pageshow` event makes the next attempt at once without resetting it: this
   file's choice, which you may overrule (§18). `DESIGN_PRINCIPLES.md` §3
   records the backoff as a decided exception, with the one extra round after
   `409 stale_challenge` (§4.3). §2, §10, §14 and §17.2 follow it.

   **The browser's wait of 5 s.** After a network failure, a 5xx, or a 4xx
   on an exchange that §10 does not list, the browser waits 5 s before it
   tries again, or less if an `online` or `visible` event comes first
   (`post_interface.js:36-44`, after RNS's TCP client interface, which waits
   the same before reconnecting). That is a retry and a timer under the
   principles' §3, which records no exception for browsers. Today it follows
   a failed exchange or registration; Stage 1 adds the challenge (§10).
   (REGISTRATION.md open question 17.3.)
   - (a) Keep it, recorded as a browser exception in `DESIGN_PRINCIPLES.md`
     §3.
   - (b) Wait 2 s, then twice as long after each failure up to 5 min, reset
     by a successful registration, as the gateway's exception allows. A
     browser is never woken, so nothing else resets it.
   - (c) The only choice that fully follows §3: after a network failure or a
     5xx, stop and say why, and try again only on an `online`, `visible` or
     `pageshow` event, a reload or a reconnect. The cost: a few seconds of
     PHP node outage leave open tabs offline until their user comes back to
     them.

   Whichever you choose, §3 should also record the one extra round after
   `409 stale_challenge`, which you approved on 2026-10-04 (§4.3, §18): that
   asks you to record it, not to decide it again. Dropping that round instead
   would stop a tab whose own abandoned registration had landed, since an
   aborted request never says whether the PHP node took it. Answer before
   the build: (b) or (c) changes §10 and §14's tests in the same Retichat-js
   change. **Recommendation: (a).**

5. **Answered 2026-10-14:** no. "the verdict was to rely on Reticulum's
   security for PHP nodes. A compromised node still can only manifest as a
   black hole. It can't actually manipulate the messages. This is a standard
   risk of Reticulum." No address is signed, now or in a later version of the
   browser's registration; the vectors stay at format 6, and neither (b)'s
   test nor its version 2 registration comes (§4.2, §14, §15, §16 item 6).

   **Sign the address of the PHP node?** TLS proves which PHP node the
   browser reached. It does not stop the node the page uses from passing the
   registration on: that node (one of your two hosts, if compromised; later,
   someone else's) fetches another PHP node's challenge for the user's key,
   has the browser sign it and forwards the body. The other node then binds
   the user's identity there and supersedes the user's own session there, and
   since the browser hands its token to the node it registered through at
   every exchange, the forwarder holds the user's session at the other node.
   The encrypted token does not stop this (§5). In Stage 1 only a compromised
   retichat.com or selectiv can do it, and a compromised host already serves
   its own page's `app.js`; what A12 adds is takeover at the other host for
   users whose page connects through the compromised one (both sites have the
   same CSP), and any third party's node once `connect-src` widens. Your
   "Don't we have ssl to prevent spoofing?" (2026-10-03) was recorded as a
   decision; it was a question (§18).
   - (a) Sign it now: the signed bytes gain the host the browser connected
     to, which the PHP node compares with its configured `host_url` in
     canonical form, refusing a mismatch with a code of its own. The vectors
     go to format 7 (`browser-first` and `browser-reregister` regenerated),
     and REGISTRATION.md's "Stage 2 changes no byte" moves with them. Cost: a
     node behind a proxy that rewrites the host refuses every browser, which
     Phase 1's probe catches.
   - (b) Leave it unsigned while the web can reach only your two nodes,
     enforced by a test: `exchange_url_policy.test.mjs` fails if `connect-src`
     names any PHP node beyond the two hosts (§14). The address then comes in
     a version 2 registration before any other node can be chosen.

   **Recommendation: (b).** In Stage 1 the attacker must already control one
   of your hosts, which can do worse through its own page; (b) changes no
   byte, and its test turns "revisit it later" into a failing build. The
   advice on 2026-10-03 was to sign it, and signing costs most to add after
   the build.
