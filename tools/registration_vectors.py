#!/usr/bin/env python3
"""
Reference generator for the signed-registration test vectors.

The normative protocol is REGISTRATION.md at the root of this repository.
This script is its executable reference: it derives every byte of
php/tests/vectors/registration_vectors.json from fixed labels (no randomness),
using the RNS 1.5.2 Identity from the workspace .venv for keys, identity
hashes, Ed25519 signatures and Identity.decrypt, so the vectors are pinned to
the reference implementation rather than to any of the three ports.

Run from the workspace root:

    .venv/bin/python Reticulum-post/tools/registration_vectors.py          # (re)write the JSON
    .venv/bin/python Reticulum-post/tools/registration_vectors.py --check  # fail if the JSON drifted

Every vector is verified before it is written:

- each signature with RNS (Identity.validate, or the RNS Ed25519 key for the
  low-order identity), each identity hash against Identity.hash, each encrypted
  session token with Identity.decrypt;
- every positive and negative registration with this script's own reference
  verifier (REGISTRATION.md section 4.3, in its normative order), which must
  give the expected status and error;
- every canonical-URL example with this script's own function;
- the gateway wake-URL confirm (REGISTRATION.md section 9.8): the positive
  signature with RNS Identity.validate, every gateway refusal with this
  script's reference gateway handler, and every relay-side answer with its
  reference answer verifier;
- the PHP relay peer (section 10): its registration as an ordinary positive
  vector, its identity file, its token decryption and every decryption it
  must refuse with this script's reference decrypt, its confirm handler and
  the link-order examples;
- the PHP relay's transport id (section 10.2, revision 7): the identity
  file's hash with RNS Identity.from_bytes, and each packet put into
  transport through it with RNS Packet.unpack and Packet.get_hash.

--check additionally regenerates the file in memory and compares it byte for
byte with the committed copy.

tools/check_registration_vectors.php checks the same file independently with
PHP sodium/openssl, the primitives the relay will use, and its own copy of the
reference verifier and URL canonicalisation.
"""

import argparse
import copy
import hashlib
import hmac
import json
import os
import re
import sys

try:
    import RNS
    from RNS.Cryptography import X25519PrivateKey, X25519PublicKey, PKCS7, HMAC
    from RNS.Cryptography import Ed25519PrivateKey, Ed25519PublicKey
    from RNS.Cryptography.AES import AES_256_CBC
    from RNS.Cryptography import hkdf
except ImportError:  # pragma: no cover - environment guard
    sys.stderr.write("RNS is not importable: run with the workspace .venv (RNS 1.5.2)\n")
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.normpath(os.path.join(HERE, "..", "php", "tests", "vectors", "registration_vectors.json"))

REGISTER_DOMAIN = b"reticulum-post/register/v1"
CHALLENGE_DOMAIN = b"reticulum-post/challenge/v1"
LABEL_ROOT = "reticulum-post registration vectors v1"
CHALLENGE_LENGTH = 48
MAX_SAFE_INTEGER = 2 ** 53 - 1

# The twelve signed fields, in signing order (REGISTRATION.md section 3).
# Revision 3 removed "audience" (James, 2026-10-03: no Host binding).
SIGNED_FIELD_ORDER = [
    "domain",
    "challenge",
    "public_key",
    "name",
    "bitrate",
    "mtu",
    "client",
    "mode",
    "transport",
    "peer_url",
    "peer_interface_id",
    "peer_session_token",
]

REGISTRATION_KEYS = {"version", "public_key", "challenge", "signature"}
ALLOWED_METADATA_KEYS = {"client", "implementation", "mode", "transport", "peer_url",
                         "peer_interface_id", "peer_session_token", "identity_hash"}
KNOWN_CLIENTS = ("rns-js", "reticulum-php", "rns-post-interface")

HEX_RE = re.compile(r"[0-9a-f]+")

# The gateway wake-URL confirm (REGISTRATION.md section 9.8).
GATEWAY_CONFIRM_DOMAIN = b"reticulum-post/gateway-confirm/v1"
GATEWAY_CONFIRM_PATH = "/v1/gateway/confirm"
GATEWAY_CONFIRM_FIELD_ORDER = ["domain", "nonce", "identity_hash", "relay_url", "peer_url"]
GATEWAY_CONFIRM_KEYS = {"version", "nonce", "identity_hash", "relay_url", "peer_url"}


# ---------------------------------------------------------------------------
# Encoding primitives
# ---------------------------------------------------------------------------

def label_bytes(label, length=32):
    """Deterministic bytes for a label: SHA-512 of LABEL_ROOT + "/" + label, truncated."""
    full = hashlib.sha512((LABEL_ROOT + "/" + label).encode("utf-8")).digest()
    assert length <= len(full)
    return full[:length]


def lp(data):
    if len(data) > 0xFFFF:
        raise ValueError("lp field longer than 65535 bytes")
    return len(data).to_bytes(2, "big") + data


def u64(value):
    return int(value).to_bytes(8, "big")


def u32(value):
    return int(value).to_bytes(4, "big")


def u8(value):
    return int(value).to_bytes(1, "big")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_lower_hex(v, length):
    return isinstance(v, str) and len(v) == length and HEX_RE.fullmatch(v) is not None


# ---------------------------------------------------------------------------
# Canonical peer URLs (REGISTRATION.md section 10.1)
# ---------------------------------------------------------------------------

def canonical_url(u):
    """REGISTRATION.md section 10.1. Returns (canonical, None) or (None, reason)."""
    if not isinstance(u, str) or u == "":
        return None, "empty"
    if any(ord(c) > 0x7E for c in u):
        return None, "not_ascii"
    if any(ord(c) <= 0x20 for c in u):
        return None, "whitespace_or_control"
    if "?" in u or "#" in u:
        return None, "query_or_fragment"
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/]*)(.*)", u)
    if m is None:
        return None, "not_absolute"
    scheme, authority, path = m.group(1).lower(), m.group(2), m.group(3)
    if scheme not in ("http", "https"):
        return None, "scheme"
    if "@" in authority:
        return None, "userinfo"
    hm = re.fullmatch(r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?", authority)
    if hm is None:
        return None, "host"
    host = hm.group(1).lower()
    port = hm.group(2)
    if port is not None:
        p = int(port)
        if p < 1 or p > 65535:
            return None, "port"
        port = None if (scheme, p) in (("https", 443), ("http", 80)) else str(p)
    path = path.rstrip("/")
    if path.endswith("/v1/wake"):
        path = path[: -len("/v1/wake")].rstrip("/")
    return scheme + "://" + host + ("" if port is None else ":" + port) + path, None


def url_key(canonical):
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


# ---------------------------------------------------------------------------
# Identities (RNS 1.5.2)
# ---------------------------------------------------------------------------

def make_identity(name):
    x_prv = label_bytes("identity/" + name + "/x25519")
    e_prv = label_bytes("identity/" + name + "/ed25519")
    prv = x_prv + e_prv
    ident = RNS.Identity.from_bytes(prv)
    assert ident is not None, "RNS refused the vector private key"
    assert ident.get_private_key() == prv
    pub = ident.get_public_key()
    assert len(pub) == 64
    # Identity hash = SHA-256(x25519_pub || ed25519_pub)[:16]
    assert ident.hash == hashlib.sha256(pub).digest()[:16]
    return ident, {
        "private_key_hex": prv.hex(),
        "x25519_private_hex": x_prv.hex(),
        "ed25519_private_seed_hex": e_prv.hex(),
        "public_key_hex": pub.hex(),
        "x25519_public_hex": pub[:32].hex(),
        "ed25519_public_hex": pub[32:].hex(),
        "identity_hash_hex": ident.hash.hex(),
    }


class LowOrderIdentity:
    """An identity whose X25519 half is the all-zero point (low order).

    RNS cannot hold it as an Identity (there is no X25519 private key), but its
    Ed25519 half signs normally, so a registration by it passes every check
    up to the token encryption, which must fail."""

    def __init__(self, name):
        self.seed = label_bytes("identity/" + name + "/ed25519")
        self.sig_prv = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.ed_pub = self.sig_prv.public_key().public_bytes()
        self.x_pub = bytes(32)
        self.pub = self.x_pub + self.ed_pub
        self.hash = hashlib.sha256(self.pub).digest()[:16]

    def get_public_key(self):
        return self.pub

    def sign(self, msg):
        return self.sig_prv.sign(msg)

    def validate(self, sig, msg):
        try:
            Ed25519PublicKey.from_public_bytes(self.ed_pub).verify(sig, msg)
            return True
        except Exception:
            return False

    def describe(self):
        return {
            "private_key_hex": None,
            "x25519_private_hex": None,
            "ed25519_private_seed_hex": self.seed.hex(),
            "public_key_hex": self.pub.hex(),
            "x25519_public_hex": self.x_pub.hex(),
            "ed25519_public_hex": self.ed_pub.hex(),
            "identity_hash_hex": self.hash.hex(),
            "note": "X25519 half is the all-zero (low-order) point: the Ed25519 signature "
                    "verifies, but no session token can be encrypted to it.",
        }


# ---------------------------------------------------------------------------
# Challenge (REGISTRATION.md section 2)
# ---------------------------------------------------------------------------

def challenge_mac_input(identity_hash, seq, nonce):
    assert len(identity_hash) == 16 and len(nonce) == 16
    return CHALLENGE_DOMAIN + identity_hash + u64(seq) + nonce


def challenge_mac(relay_secret, identity_hash, seq, nonce):
    return hmac.new(relay_secret, challenge_mac_input(identity_hash, seq, nonce), hashlib.sha256).digest()


def make_challenge(relay_secret, identity_hash, seq, nonce):
    mac = challenge_mac(relay_secret, identity_hash, seq, nonce)
    challenge = nonce + mac
    assert len(challenge) == CHALLENGE_LENGTH
    return challenge, challenge_mac_input(identity_hash, seq, nonce), mac


# ---------------------------------------------------------------------------
# Signed bytes (REGISTRATION.md section 3)
# ---------------------------------------------------------------------------

def signed_field_values(body):
    """The twelve field values, as bytes, read from a register request body."""
    reg = body["registration"]
    md = body["metadata"]

    def opt_str(key):
        value = md.get(key)
        return b"" if value is None else value.encode("utf-8")

    return [
        ("domain", REGISTER_DOMAIN),
        ("challenge", bytes.fromhex(reg["challenge"])),
        ("public_key", bytes.fromhex(reg["public_key"])),
        ("name", body["name"].encode("utf-8")),
        ("bitrate", u64(body["bitrate"])),
        ("mtu", u32(body["mtu"])),
        ("client", md["client"].encode("utf-8")),
        ("mode", u8(md["mode"])),
        ("transport", opt_str("transport")),
        ("peer_url", opt_str("peer_url")),
        ("peer_interface_id", opt_str("peer_interface_id")),
        ("peer_session_token", opt_str("peer_session_token")),
    ]


def signed_bytes(body):
    fields = signed_field_values(body)
    assert [n for n, _ in fields] == SIGNED_FIELD_ORDER
    return b"".join(lp(v) for _, v in fields), fields


# ---------------------------------------------------------------------------
# Reference verifier (REGISTRATION.md section 4.3, normative order)
# ---------------------------------------------------------------------------

def _utf8_len(s):
    return len(s.encode("utf-8"))


def _valid_unicode(s):
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _opt_ok(md, key, max_bytes):
    if key not in md:
        return True
    v = md[key]
    return v is None or (isinstance(v, str) and _valid_unicode(v) and _utf8_len(v) <= max_bytes)


def _present(md, key):
    v = md.get(key)
    return isinstance(v, str) and v != ""


def verify_reference(body, relay, state):
    """relay: {secret}; state: {row_registration_seq, at_capacity}."""
    def bad(status, error, step):
        return {"status": status, "error": error, "step": step}

    reg = body.get("registration")
    md = body.get("metadata")
    # 1. Shape.
    if (not isinstance(reg, dict) or not isinstance(md, dict)
            or set(reg.keys()) != REGISTRATION_KEYS
            or not (is_int(reg.get("version")) and reg["version"] == 1)
            or not is_lower_hex(reg.get("public_key"), 128)
            or not is_lower_hex(reg.get("challenge"), 2 * CHALLENGE_LENGTH)
            or not is_lower_hex(reg.get("signature"), 128)
            or not (isinstance(body.get("name"), str) and body["name"] != ""
                    and _valid_unicode(body["name"]) and _utf8_len(body["name"]) <= 255)
            or not (is_int(body.get("bitrate")) and 1 <= body["bitrate"] <= MAX_SAFE_INTEGER)
            or not (is_int(body.get("mtu")) and 1 <= body["mtu"] <= 0xFFFFFFFF)
            or not (isinstance(md.get("client"), str) and md["client"] != ""
                    and _valid_unicode(md["client"]) and _utf8_len(md["client"]) <= 64)
            or not _opt_ok(md, "implementation", 64)
            or not (is_int(md.get("mode")) and 1 <= md["mode"] <= 7)
            or not _opt_ok(md, "transport", 64)
            or not _opt_ok(md, "peer_url", 512)
            or not _opt_ok(md, "peer_interface_id", 64)
            or not _opt_ok(md, "peer_session_token", 128)):
        return bad(400, "bad_registration", "shape")

    # 2. Only signed (or informational) metadata keys.
    if not set(md.keys()) <= ALLOWED_METADATA_KEYS:
        return bad(400, "unsigned_metadata", "metadata_keys")

    pub = bytes.fromhex(reg["public_key"])
    h = hashlib.sha256(pub).digest()[:16]

    # 3. metadata.identity_hash, if sent, is the key's own hash.
    if "identity_hash" in md and not (isinstance(md["identity_hash"], str)
                                      and hmac.compare_digest(md["identity_hash"], h.hex())):
        return bad(400, "identity_hash_mismatch", "metadata_identity_hash")

    # 4. Client policy (section 4.3.1).
    client = md["client"]
    if client not in KNOWN_CLIENTS:
        return bad(400, "unknown_client", "client_policy")
    if client == "rns-js":
        if md["mode"] in (3, 5, 6):
            return bad(400, "transit_mode_not_allowed", "client_policy")
        if any(_present(md, k) for k in ("transport", "peer_url", "peer_interface_id", "peer_session_token")):
            return bad(400, "metadata_not_allowed", "client_policy")
    elif client == "rns-post-interface":
        if any(_present(md, k) for k in ("peer_url", "peer_interface_id", "peer_session_token")):
            return bad(400, "metadata_not_allowed", "client_policy")
    else:  # reticulum-php (wake-mode gateway)
        if _present(md, "transport"):
            return bad(400, "metadata_not_allowed", "client_policy")
        if not all(_present(md, k) for k in ("peer_url", "peer_interface_id", "peer_session_token")):
            return bad(400, "peer_fields_required", "client_policy")
        if canonical_url(md["peer_url"])[0] is None:
            return bad(400, "peer_url_not_allowed", "client_policy")

    # 5. The challenge is this relay's, for this identity, at the row's current seq.
    ch = bytes.fromhex(reg["challenge"])
    expected = challenge_mac(relay["secret"], h, state["row_registration_seq"], ch[:16])
    if not hmac.compare_digest(expected, ch[16:]):
        return bad(409, "stale_challenge", "challenge")

    # 6. The signature, over bytes rebuilt from the received body.
    msg, _ = signed_bytes(body)
    try:
        Ed25519PublicKey.from_public_bytes(pub[32:]).verify(bytes.fromhex(reg["signature"]), msg)
    except Exception:
        return bad(403, "bad_registration_signature", "signature")

    # 7. Capacity (a new row only).
    if state["row_registration_seq"] == 0 and state["at_capacity"]:
        return bad(503, "registration_capacity", "capacity")

    # 8. The token must be encryptable to the key's X25519 half.
    try:
        eph = X25519PrivateKey.from_private_bytes(label_bytes("reference-verifier/ephemeral"))
        shared = eph.exchange(X25519PublicKey.from_public_bytes(pub[:32]))
        if shared == bytes(32):
            raise ValueError("all-zero shared secret")
    except Exception:
        return bad(400, "bad_registration", "token_encryption")

    # 9. Bind (modelled by the row's seq).
    return {"status": 200, "identity_hash": h.hex(), "registration_seq": state["row_registration_seq"] + 1}


# ---------------------------------------------------------------------------
# Gateway wake-URL confirm (REGISTRATION.md section 9.8)
# ---------------------------------------------------------------------------

def gateway_confirm_fields(body):
    """The five signed values, read from the confirm request body as received."""
    return [
        ("domain", GATEWAY_CONFIRM_DOMAIN),
        ("nonce", bytes.fromhex(body["nonce"])),
        ("identity_hash", bytes.fromhex(body["identity_hash"])),
        ("relay_url", body["relay_url"].encode("utf-8")),
        ("peer_url", body["peer_url"].encode("utf-8")),
    ]


def gateway_confirm_bytes(body):
    fields = gateway_confirm_fields(body)
    assert [n for n, _ in fields] == GATEWAY_CONFIRM_FIELD_ORDER
    return b"".join(lp(v) for _, v in fields), fields


def gateway_handle_confirm(body, ident, cfg):
    """The gateway's handler. cfg: {node_url, wake_url} as its config writes them."""
    return handle_confirm(body, ident, {canonical_url(cfg["node_url"])[0]}, canonical_url(cfg["wake_url"])[0])


def php_relay_handle_confirm(body, ident, cfg):
    """A PHP relay's handler (section 10). cfg: {host_url, interfaces_node_urls}."""
    relays = {canonical_url(u)[0] for u in cfg["interfaces_node_urls"]} - {None}
    return handle_confirm(body, ident, relays, canonical_url(cfg["host_url"])[0])


def handle_confirm(body, ident, relay_urls, own_url):
    """Section 9.8's handler checks, in their normative order.

    relay_urls: the canonical URLs of the relays this node registers at;
    own_url: the canonical URL it signs as its peer_url."""
    def bad(status, error):
        return {"status": status, "error": error}

    if (not isinstance(body, dict) or set(body.keys()) != GATEWAY_CONFIRM_KEYS
            or not (is_int(body.get("version")) and body["version"] == 1)
            or not is_lower_hex(body.get("nonce"), 32)
            or not is_lower_hex(body.get("identity_hash"), 32)
            or not (isinstance(body.get("relay_url"), str) and _valid_unicode(body["relay_url"])
                    and 0 < _utf8_len(body["relay_url"]) <= 512)
            or not (isinstance(body.get("peer_url"), str) and _valid_unicode(body["peer_url"])
                    and 0 < _utf8_len(body["peer_url"]) <= 512)):
        return bad(400, "bad_confirm_request")
    if not hmac.compare_digest(body["identity_hash"], ident.hash.hex()):
        return bad(403, "not_my_identity")
    relay, _ = canonical_url(body["relay_url"])
    if relay is None or relay not in relay_urls:
        return bad(403, "unknown_relay")
    peer, _ = canonical_url(body["peer_url"])
    if peer is None or peer != own_url:
        return bad(403, "not_my_wake_url")
    msg, _ = gateway_confirm_bytes(body)
    return {"status": 200, "body": {"signature": ident.sign(msg).hex()}}


def relay_verify_confirm_answer(sent_body, status, answer, public_key):
    """The relay's runner, after its POST: 'confirmed', or why not."""
    if status != 200:
        return {"result": "bad_answer", "reason": "status"}
    if (not isinstance(answer, dict) or set(answer.keys()) != {"signature"}
            or not is_lower_hex(answer.get("signature"), 128)):
        return {"result": "bad_answer", "reason": "shape"}
    msg, _ = gateway_confirm_bytes(sent_body)
    try:
        Ed25519PublicKey.from_public_bytes(public_key[32:]).verify(bytes.fromhex(answer["signature"]), msg)
    except Exception:
        return {"result": "bad_signature"}
    return {"result": "confirmed"}


def reference_decrypt(blob, x_prv, identity_hash):
    """A registrant's decrypt of session_token_encrypted (sections 5 and 10.4).

    Returns {"result": "ok", "session_token": ...} or {"result": <reason>}."""
    if len(blob) < 32 + 16 + 16 + 32 or (len(blob) - 32 - 16 - 32) % 16 != 0:
        return {"result": "malformed"}
    eph_pub, iv, ct, tag = blob[:32], blob[32:48], blob[48:-32], blob[-32:]
    try:
        shared = X25519PrivateKey.from_private_bytes(x_prv).exchange(X25519PublicKey.from_public_bytes(eph_pub))
    except Exception:
        return {"result": "zero_shared_secret"}
    if shared == bytes(32):
        return {"result": "zero_shared_secret"}
    derived = hkdf(length=64, derive_from=shared, salt=identity_hash, context=None)
    if not hmac.compare_digest(HMAC.new(derived[:32], iv + ct).digest(), tag):
        return {"result": "hmac"}
    try:
        pt = PKCS7.unpad(AES_256_CBC.decrypt(ciphertext=ct, key=derived[32:], iv=iv))
    except Exception:
        return {"result": "padding"}
    try:
        token = pt.decode("ascii")
    except UnicodeDecodeError:
        return {"result": "not_a_token"}
    if not is_lower_hex(token, 64):
        return {"result": "not_a_token"}
    return {"result": "ok", "session_token": token}


# ---------------------------------------------------------------------------
# Encrypted session token (REGISTRATION.md section 5): RNS Identity.encrypt
# with the ephemeral key and IV pinned so the bytes are reproducible.
# ---------------------------------------------------------------------------

def encrypt_token_deterministic(ident, plaintext, eph_prv, iv):
    eph = X25519PrivateKey.from_private_bytes(eph_prv)
    eph_pub = eph.public_key().public_bytes()
    shared = eph.exchange(ident.pub)
    derived = hkdf(length=64, derive_from=shared, salt=ident.get_salt(), context=ident.get_context())
    signing_key, encryption_key = derived[:32], derived[32:]
    ciphertext = AES_256_CBC.encrypt(plaintext=PKCS7.pad(plaintext), key=encryption_key, iv=iv)
    signed_parts = iv + ciphertext
    token = signed_parts + HMAC.new(signing_key, signed_parts).digest()
    blob = eph_pub + token
    # The pinned construction must be exactly what RNS Identity.decrypt accepts.
    assert ident.decrypt(blob) == plaintext, "RNS Identity.decrypt rejected the deterministic token"
    # And a fresh RNS Identity.encrypt of the same plaintext round-trips too
    # (sanity: same identity, same format, random ephemeral key and IV).
    assert ident.decrypt(ident.encrypt(plaintext)) == plaintext
    return {
        "plaintext_utf8": plaintext.decode("utf-8"),
        "ephemeral_private_hex": eph_prv.hex(),
        "ephemeral_public_hex": eph_pub.hex(),
        "iv_hex": iv.hex(),
        "shared_key_hex": shared.hex(),
        "hkdf_salt_hex": ident.get_salt().hex(),
        "derived_key_hex": derived.hex(),
        "hmac_key_hex": signing_key.hex(),
        "aes_key_hex": encryption_key.hex(),
        "session_token_encrypted_hex": blob.hex(),
        "length": len(blob),
    }


# ---------------------------------------------------------------------------
# Vector construction
# ---------------------------------------------------------------------------

def build():
    idents = {}
    identity_json = {}
    for name in ("browser", "gateway", "other", "relay_b"):
        idents[name], identity_json[name] = make_identity(name)
    idents["lowx"] = LowOrderIdentity("lowx")
    identity_json["lowx"] = idents["lowx"].describe()

    relays = {
        "A": {"relay_secret_hex": label_bytes("relay/A/secret").hex(),
              "description": "the relay every vector is presented to"},
        "B": {"relay_secret_hex": label_bytes("relay/B/secret").hex(),
              "description": "another relay; its challenges must be refused at A"},
    }
    relay_cfg = {k: {"secret": bytes.fromhex(v["relay_secret_hex"])} for k, v in relays.items()}
    secret = {k: v["secret"] for k, v in relay_cfg.items()}

    challenges = []
    challenge_by_id = {}

    def challenge(cid, relay, ident_name, seq, nonce_label=None):
        ident = idents[ident_name]
        nonce = label_bytes("nonce/" + (nonce_label or cid), 16)
        ch, mac_input, mac = make_challenge(secret[relay], ident.hash, seq, nonce)
        entry = {
            "id": cid,
            "minted_by_relay": relay,
            "for_identity": ident_name,
            "identity_hash_hex": ident.hash.hex(),
            "registration_seq_bound": seq,
            "nonce_hex": nonce.hex(),
            "mac_input_hex": mac_input.hex(),
            "mac_hex": mac.hex(),
            "challenge_hex": ch.hex(),
            "challenge_response": {
                "status": "challenge",
                "version": 1,
                "identity_hash": ident.hash.hex(),
                "challenge": ch.hex(),
            },
        }
        challenges.append(entry)
        challenge_by_id[cid] = entry
        return ch

    def body_for(ident_name, ch, name, bitrate, mtu, metadata, signer=None):
        ident = idents[ident_name]
        body = {
            "name": name,
            "bitrate": bitrate,
            "mtu": mtu,
            "metadata": metadata,
            "registration": {
                "version": 1,
                "public_key": ident.get_public_key().hex(),
                "challenge": ch.hex(),
                "signature": "",
            },
        }
        msg, _ = signed_bytes(body)
        sig = (signer or ident).sign(msg)
        body["registration"]["signature"] = sig.hex()
        return body

    def state(row_seq, at_capacity=False):
        return {"signed_row_exists": row_seq > 0, "row_registration_seq": row_seq, "at_capacity": at_capacity}

    registrations = []

    def positive(vid, description, relay, ident_name, row_seq_before, cid, body, session_token_label, eph_label, iv_label):
        ident = idents[ident_name]
        msg, fields = signed_bytes(body)
        sig = bytes.fromhex(body["registration"]["signature"])
        assert ident.validate(sig, msg), vid + ": RNS rejects the signature"
        assert len(sig) == 64
        st = state(row_seq_before)
        result = verify_reference(body, relay_cfg[relay], st)
        assert result.get("status") == 200, vid + ": reference verifier refused: " + json.dumps(result)
        assert result["identity_hash"] == ident.hash.hex()
        session_token = label_bytes("session_token/" + session_token_label, 32).hex()
        token = encrypt_token_deterministic(
            ident,
            session_token.encode("ascii"),
            label_bytes("ephemeral/" + eph_label, 32),
            label_bytes("iv/" + iv_label, 16),
        )
        new_seq = row_seq_before + 1
        assert result["registration_seq"] == new_seq
        registrations.append({
            "id": vid,
            "description": description,
            "relay": relay,
            "identity": ident_name,
            "relay_state_before": st,
            "challenge_id": cid,
            "challenge_request": {"public_key": ident.get_public_key().hex()},
            "request_body": body,
            "signed_fields": [
                {"name": n, "value_hex": v.hex(), "lp_hex": lp(v).hex()} for n, v in fields
            ],
            "signed_bytes_hex": msg.hex(),
            "signature_hex": sig.hex(),
            "expected": {
                "status": 200,
                "identity_hash": ident.hash.hex(),
                "relay_state_after": {"row_registration_seq": new_seq},
            },
            "response_example": {
                "status": "registered",
                "interface_id": label_bytes("interface_id/" + vid, 16).hex(),
                "identity_hash": ident.hash.hex(),
                "session_token_encrypted": token["session_token_encrypted_hex"],
                "idle_exchange_interval_ms": 1000,
                "max_batch_packets": 64,
                "max_packet_bytes": 500,
            },
            "encrypted_token": token,
        })
        return body

    browser_md = {"client": "rns-js", "implementation": "PostInterface", "mode": 1}
    gateway_wake_md = {"client": "reticulum-php", "implementation": "PostInterface", "mode": 6,
                       "peer_url": "http://gateway.example.net:4371",
                       "peer_interface_id": label_bytes("gateway/peer_interface_id", 16).hex(),
                       "peer_session_token": label_bytes("gateway/peer_session_token", 32).hex()}

    # --- Positive 1: a browser's first signed registration (no row yet) ----
    ch = challenge("A/browser/seq0", "A", "browser", 0)
    browser_first = positive(
        "browser-first",
        "Retichat-js browser, first signed registration at relay A: no signed row "
        "exists for the identity, so the challenge's MAC binds seq 0 and the relay INSERTs.",
        "A", "browser", 0, "A/browser/seq0",
        body_for("browser", ch, "Retichat Web", 1000000, 500, dict(browser_md)),
        "browser-first", "browser-first", "browser-first",
    )

    # --- Positive 2: the same browser re-registering (401 recovery) --------
    # Non-ASCII name pins the UTF-8 encoding of string fields.
    ch = challenge("A/browser/seq1", "A", "browser", 1)
    positive(
        "browser-reregister",
        "The same browser re-registering after a 401 (session lost): its row is at "
        "seq 1, so the challenge's MAC binds seq 1 and the relay UPDATEs the row in "
        "place to seq 2. The name carries non-ASCII characters to pin UTF-8.",
        "A", "browser", 1, "A/browser/seq1",
        body_for("browser", ch, "Retichat Web — Zoë", 1000000, 500, dict(browser_md)),
        "browser-reregister", "browser-reregister", "browser-reregister",
    )

    # --- Positive 3: the gateway, wake mode, re-registering at seq 5 -------
    ch = challenge("A/gateway/seq5", "A", "gateway", 5)
    gateway_wake = positive(
        "gateway-wake",
        "Reticulum-rust gateway (or Python PostInterface) in wake mode, signing with "
        "its persistent transport identity (no relay lists it: peering is open): "
        "client reticulum-php, mode 6, with peer_url / peer_interface_id / "
        "peer_session_token covered by the signature. Its row is at seq 5.",
        "A", "gateway", 5, "A/gateway/seq5",
        body_for("gateway", ch, "RNS PostInterface (Retichat Bridge)", 10000000, 500, dict(gateway_wake_md)),
        "gateway-wake", "gateway-wake", "gateway-wake",
    )

    # --- Positive 4: the gateway, poll mode, first registration ------------
    ch = challenge("A/gateway/seq0", "A", "gateway", 0)
    positive(
        "gateway-poll",
        "The same gateway identity in poll mode (no wake_url): client "
        "rns-post-interface with the transport field, no peer fields (signed as "
        "empty strings). First registration, seq 0.",
        "A", "gateway", 0, "A/gateway/seq0",
        body_for("gateway", ch, "RNS PostInterface (Retichat Bridge)", 10000000, 500,
                 {"client": "rns-post-interface", "implementation": "PostInterface", "mode": 6,
                  "transport": "tcp-backbone-gateway"}),
        "gateway-poll", "gateway-poll", "gateway-poll",
    )

    # --- Positive 5: a PHP relay registering at a peer relay (section 10) ---
    relay_b_md = {"client": "reticulum-php", "implementation": "Reticulum-post", "mode": 1,
                  "peer_url": "https://relay-b.example.org/reticulum",
                  "peer_interface_id": label_bytes("relay_b/peer_interface_id", 16).hex(),
                  "peer_session_token": label_bytes("relay_b/peer_session_token", 32).hex()}
    ch = challenge("A/relay_b/seq0", "A", "relay_b", 0)
    php_relay_body = positive(
        "php-relay-peer",
        "PHP relay B registering at relay A exactly as a gateway does (section 10): "
        "signed with B's persistent relay identity (the identity file), client "
        "reticulum-php, mode 1, peer_url = B's canonical host_url, the peer fields "
        "random per registration. First registration, seq 0.",
        "A", "relay_b", 0, "A/relay_b/seq0",
        body_for("relay_b", ch, "relay-b.example.org", 1000000, 500, dict(relay_b_md)),
        "php-relay-peer", "php-relay-peer", "php-relay-peer",
    )

    # -----------------------------------------------------------------------
    # Negative vectors. Each one fails EXACTLY ONE relay check, so the
    # expected answer does not depend on the order an implementation runs
    # its checks in. relay_state_before gives the signed row's seq at A
    # (0 = no signed row for that identity) and whether A is at capacity.
    # -----------------------------------------------------------------------
    negative = []

    def neg(vid, description, body, row_seq, status, error, fails, at_capacity=False):
        st = state(row_seq, at_capacity)
        result = verify_reference(body, relay_cfg["A"], st)
        assert result.get("status") == status and result.get("error") == error and result.get("step") == fails, \
            vid + ": reference verifier gave " + json.dumps(result)
        negative.append({
            "id": vid,
            "description": description,
            "relay": "A",
            "relay_state_before": st,
            "request_body": body,
            "fails_check": fails,
            "expected": {"status": status, "error": error},
        })

    # Tampering after signing.
    b = copy.deepcopy(browser_first)
    b["name"] = "Retichat Web (evil)"
    neg("tampered-name", "browser-first with the name changed after signing.",
        b, 0, 403, "bad_registration_signature", "signature")

    b = copy.deepcopy(browser_first)
    b["bitrate"] = 2000000
    neg("tampered-bitrate", "browser-first with bitrate changed after signing.",
        b, 0, 403, "bad_registration_signature", "signature")

    b = copy.deepcopy(gateway_wake)
    b["metadata"]["peer_url"] = "http://attacker.example.net:4371"
    neg("tampered-peer-url", "gateway-wake with peer_url changed after signing.",
        b, 5, 403, "bad_registration_signature", "signature")

    b = copy.deepcopy(gateway_wake)
    b["metadata"]["peer_session_token"] = label_bytes("attacker/peer_session_token", 32).hex()
    neg("tampered-peer-session-token", "gateway-wake with peer_session_token changed after signing.",
        b, 5, 403, "bad_registration_signature", "signature")

    msg, _ = signed_bytes(browser_first)
    b = copy.deepcopy(browser_first)
    b["registration"]["signature"] = idents["other"].sign(msg).hex()
    neg("wrong-key-signature",
        "browser-first's exact signed bytes, signed by a different identity, presented "
        "with the browser's public key.",
        b, 0, 403, "bad_registration_signature", "signature")

    # The challenge.
    neg("replay-after-success",
        "browser-first replayed verbatim after it succeeded. The signature is valid, "
        "but the row is now at seq 1 and the challenge's MAC bound seq 0.",
        copy.deepcopy(browser_first), 1, 409, "stale_challenge", "challenge")

    ch = challenge("A/gateway/seq4", "A", "gateway", 4)
    b = body_for("gateway", ch, gateway_wake["name"], gateway_wake["bitrate"], gateway_wake["mtu"],
                 copy.deepcopy(gateway_wake["metadata"]))
    neg("old-challenge-lower-seq",
        "A correctly signed gateway registration over a challenge relay A issued while "
        "the row was at seq 4, presented after the row moved to seq 5.",
        b, 5, 409, "stale_challenge", "challenge")

    ch = challenge("B/browser/seq0", "B", "browser", 0)
    b = body_for("browser", ch, "Retichat Web", 1000000, 500, dict(browser_md))
    neg("other-relay-mac",
        "A correctly signed browser registration, addressed to relay A, over a challenge "
        "minted by relay B (different relay_secret). Same identity, same seq: only the "
        "MAC differs.",
        b, 0, 409, "stale_challenge", "challenge")

    ch = challenge("A/other/seq0", "A", "other", 0)
    b = body_for("browser", ch, "Retichat Web", 1000000, 500, dict(browser_md))
    neg("challenge-for-other-identity",
        "The browser signs (validly) a challenge relay A issued for another identity. "
        "The MAC covers the identity hash, so it fails for the browser's hash.",
        b, 0, 409, "stale_challenge", "challenge")

    real = bytearray(bytes.fromhex(challenge_by_id["A/browser/seq0"]["challenge_hex"]))
    real[0] ^= 0x01
    b = body_for("browser", bytes(real), "Retichat Web", 1000000, 500, dict(browser_md))
    neg("altered-challenge-nonce",
        "The browser flips one bit of the nonce inside a real seq-0 challenge and signs "
        "the result validly. The MAC no longer matches: a client cannot alter a challenge.",
        b, 0, 409, "stale_challenge", "challenge")

    # Metadata.
    b = copy.deepcopy(browser_first)
    b["metadata"]["identity_hash"] = idents["other"].hash.hex()
    neg("identity-hash-mismatch",
        "browser-first plus metadata.identity_hash naming another identity (not a "
        "signed field, so the signature still verifies).",
        b, 0, 400, "identity_hash_mismatch", "metadata_identity_hash")

    b = copy.deepcopy(browser_first)
    b["metadata"]["wake_url"] = "https://attacker.example.net/v1/wake"
    neg("unsigned-metadata",
        "browser-first plus metadata.wake_url, a key the signature does not cover.",
        b, 0, 400, "unsigned_metadata", "metadata_keys")

    b = copy.deepcopy(browser_first)
    b["registration"]["public_key"] = b["registration"]["public_key"].upper()
    neg("uppercase-public-key",
        "browser-first with the public key in upper-case hex. Hex fields are "
        "lower-case only.",
        b, 0, 400, "bad_registration", "shape")

    # Client policy (section 4.3.1), each correctly signed.
    ch = challenge("A/browser/seq0/mode6", "A", "browser", 0)
    b = body_for("browser", ch, "Retichat Web", 1000000, 500, dict(browser_md, mode=6))
    neg("browser-transit-mode",
        "A correctly signed rns-js registration with mode 6 (gateway). Browsers are "
        "endpoints: modes 3, 5 and 6 are refused for client rns-js.",
        b, 0, 400, "transit_mode_not_allowed", "client_policy")

    ch = challenge("A/browser/seq0/peer-url", "A", "browser", 0)
    b = body_for("browser", ch, "Retichat Web", 1000000, 500,
                 dict(browser_md, peer_url="https://reflector.example.net"))
    neg("browser-with-peer-url",
        "A correctly signed rns-js registration that names a peer_url. A browser row "
        "may not carry peer fields: they would make it look like a PHP peer and draw "
        "wakes to any URL.",
        b, 0, 400, "metadata_not_allowed", "client_policy")

    ch = challenge("A/other/seq0/unknown-client", "A", "other", 0)
    b = body_for("other", ch, "Something", 1000000, 500,
                 {"client": "x", "implementation": "PostInterface", "mode": 1})
    neg("unknown-client",
        "A correctly signed registration with client \"x\". Only rns-js, reticulum-php "
        "and rns-post-interface may register signed.",
        b, 0, 400, "unknown_client", "client_policy")

    ch = challenge("A/gateway/seq5/no-peer-fields", "A", "gateway", 5)
    b = body_for("gateway", ch, gateway_wake["name"], gateway_wake["bitrate"], gateway_wake["mtu"],
                 {"client": "reticulum-php", "implementation": "PostInterface", "mode": 6})
    neg("wake-gateway-without-peer-fields",
        "The gateway, correctly signed, client reticulum-php with no peer fields. "
        "A wake-mode gateway must name where it is woken.",
        b, 5, 400, "peer_fields_required", "client_policy")

    ch = challenge("A/gateway/seq5/poll-peer-url", "A", "gateway", 5)
    b = body_for("gateway", ch, gateway_wake["name"], gateway_wake["bitrate"], gateway_wake["mtu"],
                 {"client": "rns-post-interface", "implementation": "PostInterface", "mode": 6,
                  "transport": "tcp-backbone-gateway", "peer_url": "http://gateway.example.net:4371"})
    neg("poll-gateway-with-peer-url",
        "The gateway, correctly signed, client rns-post-interface carrying a "
        "peer_url. A poll-mode gateway is never woken, so it may not name a URL.",
        b, 5, 400, "metadata_not_allowed", "client_policy")

    # Capacity.
    ch = challenge("A/other/seq0/capacity", "A", "other", 0)
    b = body_for("other", ch, "Retichat Web", 1000000, 500, dict(browser_md))
    neg("registration-capacity",
        "A correctly signed first registration (a new row) while relay A's interfaces "
        "table is at max_interface_rows and nothing is reclaimable.",
        b, 0, 503, "registration_capacity", "capacity", at_capacity=True)

    # Token encryption.
    ch = challenge("A/lowx/seq0", "A", "lowx", 0)
    b = body_for("lowx", ch, "Retichat Web", 1000000, 500, dict(browser_md))
    neg("low-order-x25519-key",
        "A correctly signed browser registration whose public key has the all-zero "
        "(low-order) X25519 half. The Ed25519 signature verifies, but no token can be "
        "encrypted to the key, so the relay refuses it before writing anything.",
        b, 0, 400, "bad_registration", "token_encryption")

    # Token negatives: what a client must refuse when decrypting.
    tokens_negative = []
    good = registrations[0]["encrypted_token"]["session_token_encrypted_hex"]
    blob = bytearray(bytes.fromhex(good))
    blob[32 + 16] ^= 0x01  # first ciphertext byte
    tampered = bytes(blob)
    assert idents["browser"].decrypt(tampered) is None
    tokens_negative.append({
        "id": "token-tampered-ciphertext",
        "identity": "browser",
        "description": "browser-first's encrypted token with one ciphertext bit flipped: "
                       "the HMAC fails, decryption must fail, the client must not use it.",
        "session_token_encrypted_hex": tampered.hex(),
        "expected": "decrypt_fails",
    })
    assert idents["gateway"].decrypt(bytes.fromhex(good)) is None
    tokens_negative.append({
        "id": "token-wrong-identity",
        "identity": "gateway",
        "description": "browser-first's encrypted token decrypted by the gateway identity: "
                       "a token is readable only by the identity it was encrypted to.",
        "session_token_encrypted_hex": good,
        "expected": "decrypt_fails",
    })

    # Canonical peer URLs (section 10.1).
    url_inputs = [
        ("https://retichat.com/reticulum", "already canonical"),
        ("https://Retichat.COM/reticulum/", "host lower-cased, trailing slash dropped; the path keeps its case"),
        ("HTTPS://retichat.com:443/reticulum/v1/wake", "scheme lower-cased, default port and /v1/wake dropped"),
        ("https://retichat.com/reticulum/v1/wake/", "trailing slash, then /v1/wake, dropped"),
        ("https://RETICHAT.com/Reticulum", "path case is significant: a different key"),
        ("https://retichat.com", "empty path"),
        ("https://retichat.com/", "root path"),
        ("https://retichat.com:8443/reticulum", "a non-default port is kept"),
        ("http://127.0.0.1:4371/", "loopback http (staging)"),
        ("http://[::1]:4371", "IPv6 literal"),
        ("https://xn--rtichat-bya.com/reticulum", "an IDN look-alike in ASCII form: valid, and a different key"),
        ("https://rétichat.com/reticulum", "a non-ASCII look-alike: refused, never folded onto retichat.com"),
        ("https://retichat.com/reticulum ", "whitespace: refused"),
        ("https://user@retichat.com/reticulum", "userinfo: refused"),
        ("https://retichat.com/reticulum?x=1", "query: refused"),
        ("https://retichat.com/reticulum#top", "fragment: refused"),
        ("ftp://retichat.com/reticulum", "scheme other than http(s): refused"),
        ("retichat.com/reticulum", "not absolute: refused"),
        ("https://retichat.com:0/reticulum", "port 0: refused"),
    ]
    url_canonical = []
    for u, note in url_inputs:
        canon, reason = canonical_url(u)
        url_canonical.append({
            "input": u,
            "note": note,
            "canonical": canon,
            "peer_url_key": None if canon is None else url_key(canon),
            "refused": reason,
        })
    keys = {e["input"]: e["peer_url_key"] for e in url_canonical}
    assert keys["https://Retichat.COM/reticulum/"] == keys["https://retichat.com/reticulum"]
    assert keys["HTTPS://retichat.com:443/reticulum/v1/wake"] == keys["https://retichat.com/reticulum"]
    assert keys["https://xn--rtichat-bya.com/reticulum"] != keys["https://retichat.com/reticulum"]
    assert keys["https://rétichat.com/reticulum"] is None

    # The gateway wake-URL confirm (section 9.8). Relay A confirms the wake
    # URL that the gateway-wake vector's row stores, before ever waking it.
    gw = idents["gateway"]
    gw_cfg = {"node_url": "https://relay-a.example.org/reticulum/",
              "wake_url": "http://gateway.example.net:4371/v1/wake"}
    relay_a_url = "https://relay-a.example.org/reticulum"
    relay_b_url = "https://relay-b.example.org/reticulum"
    stored_peer_url, _ = canonical_url(gateway_wake["metadata"]["peer_url"])
    assert stored_peer_url == "http://gateway.example.net:4371"
    assert canonical_url(gw_cfg["node_url"])[0] == relay_a_url
    confirm_nonce = label_bytes("gateway-confirm/nonce", 16)
    confirm_body = {"version": 1, "nonce": confirm_nonce.hex(), "identity_hash": gw.hash.hex(),
                    "relay_url": relay_a_url, "peer_url": stored_peer_url}
    confirm_msg, confirm_fields = gateway_confirm_bytes(confirm_body)
    handled = gateway_handle_confirm(confirm_body, gw, gw_cfg)
    assert handled["status"] == 200, handled
    confirm_sig = bytes.fromhex(handled["body"]["signature"])
    assert gw.validate(confirm_sig, confirm_msg), "RNS rejects the confirm signature"
    gw_pub = gw.get_public_key()
    assert relay_verify_confirm_answer(confirm_body, 200, handled["body"], gw_pub)["result"] == "confirmed"

    gateway_refusals = []

    def refusal(rid, description, body, status, error):
        got = gateway_handle_confirm(body, gw, gw_cfg)
        assert got == {"status": status, "error": error}, rid + ": " + json.dumps(got)
        gateway_refusals.append({"id": rid, "description": description, "request_body": body,
                                 "expected": {"status": status, "error": error}})

    b = dict(confirm_body, identity_hash=idents["other"].hash.hex())
    refusal("not-my-identity", "A confirm for another identity's row. The gateway signs only "
            "for its own transport identity.", b, 403, "not_my_identity")
    b = dict(confirm_body, relay_url=relay_b_url)
    refusal("unknown-relay", "A confirm from a relay this gateway does not register with "
            "(its node_url is relay A). The gateway is not a signing oracle for anyone else.",
            b, 403, "unknown_relay")
    b = dict(confirm_body, peer_url="http://attacker.example.net:4371")
    refusal("not-my-wake-url", "A confirm naming a wake URL that is not this gateway's own.",
            b, 403, "not_my_wake_url")
    b = dict(confirm_body, nonce=confirm_body["nonce"].upper())
    refusal("bad-nonce", "The nonce in upper-case hex. Hex fields are lower-case only.",
            b, 400, "bad_confirm_request")
    b = dict(confirm_body, waker_url=relay_a_url)
    refusal("extra-key", "A confirm body with a key outside the five.", b, 400, "bad_confirm_request")

    answer_negative = []

    def answer(aid, description, status, body, expected):
        got = relay_verify_confirm_answer(confirm_body, status, body, gw_pub)
        assert got == expected, aid + ": " + json.dumps(got)
        answer_negative.append({"id": aid, "description": description, "answer_status": status,
                                "answer_body": body, "expected": expected})

    answer("answer-other-key", "The right bytes, signed by another identity.", 200,
           {"signature": idents["other"].sign(confirm_msg).hex()}, {"result": "bad_signature"})
    other_nonce = dict(confirm_body, nonce=label_bytes("gateway-confirm/other-nonce", 16).hex())
    answer("answer-other-nonce", "The gateway's signature over another nonce (an earlier "
           "confirm's answer).", 200, {"signature": gw.sign(gateway_confirm_bytes(other_nonce)[0]).hex()},
           {"result": "bad_signature"})
    other_peer = dict(confirm_body, peer_url="http://attacker.example.net:4371")
    answer("answer-other-peer-url", "The gateway's signature for another wake URL.", 200,
           {"signature": gw.sign(gateway_confirm_bytes(other_peer)[0]).hex()}, {"result": "bad_signature"})
    other_relay = dict(confirm_body, relay_url=relay_b_url)
    answer("answer-other-relay", "The gateway's signature for relay B's confirm.", 200,
           {"signature": gw.sign(gateway_confirm_bytes(other_relay)[0]).hex()}, {"result": "bad_signature"})
    answer("answer-registration-signature", "The gateway's registration signature (vector "
           "gateway-wake) offered as the answer. The domains keep the two apart.", 200,
           {"signature": registrations[2]["signature_hex"]}, {"result": "bad_signature"})
    answer("answer-echo-nonce", "The nonce echoed back. Reaching the URL is not enough: the "
           "answer must be signed by the row's key.", 200, {"nonce": confirm_body["nonce"]},
           {"result": "bad_answer", "reason": "shape"})
    answer("answer-wake-ok", "What today's wake route answers ({\"status\": \"ok\"}).", 200,
           {"status": "ok"}, {"result": "bad_answer", "reason": "shape"})
    answer("answer-uppercase-signature", "The right signature in upper-case hex.", 200,
           {"signature": confirm_sig.hex().upper()}, {"result": "bad_answer", "reason": "shape"})
    answer("answer-extra-key", "The right signature with a second key.", 200,
           {"signature": confirm_sig.hex(), "status": "ok"}, {"result": "bad_answer", "reason": "shape"})
    answer("answer-404", "A server without the handler (an older gateway binary) answers 404.",
           404, None, {"result": "bad_answer", "reason": "status"})

    # --- The PHP relay peer (section 10) ------------------------------------
    rb = idents["relay_b"]
    rb_cfg = {"host_url": "https://relay-b.example.org/reticulum",
              "interfaces_node_urls": ["https://relay-a.example.org/reticulum/",
                                       "https://relay-c.example.org/reticulum"]}
    rb_reg = [r for r in registrations if r["id"] == "php-relay-peer"][0]
    rb_tok = rb_reg["encrypted_token"]
    rb_blob = bytes.fromhex(rb_tok["session_token_encrypted_hex"])
    rb_xprv = bytes.fromhex(identity_json["relay_b"]["x25519_private_hex"])
    got = reference_decrypt(rb_blob, rb_xprv, rb.hash)
    assert got == {"result": "ok", "session_token": rb_tok["plaintext_utf8"]}, got
    decrypt_walk = {
        "registration_id": "php-relay-peer",
        "session_token_encrypted_hex": rb_blob.hex(),
        "ephemeral_public_hex": rb_blob[:32].hex(),
        "iv_hex": rb_blob[32:48].hex(),
        "ciphertext_hex": rb_blob[48:-32].hex(),
        "hmac_hex": rb_blob[-32:].hex(),
        "shared_key_hex": rb_tok["shared_key_hex"],
        "hkdf_salt_hex": rb.hash.hex(),
        "derived_key_hex": rb_tok["derived_key_hex"],
        "hmac_key_hex": rb_tok["hmac_key_hex"],
        "aes_key_hex": rb_tok["aes_key_hex"],
        "expected": got,
    }
    decrypt_negative = []

    def dneg(did, description, blob, expected):
        r = reference_decrypt(blob, rb_xprv, rb.hash)
        assert r == {"result": expected}, did + ": " + json.dumps(r)
        decrypt_negative.append({"id": did, "description": description,
                                 "session_token_encrypted_hex": blob.hex(),
                                 "expected": {"result": expected}})

    dneg("zero-ephemeral-key", "The good blob with its ephemeral public key replaced by 32 zero "
         "bytes: the X25519 result is all zero, so it is refused before any key is derived.",
         bytes(32) + rb_blob[32:], "zero_shared_secret")
    flipped = bytearray(rb_blob)
    flipped[-1] ^= 0x01
    dneg("hmac-flipped", "The good blob with one bit of its HMAC flipped.", bytes(flipped), "hmac")
    dneg("other-identity", "The gateway-wake vector's token, encrypted to the gateway: the "
         "HMAC fails under relay B's keys.",
         bytes.fromhex(registrations[2]["encrypted_token"]["session_token_encrypted_hex"]), "hmac")
    not_token = encrypt_token_deterministic(rb, b"not a session token",
                                            label_bytes("ephemeral/php-relay-not-token", 32),
                                            label_bytes("iv/php-relay-not-token", 16))
    dneg("not-a-session-token", "A correctly encrypted blob whose plaintext is not 64 lower-case "
         "hex: it decrypts, and is refused as a protocol error.",
         bytes.fromhex(not_token["session_token_encrypted_hex"]), "not_a_token")

    rb_nonce = label_bytes("php-relay-confirm/nonce", 16)
    rb_confirm_body = {"version": 1, "nonce": rb_nonce.hex(), "identity_hash": rb.hash.hex(),
                       "relay_url": relay_a_url, "peer_url": rb_cfg["host_url"]}
    rb_msg, rb_fields = gateway_confirm_bytes(rb_confirm_body)
    rb_handled = php_relay_handle_confirm(rb_confirm_body, rb, rb_cfg)
    assert rb_handled["status"] == 200, rb_handled
    rb_sig = bytes.fromhex(rb_handled["body"]["signature"])
    assert rb.validate(rb_sig, rb_msg)
    rb_pub = rb.get_public_key()
    assert relay_verify_confirm_answer(rb_confirm_body, 200, rb_handled["body"], rb_pub)["result"] == "confirmed"
    rb_refusals = []

    def rbref(rid, description, body, status, error):
        r = php_relay_handle_confirm(body, rb, rb_cfg)
        assert r == {"status": status, "error": error}, rid + ": " + json.dumps(r)
        rb_refusals.append({"id": rid, "description": description, "request_body": body,
                            "expected": {"status": status, "error": error}})

    rbref("not-my-identity", "A confirm for the gateway's identity, sent to relay B.",
          dict(rb_confirm_body, identity_hash=gw.hash.hex()), 403, "not_my_identity")
    rbref("unknown-relay", "A confirm from a relay that is not in relay B's [interfaces].",
          dict(rb_confirm_body, relay_url="https://relay-d.example.org/reticulum"), 403, "unknown_relay")
    rbref("not-my-wake-url", "A confirm naming relay A's URL as relay B's wake URL.",
          dict(rb_confirm_body, peer_url=relay_a_url), 403, "not_my_wake_url")
    rb_answer_negative = []
    r = relay_verify_confirm_answer(rb_confirm_body, 200, {"signature": gw.sign(rb_msg).hex()}, rb_pub)
    assert r == {"result": "bad_signature"}
    rb_answer_negative.append({"id": "answer-gateway-key",
                               "description": "The right bytes signed by the gateway's key, not relay B's.",
                               "answer_status": 200, "answer_body": {"signature": gw.sign(rb_msg).hex()},
                               "expected": r})

    def link_registrant(a, b):
        ca, cb = canonical_url(a)[0], canonical_url(b)[0]
        return (a, b) if ca.encode("ascii") < cb.encode("ascii") else (b, a)

    link_order = []
    for a, b, note in [
        ("https://relay-a.example.org/reticulum", "https://relay-b.example.org/reticulum", "the vectors' two relays"),
        ("https://selectivesubconscious.com/reticulum", "https://retichat.com/reticulum", "the live pair"),
        ("https://relay-a.example.org:8443/reticulum", "https://relay-a.example.org/reticulum", "'/' (0x2f) sorts before ':' (0x3a)"),
        ("https://Relay-B.example.org/reticulum/", "https://relay-a.example.org/reticulum", "compared in canonical form"),
    ]:
        keep, down = link_registrant(a, b)
        link_order.append({"relay_1": a, "relay_2": b, "note": note,
                           "canonical_1": canonical_url(a)[0], "canonical_2": canonical_url(b)[0],
                           "link_is_registration_of": canonical_url(keep)[0],
                           "stands_down": canonical_url(down)[0]})
    assert link_order[1]["link_is_registration_of"] == "https://retichat.com/reticulum"

    # Revision 7 (James, 2026-10-04): relay B's transport id is the hash of its
    # identity file, as RNS's transport id is Transport.identity.hash, and the
    # random id it had before the switch stays its own. Each packet is a link
    # request for the browser's lxmf.delivery destination, sent by a node whose
    # path to it goes through some next hop, and put into transport the way
    # RNS 1.5.2 Transport.outbound does it (Transport.py:1397-1403).
    rb_from_file = RNS.Identity.from_bytes(bytes.fromhex(identity_json["relay_b"]["private_key_hex"]))
    assert rb_from_file is not None and rb_from_file.hash == rb.hash
    pre_switch_id = label_bytes("php-relay-peer/pre-switch-transport-id", 16)
    assert pre_switch_id != rb.hash
    own_ids = [rb.hash, pre_switch_id]
    lr_dest = RNS.Destination.hash(idents["browser"], "lxmf", "delivery")
    lr_ident, _ = make_identity("link-request-sender")
    lr_flags = (RNS.Packet.HEADER_1 << 6) | (RNS.Transport.BROADCAST << 4) | (RNS.Destination.SINGLE << 2) | RNS.Packet.LINKREQUEST
    lr_raw = bytes([lr_flags, 0]) + lr_dest + bytes([RNS.Packet.NONE]) + lr_ident.get_public_key()
    lr_packet = RNS.Packet(None, lr_raw)
    assert lr_packet.unpack() and lr_packet.header_type == RNS.Packet.HEADER_1
    assert lr_packet.destination_hash == lr_dest and lr_packet.packet_type == RNS.Packet.LINKREQUEST
    lr_hash = lr_packet.get_hash()

    def into_transport(raw, next_hop):
        flags = (RNS.Packet.HEADER_2 << 6) | (RNS.Transport.TRANSPORT << 4) | (raw[0] & 0b00001111)
        return bytes([flags]) + raw[1:2] + next_hop + raw[2:]

    transport_packets = []
    for tid_case, description, next_hop in [
        ("via-transport-id", "The sender learned its path from an announce relay B relayed after the "
         "switch: the next hop is B's transport id. B forwards it.", rb.hash),
        ("via-pre-switch-id", "The sender learned its path before the switch: the next hop is B's "
         "pre-switch id. B still forwards it.", pre_switch_id),
        ("via-another-node", "The next hop is another transport node (the gateway's identity hash): "
         "not B's. B's packet filter refuses it.", gw.hash),
    ]:
        raw = into_transport(lr_raw, next_hop)
        p = RNS.Packet(None, raw)
        assert p.unpack() and p.header_type == RNS.Packet.HEADER_2 and p.transport_id == next_hop, tid_case
        assert p.destination_hash == lr_dest and p.packet_type == RNS.Packet.LINKREQUEST, tid_case
        assert p.get_hash() == lr_hash, tid_case + ": the transport id is not part of the packet hash"
        own = next_hop in own_ids
        transport_packets.append({
            "id": tid_case,
            "description": description,
            "next_hop_hex": next_hop.hex(),
            "raw_hex": raw.hex(),
            "header": {"flags_hex": "%02x" % raw[0], "hops": raw[1], "transport_id_hex": raw[2:18].hex(),
                       "destination_hash_hex": raw[18:34].hex(), "context_hex": "%02x" % raw[34]},
            "packet_hash_hex": p.get_hash().hex(),
            "expected": {"own": True} if own else {"own": False, "filter": "transport_id_mismatch"},
        })
    assert [t["expected"]["own"] for t in transport_packets] == [True, True, False]

    transport_id = {
        "rule": "REGISTRATION.md section 10.2 (revision 7): the transport id is the identity hash, "
                "SHA-256(x25519_pub || ed25519_pub)[:16] of the identity file, and is the only id the "
                "relay writes; the pre-switch id (transport_state.identity_hash_hex) stays its own too",
        "transport_id_hex": rb.hash.hex(),
        "pre_switch_transport_id_hex": pre_switch_id.hex(),
        "own_transport_ids_hex": [x.hex() for x in own_ids],
        "sent": {
            "description": "A link request for the browser's lxmf.delivery destination, as its sender "
                           "packs it (HEADER_1, hops 0), before it is put into transport.",
            "destination_hash_hex": lr_dest.hex(),
            "raw_hex": lr_raw.hex(),
            "packet_hash_hex": lr_hash.hex(),
        },
        "into_transport": "flags = HEADER_2 << 6 | TRANSPORT << 4 | (flags & 0x0f); "
                          "raw = flags || hops || next_hop(16) || raw[2:] "
                          "(RNS 1.5.2 Transport.outbound, Transport.py:1397-1403)",
        "packets": transport_packets,
    }

    php_relay_peer = {
        "identity": "relay_b",
        "identity_file_hex": identity_json["relay_b"]["private_key_hex"],
        "identity_file_layout": "x25519_private(32) || ed25519_seed(32): the 64 bytes RNS Identity.to_file writes",
        "identity_hash_hex": rb.hash.hex(),
        "config": rb_cfg,
        "registration_id": "php-relay-peer",
        "decrypt": decrypt_walk,
        "decrypt_negative": decrypt_negative,
        "confirm": {
            "id": "php-relay-confirm",
            "description": "Relay A confirms relay B's wake URL (its canonical host_url) after B's "
                           "registration, before it ever wakes B. B's [interfaces] writes relay A's "
                           "node_url with a trailing slash: it compares canonical forms.",
            "request_url": rb_cfg["host_url"] + GATEWAY_CONFIRM_PATH,
            "request_body": rb_confirm_body,
            "signed_fields": [{"name": n, "value_hex": v.hex(), "lp_hex": lp(v).hex()} for n, v in rb_fields],
            "signed_bytes_hex": rb_msg.hex(),
            "signature_hex": rb_sig.hex(),
            "response_body": {"signature": rb_sig.hex()},
            "expected_relay": {"result": "confirmed"},
        },
        "confirm_refusals": rb_refusals,
        "confirm_answer_negative": rb_answer_negative,
        "link_order": link_order,
        "transport_id": transport_id,
    }

    gateway_confirm = {
        "domain": GATEWAY_CONFIRM_DOMAIN.decode(),
        "domain_hex": GATEWAY_CONFIRM_DOMAIN.hex(),
        "path": GATEWAY_CONFIRM_PATH,
        "signed_field_order": GATEWAY_CONFIRM_FIELD_ORDER,
        "gateway": {"identity": "gateway", "config": gw_cfg},
        "relay_url": relay_a_url,
        "positive": {
            "id": "gateway-confirm",
            "description": "Relay A confirms the wake URL stored for the gateway-wake row "
                           "(canonical peer_url) before it ever wakes it. The gateway's config "
                           "writes its node_url with a trailing slash: it compares canonical forms.",
            "row": {"identity": "gateway", "peer_url": stored_peer_url, "peer_url_key": url_key(stored_peer_url)},
            "request_url": stored_peer_url + GATEWAY_CONFIRM_PATH,
            "request_body": confirm_body,
            "signed_fields": [{"name": n, "value_hex": v.hex(), "lp_hex": lp(v).hex()} for n, v in confirm_fields],
            "signed_bytes_hex": confirm_msg.hex(),
            "signature_hex": confirm_sig.hex(),
            "response_body": {"signature": confirm_sig.hex()},
            "expected_relay": {"result": "confirmed"},
        },
        "gateway_refusals": gateway_refusals,
        "answer_negative": answer_negative,
    }

    lp_examples = [
        {"input_hex": "", "output_hex": lp(b"").hex()},
        {"input_utf8": "rns-js", "output_hex": lp(b"rns-js").hex()},
        {"input_utf8": REGISTER_DOMAIN.decode(), "output_hex": lp(REGISTER_DOMAIN).hex()},
    ]

    return {
        "spec": "Reticulum-post/REGISTRATION.md",
        "format_version": 6,
        "generator": "Reticulum-post/tools/registration_vectors.py (RNS " + RNS.__version__ + ")",
        "note": "Every byte below is derived from fixed labels; regenerate with the "
                "generator, never by hand. Hex is lower-case throughout.",
        "constants": {
            "register_domain": REGISTER_DOMAIN.decode(),
            "register_domain_hex": REGISTER_DOMAIN.hex(),
            "challenge_domain": CHALLENGE_DOMAIN.decode(),
            "challenge_domain_hex": CHALLENGE_DOMAIN.hex(),
            "challenge_length": CHALLENGE_LENGTH,
            "challenge_layout": "nonce(16) || HMAC-SHA256(relay_secret, challenge_domain || identity_hash(16) || u64be(registration_seq) || nonce(16))",
            "signed_field_order": SIGNED_FIELD_ORDER,
            "lp": "u16be(len(x)) || x",
        },
        "lp_examples": lp_examples,
        "relays": relays,
        "identities": identity_json,
        "challenges": challenges,
        "registrations": registrations,
        "negative": negative,
        "tokens_negative": tokens_negative,
        "url_canonical": url_canonical,
        "gateway_confirm": gateway_confirm,
        "php_relay_peer": php_relay_peer,
    }


def render(doc):
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify the committed JSON instead of writing it")
    parser.add_argument("--out", default=OUT_PATH, help="output path (default: %(default)s)")
    args = parser.parse_args()

    text = render(build())

    if args.check:
        try:
            with open(args.out, "r", encoding="utf-8") as f:
                committed = f.read()
        except FileNotFoundError:
            print("FAIL: " + args.out + " does not exist")
            return 1
        if committed != text:
            print("FAIL: " + args.out + " differs from what the generator produces")
            return 1
        print("PASS: " + args.out + " matches the generator, and every vector verified with RNS " + RNS.__version__)
        return 0

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote " + args.out + " (all vectors verified with RNS " + RNS.__version__ + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
