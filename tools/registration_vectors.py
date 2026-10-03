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

Every vector is verified with RNS before it is written: each signature with
Identity.validate, each identity hash against Identity.hash, each encrypted
session token with Identity.decrypt (and, for the deterministic ones, by
re-deriving the same bytes). --check additionally regenerates the file in
memory and compares it byte for byte with the committed copy.

tools/check_registration_vectors.php checks the same file independently with
PHP sodium/openssl, the primitives the relay will use.
"""

import argparse
import copy
import hashlib
import hmac
import json
import os
import sys

try:
    import RNS
    from RNS.Cryptography import X25519PrivateKey, PKCS7, HMAC
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

# The twelve signed fields, in signing order (REGISTRATION.md section 3).
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


# ---------------------------------------------------------------------------
# Challenge (REGISTRATION.md section 2)
# ---------------------------------------------------------------------------

def challenge_mac_input(identity_hash, seq, nonce):
    assert len(identity_hash) == 16 and len(nonce) == 16
    return CHALLENGE_DOMAIN + identity_hash + u64(seq) + nonce


def make_challenge(relay_secret, identity_hash, seq, nonce):
    mac_input = challenge_mac_input(identity_hash, seq, nonce)
    mac = hmac.new(relay_secret, mac_input, hashlib.sha256).digest()
    challenge = nonce + u64(seq) + mac
    assert len(challenge) == 56
    return challenge, mac_input, mac


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
    relays = {
        "A": {"relay_secret_hex": label_bytes("relay/A/secret").hex(),
              "description": "the relay every vector is presented to"},
        "B": {"relay_secret_hex": label_bytes("relay/B/secret").hex(),
              "description": "another relay; its challenges must be refused at A"},
    }
    secret = {k: bytes.fromhex(v["relay_secret_hex"]) for k, v in relays.items()}

    idents = {}
    identity_json = {}
    for name in ("browser", "gateway", "other"):
        idents[name], identity_json[name] = make_identity(name)

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
            "registration_seq": seq,
            "nonce_hex": nonce.hex(),
            "mac_input_hex": mac_input.hex(),
            "mac_hex": mac.hex(),
            "challenge_hex": ch.hex(),
            "challenge_response": {
                "status": "challenge",
                "version": 1,
                "identity_hash": ident.hash.hex(),
                "registration_seq": seq,
                "challenge": ch.hex(),
            },
        }
        challenges.append(entry)
        challenge_by_id[cid] = entry
        return ch

    def body_for(ident_name, ch, name, bitrate, mtu, metadata, signer=None, sign_override=None):
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

    registrations = []

    def positive(vid, description, relay, ident_name, row_seq_before, cid, body, session_token_label, eph_label, iv_label):
        ident = idents[ident_name]
        msg, fields = signed_bytes(body)
        sig = bytes.fromhex(body["registration"]["signature"])
        assert ident.validate(sig, msg), vid + ": RNS rejects the signature"
        assert len(sig) == 64
        session_token = label_bytes("session_token/" + session_token_label, 32).hex()
        token = encrypt_token_deterministic(
            ident,
            session_token.encode("ascii"),
            label_bytes("ephemeral/" + eph_label, 32),
            label_bytes("iv/" + iv_label, 16),
        )
        new_seq = row_seq_before + 1
        registrations.append({
            "id": vid,
            "description": description,
            "relay": relay,
            "identity": ident_name,
            "relay_state_before": {
                "signed_row_exists": row_seq_before > 0,
                "row_registration_seq": row_seq_before,
            },
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
                "registration_seq": new_seq,
                "relay_state_after": {"row_registration_seq": new_seq},
            },
            "response_example": {
                "status": "registered",
                "interface_id": label_bytes("interface_id/" + vid, 16).hex(),
                "identity_hash": ident.hash.hex(),
                "registration_seq": new_seq,
                "session_token_encrypted": token["session_token_encrypted_hex"],
                "idle_exchange_interval_ms": 1000,
                "max_batch_packets": 64,
                "max_packet_bytes": 500,
            },
            "encrypted_token": token,
        })
        return body

    # --- Positive 1: a browser's first signed registration (no row yet) ----
    ch = challenge("A/browser/seq0", "A", "browser", 0)
    browser_first = positive(
        "browser-first",
        "Retichat-js browser, first signed registration at relay A: no signed row "
        "exists for the identity, so the challenge carries seq 0 and the relay INSERTs.",
        "A", "browser", 0, "A/browser/seq0",
        body_for("browser", ch, "Retichat Web", 1000000, 500,
                 {"client": "rns-js", "implementation": "PostInterface", "mode": 1}),
        "browser-first", "browser-first", "browser-first",
    )

    # --- Positive 2: the same browser re-registering (401 recovery) --------
    # Non-ASCII name pins the UTF-8 encoding of string fields.
    ch = challenge("A/browser/seq1", "A", "browser", 1)
    browser_again = positive(
        "browser-reregister",
        "The same browser re-registering after a 401 (session lost): its row is at "
        "seq 1, so the challenge carries seq 1 and the relay UPDATEs the row in "
        "place to seq 2. The name carries non-ASCII characters to pin UTF-8.",
        "A", "browser", 1, "A/browser/seq1",
        body_for("browser", ch, "Retichat Web — Zoë", 1000000, 500,
                 {"client": "rns-js", "implementation": "PostInterface", "mode": 1}),
        "browser-reregister", "browser-reregister", "browser-reregister",
    )

    # --- Positive 3: the gateway, wake mode, re-registering at seq 5 -------
    ch = challenge("A/gateway/seq5", "A", "gateway", 5)
    gateway_wake = positive(
        "gateway-wake",
        "Reticulum-rust gateway (or Python PostInterface) in wake mode, signing with "
        "its persistent transport identity: client reticulum-php, mode 6, with "
        "peer_url / peer_interface_id / peer_session_token covered by the signature. "
        "Its row is at seq 5 (an earlier process registered five times).",
        "A", "gateway", 5, "A/gateway/seq5",
        body_for("gateway", ch, "RNS PostInterface (Retichat Bridge)", 10000000, 500,
                 {"client": "reticulum-php", "implementation": "PostInterface", "mode": 6,
                  "peer_url": "http://gateway.example.net:4371",
                  "peer_interface_id": label_bytes("gateway/peer_interface_id", 16).hex(),
                  "peer_session_token": label_bytes("gateway/peer_session_token", 32).hex()}),
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

    # -----------------------------------------------------------------------
    # Negative vectors. Each one fails EXACTLY ONE relay check, so the
    # expected answer does not depend on the order an implementation runs
    # its checks in. relay_state_before gives the signed row's seq at A
    # (0 = no signed row for that identity).
    # -----------------------------------------------------------------------
    negative = []

    def neg(vid, description, body, row_seq, status, error, fails):
        negative.append({
            "id": vid,
            "description": description,
            "relay": "A",
            "relay_state_before": {"signed_row_exists": row_seq > 0, "row_registration_seq": row_seq},
            "request_body": body,
            "fails_check": fails,
            "expected": {"status": status, "error": error},
        })

    # N1: tampered name (signature over the original).
    b = copy.deepcopy(browser_first)
    b["name"] = "Retichat Web (evil)"
    neg("tampered-name", "browser-first with the name changed after signing.",
        b, 0, 403, "bad_registration_signature", "signature")

    # N2: tampered bitrate.
    b = copy.deepcopy(browser_first)
    b["bitrate"] = 2000000
    neg("tampered-bitrate", "browser-first with bitrate changed after signing.",
        b, 0, 403, "bad_registration_signature", "signature")

    # N3: tampered peer_url on the gateway (the wake target is covered).
    b = copy.deepcopy(gateway_wake)
    b["metadata"]["peer_url"] = "http://attacker.example.net:4371"
    neg("tampered-peer-url", "gateway-wake with peer_url changed after signing.",
        b, 5, 403, "bad_registration_signature", "signature")

    # N4: tampered peer_session_token.
    b = copy.deepcopy(gateway_wake)
    b["metadata"]["peer_session_token"] = label_bytes("attacker/peer_session_token", 32).hex()
    neg("tampered-peer-session-token", "gateway-wake with peer_session_token changed after signing.",
        b, 5, 403, "bad_registration_signature", "signature")

    # N5: signature by another key over the browser's exact bytes.
    msg, _ = signed_bytes(browser_first)
    b = copy.deepcopy(browser_first)
    b["registration"]["signature"] = idents["other"].sign(msg).hex()
    neg("wrong-key-signature",
        "browser-first's exact signed bytes, signed by a different identity, presented "
        "with the browser's public key.",
        b, 0, 403, "bad_registration_signature", "signature")

    # N6: replay -- browser-first verbatim after it succeeded (row now at seq 1).
    neg("replay-wrong-seq",
        "browser-first replayed verbatim after it succeeded: MAC and signature are "
        "valid, but the row is now at seq 1 and the challenge carries seq 0.",
        copy.deepcopy(browser_first), 1, 409, "stale_challenge", "challenge_seq")

    # N7: an older (properly MACed) gateway challenge, seq 4, row at 5.
    ch = challenge("A/gateway/seq4", "A", "gateway", 4)
    b = body_for("gateway", ch, gateway_wake["name"], gateway_wake["bitrate"], gateway_wake["mtu"],
                 copy.deepcopy(gateway_wake["metadata"]))
    neg("old-challenge-lower-seq",
        "A correctly signed gateway registration over a challenge relay A issued at "
        "seq 4, presented after the row moved to seq 5.",
        b, 5, 409, "stale_challenge", "challenge_seq")

    # N8: the other relay's MAC -- challenge minted by relay B.
    ch = challenge("B/browser/seq0", "B", "browser", 0)
    b = body_for("browser", ch, "Retichat Web", 1000000, 500,
                 {"client": "rns-js", "implementation": "PostInterface", "mode": 1})
    neg("other-relay-mac",
        "A correctly signed browser registration over a challenge minted by relay B "
        "(different relay_secret), presented to relay A. Same identity, same seq: "
        "only the MAC differs. This is why the client never signs a relay URL.",
        b, 0, 409, "stale_challenge", "challenge_mac")

    # N9: a challenge relay A minted for a DIFFERENT identity.
    ch = challenge("A/other/seq0", "A", "other", 0)
    b = body_for("browser", ch, "Retichat Web", 1000000, 500,
                 {"client": "rns-js", "implementation": "PostInterface", "mode": 1})
    neg("challenge-for-other-identity",
        "The browser signs (validly) a challenge relay A issued for another identity. "
        "The MAC covers the identity hash, so it fails for the browser's hash.",
        b, 0, 409, "stale_challenge", "challenge_mac")

    # N10: the client edits the seq inside the challenge (MAC kept), re-signs.
    real = bytes.fromhex(challenge_by_id["A/browser/seq0"]["challenge_hex"])
    forged = real[:16] + u64(1) + real[24:]
    b = body_for("browser", forged, "Retichat Web", 1000000, 500,
                 {"client": "rns-js", "implementation": "PostInterface", "mode": 1})
    neg("forged-challenge-seq",
        "The browser rewrites the seq inside a real seq-0 challenge to 1 (the row's "
        "current seq) and signs it validly. The MAC no longer matches: a client "
        "cannot choose its own seq.",
        b, 1, 409, "stale_challenge", "challenge_mac")

    # N11: metadata.identity_hash that is not the key's hash.
    b = copy.deepcopy(browser_first)
    b["metadata"]["identity_hash"] = idents["other"].hash.hex()
    neg("identity-hash-mismatch",
        "browser-first plus metadata.identity_hash naming another identity (not a "
        "signed field, so the signature still verifies).",
        b, 0, 400, "identity_hash_mismatch", "metadata_identity_hash")

    # N12: a metadata key outside the signed set.
    b = copy.deepcopy(browser_first)
    b["metadata"]["wake_url"] = "https://attacker.example.net/v1/wake"
    neg("unsigned-metadata",
        "browser-first plus metadata.wake_url, a key the signature does not cover.",
        b, 0, 400, "unsigned_metadata", "metadata_keys")

    # N13: a browser asking for a transit mode, correctly signed.
    ch = challenge("A/browser/seq0/mode6", "A", "browser", 0)
    b = body_for("browser", ch, "Retichat Web", 1000000, 500,
                 {"client": "rns-js", "implementation": "PostInterface", "mode": 6})
    neg("browser-transit-mode",
        "A correctly signed rns-js registration with mode 6 (gateway). Browsers are "
        "endpoints: modes 3, 5 and 6 are refused for client rns-js.",
        b, 0, 400, "transit_mode_not_allowed", "client_mode_policy")

    # N14: upper-case hex public key.
    b = copy.deepcopy(browser_first)
    b["registration"]["public_key"] = b["registration"]["public_key"].upper()
    neg("uppercase-public-key",
        "browser-first with the public key in upper-case hex. Hex fields are "
        "lower-case only.",
        b, 0, 400, "bad_registration", "shape")

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

    lp_examples = [
        {"input_hex": "", "output_hex": lp(b"").hex()},
        {"input_utf8": "rns-js", "output_hex": lp(b"rns-js").hex()},
        {"input_utf8": REGISTER_DOMAIN.decode(), "output_hex": lp(REGISTER_DOMAIN).hex()},
    ]

    return {
        "spec": "Reticulum-post/REGISTRATION.md",
        "format_version": 1,
        "generator": "Reticulum-post/tools/registration_vectors.py (RNS " + RNS.__version__ + ")",
        "note": "Every byte below is derived from fixed labels; regenerate with the "
                "generator, never by hand. Hex is lower-case throughout.",
        "constants": {
            "register_domain": REGISTER_DOMAIN.decode(),
            "register_domain_hex": REGISTER_DOMAIN.hex(),
            "challenge_domain": CHALLENGE_DOMAIN.decode(),
            "challenge_domain_hex": CHALLENGE_DOMAIN.hex(),
            "challenge_length": 56,
            "challenge_layout": "nonce(16) || u64be(registration_seq) || HMAC-SHA256(relay_secret, challenge_domain || identity_hash(16) || u64be(registration_seq) || nonce(16))",
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
