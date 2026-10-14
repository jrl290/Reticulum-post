#!/usr/bin/env python3
"""
Checks a PHP node's Stage 1 registration from outside, with no credentials
(REGISTRATION-STAGE1.md §17.3, a gate of §13's phases).

Run from the workspace root, with the workspace .venv (RNS 1.5.2):

    .venv/bin/python Reticulum-post/tools/stage1_probe.py http://127.0.0.1:8080
    .venv/bin/python Reticulum-post/tools/stage1_probe.py https://<host>/reticulum
    .venv/bin/python Reticulum-post/tools/stage1_probe.py --enforced https://<host>/reticulum

It registers two test identities of its own, kept outside every repository
in ~/.reticulum-post-probe/ (mode 0700, made on first use), and checks, in
order:

  /health's registration object (version 1, schema migrated, the switch as
  expected); while identity 1 has not yet signed at that node, a legacy
  registration claiming it (200), whose session gets 401 once the signed
  registration has removed its row (so §4.5's statements run once on each
  node's database); the challenge, asked by key, with no-store; a signed
  registration answered with no plaintext token, whose encrypted token
  decrypts; an exchange; a second and a third registration, after which the
  first and second tokens get 409 session_superseded and the third 200; the
  first body replayed: 409 stale_challenge; an unknown session: 401; a legacy
  claim of identity 2: 200, and of identity 1: 403
  identity_requires_signature (with --enforced, both 403
  signature_required); goodbyes.

Each run re-binds the same two rows: identity 1's signed row, and identity
2's legacy row. Every request is timed from send to answer and printed with
its milliseconds; no token is ever printed. No request is cut off and none is
sent again: an answer later than 5 s is reported (DESIGN_PRINCIPLES.md §1)
and still checked. It exits 1, naming the step, if a check failed or an
answer came after 5 s, and 2 if it could not start. After a failed check it
still says goodbye to the sessions it holds.

It writes rows to the node's database: run it only where the node's operator
does. tools/registration_vectors.py supplies signed_bytes and
reference_decrypt, so the probe signs and decrypts as the vectors do.
"""

import argparse
import http.client
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import registration_vectors as rv  # noqa: E402  (exits 2 when RNS is not importable)
import RNS  # noqa: E402

IDENTITY_DIR = os.path.expanduser("~/.reticulum-post-probe")
ANSWER_WITHIN_S = 5.0  # DESIGN_PRINCIPLES.md §1
NAME = "Stage 1 probe"
METADATA = {"client": "rns-js", "implementation": "stage1_probe", "mode": 1}
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX96 = re.compile(r"[0-9a-f]{96}")
SEALED_TOKEN = re.compile(r"[0-9a-f]{320}")  # §5: 160 bytes for a 64-character token
LONG_HEX = re.compile(r"[0-9a-fA-F]{64,}")


class CannotStart(Exception):
    pass


class Failed(Exception):
    """A check failed; its line is printed already."""


def identity(directory, name):
    path = os.path.join(directory, name)
    if not os.path.exists(path):
        made = RNS.Identity()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(made.get_private_key())
    loaded = RNS.Identity.from_file(path)
    if loaded is None:
        raise CannotStart(path + " is not an RNS identity")
    return loaded


def identities():
    os.makedirs(IDENTITY_DIR, mode=0o700, exist_ok=True)
    mode = stat.S_IMODE(os.stat(IDENTITY_DIR).st_mode)
    if mode != 0o700:
        raise CannotStart("%s has mode %o, and it holds private keys: chmod 700 it" % (IDENTITY_DIR, mode))
    return identity(IDENTITY_DIR, "identity-1"), identity(IDENTITY_DIR, "identity-2")


def shown(body, raw=b""):
    """An answer as printed: never a token, nor any other long hex."""
    if body is None:
        text = raw.decode("utf-8", "replace").strip().replace("\n", " ")
    else:
        text = json.dumps(body, sort_keys=True)
    text = LONG_HEX.sub("<hex>", text)
    return text if len(text) <= 200 else text[:197] + "..."


class Probe:
    def __init__(self, base, enforced):
        self.base = base.rstrip("/")
        self.enforced = enforced
        self.steps = 0
        self.slowest_ms = 0.0
        self.late = []
        # The sessions to say goodbye to: label -> (interface_id, token).
        self.sessions = {}

    # ── one request, one line ───────────────────────────────────────────

    def call(self, label, method, path, body=None):
        """One request, timed from send to answer; never cut off, never sent again."""
        self.steps += 1
        step = self.steps
        url = urllib.parse.urlsplit(self.base + path)
        connection = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        conn = connection(url.hostname, url.port)  # no timeout: the probe cuts no request off
        target = url.path + ("?" + url.query if url.query else "")
        headers = {"Accept": "application/json", "Connection": "close"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        # A request still unanswered 5 s after it was sent is said then, once;
        # the watch decides nothing and ends at the answer.
        watch = threading.Timer(ANSWER_WITHIN_S, lambda: print(
            "  ...  %2d %s: no answer 5 s after it was sent (DESIGN_PRINCIPLES.md §1)" % (step, label), flush=True))
        watch.daemon = True
        sent = time.monotonic()
        watch.start()
        try:
            conn.request(method, target, body=data, headers=headers)
            response = conn.getresponse()
            raw = response.read()
            status = response.status
            answer_headers = {k.lower(): v for k, v in response.getheaders()}
        except (OSError, http.client.HTTPException) as e:
            raw, status, answer_headers = str(e).encode("utf-8"), None, {}
        finally:
            watch.cancel()
            conn.close()
        ms = (time.monotonic() - sent) * 1000.0
        self.slowest_ms = max(self.slowest_ms, ms)
        if ms > ANSWER_WITHIN_S * 1000.0:  # NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            self.late.append("%d %s (%.0f ms)" % (step, label, ms))
            print("  §1   %2d %s: answered after %.0f ms, over 5 s" % (step, label, ms), flush=True)
        try:
            parsed = json.loads(raw.decode("utf-8")) if status is not None else None
        except (UnicodeDecodeError, ValueError):
            parsed = None
        return {"step": step, "label": label, "status": status, "headers": answer_headers, "body": parsed, "raw": raw, "ms": ms}

    def line(self, answer, word, text):
        print("  %-4s %2d %s: %s  (%.0f ms)" % (word, answer["step"], answer["label"], text, answer["ms"]), flush=True)

    def expect(self, answer, status, error=None, then=None, note=""):
        """The answer's status (and error code), then `then`'s checks of its body; one line either way."""
        want = str(status) + ("" if error is None else " " + error)
        got, body = answer["status"], answer["body"]
        if got is None:
            problem = "expected %s, got no answer (%s)" % (want, shown(None, answer["raw"]))
        elif got != status or (error is not None and not (isinstance(body, dict) and body.get("error") == error)):
            problem = "expected %s, got %d %s" % (want, got, shown(body, answer["raw"]))
        elif not isinstance(body, dict):
            problem = "%d with a body that is not a JSON object: %s" % (got, shown(None, answer["raw"]))
        else:
            problem = then(body, answer["headers"]) if then is not None else None
        if problem:
            self.line(answer, "FAIL", problem)
            raise Failed("%d %s" % (answer["step"], answer["label"]))
        self.line(answer, "ok", want + note)
        return body

    # ── the requests ────────────────────────────────────────────────────

    def legacy(self, label, ident):
        metadata = dict(METADATA, identity_hash=ident.hash.hex())
        return self.call(label, "POST", "/v1/interfaces/register",
                         {"name": NAME, "bitrate": 1000000, "mtu": 500, "metadata": metadata})

    def exchange(self, label, interface_id, token):
        return self.call(label, "POST", "/v1/interfaces/exchange", {
            "interface_id": interface_id, "session_token": token,
            "ack_batch_ids": [], "max_packets": 1, "packets": [],
        })

    def goodbye(self, label, interface_id, token):
        return self.call(label, "POST", "/v1/interfaces/goodbye", {"interface_id": interface_id, "session_token": token})

    @staticmethod
    def legacy_session(body, _headers):
        if not isinstance(body.get("interface_id"), str) or body["interface_id"] == "" \
                or not isinstance(body.get("session_token"), str) or not HEX64.fullmatch(body["session_token"]):
            return "no legacy session in the answer: " + shown(body)
        return None

    def signed(self, label, ident, row=None):
        """Challenge, sign, register, decrypt. Returns (request body, interface_id, token)."""
        h = ident.hash.hex()
        public_key = ident.get_public_key().hex()

        def challenge_ok(body, headers):
            if "no-store" not in headers.get("cache-control", ""):
                return "no Cache-Control: no-store (got %r)" % headers.get("cache-control")
            if body.get("status") != "challenge" or body.get("version") != 1 or body.get("identity_hash") != h \
                    or not isinstance(body.get("challenge"), str) or not HEX96.fullmatch(body["challenge"]):
                return "not §3's answer for this identity: " + shown(body)
            return None

        body = self.expect(self.call("challenge for " + label + ", by key", "POST", "/v1/interfaces/challenge",
                                     {"public_key": public_key}), 200, then=challenge_ok, note=", no-store")
        request = {"name": NAME, "bitrate": 1000000, "mtu": 500, "metadata": dict(METADATA),
                   "registration": {"version": 1, "public_key": public_key, "challenge": body["challenge"]}}
        signed, _ = rv.signed_bytes(request)
        request["registration"]["signature"] = ident.sign(signed).hex()
        token = []

        def registered_ok(body, _headers):
            for key in ("session_token", "registration_seq"):
                if key in body:
                    return "the answer carries " + key
            if body.get("status") != "registered" or body.get("identity_hash") != h \
                    or not isinstance(body.get("interface_id"), str) or not HEX32.fullmatch(body["interface_id"]) \
                    or not isinstance(body.get("session_token_encrypted"), str) \
                    or not SEALED_TOKEN.fullmatch(body["session_token_encrypted"]):
                return "not §5's answer: " + shown(body)
            if row is not None and body["interface_id"] != row:
                return "re-bound another row (%s, not %s)" % (body["interface_id"][:8], row[:8])
            blob = bytes.fromhex(body["session_token_encrypted"])
            reference = rv.reference_decrypt(blob, ident.get_private_key()[:32], ident.hash)
            if reference.get("result") != "ok":
                return "the encrypted token does not decrypt: " + str(reference.get("result"))
            if ident.decrypt(blob) != reference["session_token"].encode("ascii"):
                return "RNS Identity.decrypt does not give the reference's plaintext"
            token.append(reference["session_token"])
            return None

        body = self.expect(self.call("signed registration " + label, "POST", "/v1/interfaces/register", request), 200,
                           then=registered_ok, note=", no plaintext token, the encrypted one decrypts")
        return request, body["interface_id"], token[0]

    # ── the run ─────────────────────────────────────────────────────────

    def run(self, id1, id2):
        def health_ok(body, _headers):
            reg = body.get("registration")
            online = reg.get("browsers_online") if isinstance(reg, dict) else None
            if not isinstance(reg, dict) or reg.get("version") != 1 or reg.get("schema_migrated") is not True \
                    or reg.get("enforce_signed_registration") is not self.enforced \
                    or not isinstance(online, dict) or not all(isinstance(online.get(k), int) for k in ("signed", "legacy")) \
                    or not isinstance(reg.get("hash_only_challenges"), int):
                return "expected registration version 1, schema_migrated true, enforce_signed_registration %s: %s" \
                       % ("true" if self.enforced else "false", shown(reg))
            return None

        self.expect(self.call("/health", "GET", "/health"), 200, then=health_ok,
                    note=", registration version 1, schema migrated, switch " + ("on" if self.enforced else "off"))

        removed = None
        if not self.enforced:
            answer = self.legacy("legacy claim of identity 1", id1)
            if answer["status"] == 200:
                body = self.expect(answer, 200, then=self.legacy_session, note=": identity 1 has not signed here yet")
                removed = (body["interface_id"], body["session_token"])
                self.sessions["identity 1's legacy row"] = removed
            else:
                self.expect(answer, 403, "identity_requires_signature",
                            note=": identity 1 signed here on an earlier run, which checked the removal")

        body_a, row, token_a = self.signed("A", id1)
        self.sessions["identity 1"] = (row, token_a)
        if removed is not None:
            self.expect(self.exchange("the removed legacy row's session", *removed), 401, "unauthorized")
            del self.sessions["identity 1's legacy row"]
        self.expect(self.exchange("exchange on A", row, token_a), 200)

        tokens = [token_a]
        for label in ("B", "C"):
            tokens.append(self.signed(label, id1, row)[2])
            self.sessions["identity 1"] = (row, tokens[-1])
        for label, token in (("A", tokens[0]), ("B", tokens[1])):
            self.expect(self.exchange("exchange on " + label + " after C", row, token), 409, "session_superseded")
        self.expect(self.exchange("exchange on C", row, tokens[2]), 200)

        self.expect(self.call("A's body again", "POST", "/v1/interfaces/register", body_a), 409, "stale_challenge")
        self.expect(self.exchange("an unknown session", secrets.token_hex(16), secrets.token_hex(32)), 401, "unauthorized")

        if self.enforced:
            self.expect(self.legacy("legacy claim of identity 2", id2), 403, "signature_required")
            self.expect(self.legacy("legacy claim of identity 1", id1), 403, "signature_required")
        else:
            body = self.expect(self.legacy("legacy claim of identity 2", id2), 200, then=self.legacy_session)
            self.sessions["identity 2"] = (body["interface_id"], body["session_token"])
            self.expect(self.legacy("legacy claim of identity 1", id1), 403, "identity_requires_signature")

        def offline(body, _headers):
            return None if body.get("status") == "offline" else "the row is not offline: " + shown(body)

        for label in list(self.sessions):
            interface_id, token = self.sessions.pop(label)
            self.expect(self.goodbye("goodbye, " + label, interface_id, token), 200, then=offline, note=", offline")

    def leave(self):
        """After a failed check: goodbye to each session still held, printed, never sent again."""
        for label in list(self.sessions):
            interface_id, token = self.sessions.pop(label)
            answer = self.goodbye("goodbye, " + label, interface_id, token)
            status = answer["status"]
            self.line(answer, "..", "no answer" if status is None else "%d %s" % (status, shown(answer["body"], answer["raw"])))


def main():
    parser = argparse.ArgumentParser(description="Check a PHP node's Stage 1 registration (REGISTRATION-STAGE1.md §17.3).")
    parser.add_argument("base_url", help="the node's base URL, e.g. http://127.0.0.1:8080 or https://<host>/reticulum")
    parser.add_argument("--enforced", action="store_true", help="expect the node's enforce_signed_registration switch on")
    args = parser.parse_args()
    if urllib.parse.urlsplit(args.base_url).scheme not in ("http", "https"):
        print("stage1_probe: the base URL must be http:// or https://", file=sys.stderr)
        return 2
    try:
        id1, id2 = identities()
    except (CannotStart, OSError) as e:
        print("stage1_probe: " + str(e), file=sys.stderr)
        return 2

    print("stage1_probe %s, switch expected %s" % (args.base_url, "on" if args.enforced else "off"))
    print("  identity 1 %s, identity 2 %s (%s)" % (id1.hash.hex(), id2.hash.hex(), IDENTITY_DIR), flush=True)
    probe = Probe(args.base_url, args.enforced)
    try:
        probe.run(id1, id2)
    except Failed as failed:
        probe.leave()
        print("FAIL: step %s" % failed)
        if probe.late:
            print("      and answers after 5 s (DESIGN_PRINCIPLES.md §1): " + "; ".join(probe.late))
        return 1
    if probe.late:
        print("FAIL: answers after 5 s (DESIGN_PRINCIPLES.md §1): " + "; ".join(probe.late))
        return 1
    print("PASS: %d requests, every answer within 5 s (slowest %.0f ms)" % (probe.steps, probe.slowest_ms))
    return 0


if __name__ == "__main__":
    sys.exit(main())
