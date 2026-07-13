"""
PostInterface — HTTP POST-based interface for Reticulum.

Connects a Reticulum transport node to a remote Reticulum-php node
via HTTP exchange (the same protocol as rns_transport.php).

Supports two modes:
  - Poll mode (no wake_url): polls the PHP node on a timer
  - Wake mode (wake_url set): bidirectional peer connection. The bridge
    runs a lightweight HTTP server to receive /v1/wake calls from the
    PHP node, triggering immediate exchange. Polling runs as a low-frequency
    fallback.

Place this file in ~/.reticulum/interfaces/ and add to config:

  [[PostInterface]]
    type = PostInterface
    enabled = yes
    node_url = https://selectivesubconscious.com/reticulum
    name = PHP Node Bridge
    wake_url = https://my-bridge.example.com/wake   # URL the PHP node calls to wake us
    wake_listen_host = 0.0.0.0                       # bind address for wake server
    wake_listen_port = 8080                          # port for wake server
"""

import threading
import time
import base64
import json
import os
import secrets
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

from RNS.Interfaces.Interface import Interface
import RNS


class PostInterface(Interface):
    DEFAULT_IFAC_SIZE = 16
    HW_MTU = 500
    BITRATE_GUESS = 100_000_000

    owner = None
    node_url = None
    wake_url = None
    wake_listen_host = "127.0.0.1"
    wake_listen_port = 8080
    online = False
    _interface_id = None
    _session_token = None
    _peer_interface_id = None   # pre-generated for PHP node to call us
    _peer_session_token = None  # pre-generated for PHP node to call us
    _max_batch = 64
    _idle_ms = 1000
    _poll_thread = None
    _wake_server = None
    _wake_server_thread = None
    _pending_wake = False
    _wake_lock = threading.Lock()
    _running = False
    _outgoing_queue = []
    _queue_lock = threading.Lock()
    _ack_ids = []
    _batch_seq = 0

    def __init__(self, owner, configuration):
        super().__init__()

        ifconf = Interface.get_config_obj(configuration)
        name = ifconf["name"]
        self.name = name
        self.owner = owner

        node_url = ifconf["node_url"] if "node_url" in ifconf else None
        if not node_url:
            raise ValueError(f"No node_url specified for {self}")
        self.node_url = node_url.rstrip('/')

        # wake_url: when present, enables bidirectional wake-driven mode.
        # The bridge runs an HTTP server to receive /v1/wake from the PHP node.
        wake_url = ifconf.get("wake_url")
        if wake_url:
            self.wake_url = str(wake_url).rstrip('/')
        else:
            self.wake_url = None

        self.wake_listen_host = str(ifconf.get("wake_listen_host", "127.0.0.1"))
        self.wake_listen_port = int(ifconf.get("wake_listen_port", 8080))

        # Read optional config with proper defaults
        self.HW_MTU = 500
        self.bitrate = 100_000_000
        # Interface mode — uses the standard RNS mode enum.
        #   MODE_FULL (1)     — endpoint: announces represent THIS node
        #   MODE_GATEWAY (6)  — relay:   announces represent remote peers
        # Sent to PHP router in metadata to control local_destination registration.
        mode_map = {
            "full":             RNS.Interfaces.Interface.Interface.MODE_FULL,
            "point_to_point":   RNS.Interfaces.Interface.Interface.MODE_POINT_TO_POINT,
            "access_point":     RNS.Interfaces.Interface.Interface.MODE_ACCESS_POINT,
            "roaming":          RNS.Interfaces.Interface.Interface.MODE_ROAMING,
            "boundary":         RNS.Interfaces.Interface.Interface.MODE_BOUNDARY,
            "gateway":          RNS.Interfaces.Interface.Interface.MODE_GATEWAY,
        }
        mode_str = str(ifconf.get("mode", "full")).lower()
        self._rns_mode = mode_map.get(mode_str, RNS.Interfaces.Interface.Interface.MODE_FULL)
        if "bitrate" in ifconf:
            try:
                self.bitrate = int(ifconf["bitrate"])
            except (ValueError, TypeError):
                pass
        if "mtu" in ifconf:
            try:
                self.HW_MTU = int(ifconf["mtu"])
            except (ValueError, TypeError):
                pass

        # Override poll interval from config (seconds, float).
        # When set, this takes precedence over the server-provided
        # idle_exchange_interval_ms for the local poll rate.
        self._poll_interval = None
        if "poll_interval" in ifconf:
            try:
                self._poll_interval = float(ifconf["poll_interval"])
            except (ValueError, TypeError):
                pass

        self.IN = True
        self.OUT = True
        self.mode = RNS.Interfaces.Interface.Interface.MODE_FULL
        self.online = False
        self._running = True
        self._poll_thread = None

        # Register with the PHP node
        try:
            self._register()
        except Exception as e:
            RNS.log(f"PostInterface[{self.name}]: Registration failed: {e}", RNS.LOG_ERROR)
            raise e

        # Verify we're in the transport interfaces list
        if hasattr(RNS.Transport, 'interfaces') and self in RNS.Transport.interfaces:
            RNS.log(f"PostInterface[{self.name}]: Registered in Transport.interfaces (OUT={self.OUT}, IN={self.IN})", RNS.LOG_NOTICE)
        else:
            RNS.log(f"PostInterface[{self.name}]: NOT in Transport.interfaces! Attempting self-registration...", RNS.LOG_ERROR)
            if hasattr(RNS.Transport, 'interfaces'):
                RNS.Transport.interfaces.append(self)
                RNS.log(f"PostInterface[{self.name}]: Self-registered in Transport.interfaces", RNS.LOG_NOTICE)

        # Mark as online and start the exchange poll thread
        self.online = True
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

        # Start wake HTTP server if in wake mode
        if self.wake_url:
            self._start_wake_server()

        poll_info = f"poll_interval={self._poll_interval}s" if self._poll_interval is not None else f"idle_ms={self._idle_ms}"
        mode_info = "wake" if self.wake_url else "poll"
        RNS.log(f"PostInterface[{self.name}]: Online ({mode_info} mode, {poll_info})", RNS.LOG_NOTICE)

    def _register(self):
        """Register this interface with the PHP node.

        In poll mode: registers as a regular client (rns-post-interface).
        In wake mode: registers as a PHP peer (reticulum-php) with
        pre-generated credentials so the remote node can call us back
        via /v1/wake and /v1/interfaces/exchange.
        """
        metadata = {
            'mode': self._rns_mode,
        }

        if self.wake_url:
            # Bidirectional peer mode: pre-generate credentials for the PHP
            # node to call us back, and send them in the register handshake.
            self._peer_interface_id = secrets.token_hex(16)
            self._peer_session_token = secrets.token_hex(32)

            # peer_url is the literal wake endpoint — used as-is.
            metadata.update({
                'client': 'reticulum-php',
                'implementation': 'PostInterface',
                'peer_url': self.wake_url,
                'peer_interface_id': self._peer_interface_id,
                'peer_session_token': self._peer_session_token,
            })
            RNS.log(f"PostInterface[{self.name}]: Registering as PHP peer (wake mode)", RNS.LOG_NOTICE)
        else:
            # Poll mode: regular client.
            metadata.update({
                'client': 'rns-post-interface',
                'implementation': 'PostInterface',
                'transport': 'tcp-backbone-gateway' if self._rns_mode == RNS.Interfaces.Interface.Interface.MODE_GATEWAY else 'http-exchange',
            })

        body = {
            'name': f'RNS PostInterface ({self.name})',
            'bitrate': self.bitrate,
            'mtu': self.HW_MTU,
            'metadata': metadata,
        }
        resp = self._http_post(f"{self.node_url}/v1/interfaces/register", body)
        self._interface_id = resp.get('interface_id')
        self._session_token = resp.get('session_token')
        self._max_batch = int(resp.get('max_batch_packets', 64))
        self._idle_ms = int(resp.get('idle_exchange_interval_ms', 1000))
        if not self._interface_id or not self._session_token:
            raise RuntimeError("Registration did not return credentials")

        if self.wake_url:
            RNS.log(
                f"PostInterface[{self.name}]: Peer handshake complete — "
                f"we call them via {self._interface_id[:8]}..., "
                f"they call us via {self._peer_interface_id[:8]}...",
                RNS.LOG_NOTICE
            )

    def _http_post(self, url, body):
        """Make an HTTP POST request."""
        data = json.dumps(body).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={
            'Content-Type': 'application/json',
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='replace')
            raise RuntimeError(f"HTTP {e.code}: {error_body[:200]}")
        except Exception as e:
            raise RuntimeError(f"HTTP POST failed: {e}")

    def process_incoming(self, data):
        """Called when we receive a packet from the PHP node (via exchange).
        The data is a raw Reticulum packet that the PHP node wants to send
        to the backbone.
        """
        self.rxb += len(data)
        # Log inbound packet for diagnostics
        if len(data) >= 18:
            dest = data[2:18].hex() if len(data) >= 18 else '?'
            pkt_type = data[0] & 0x03 if data else -1
            types = {0:'DATA',1:'ANNOUNCE',2:'LINK',3:'PROOF'}
            tname = types.get(pkt_type, str(pkt_type))
            RNS.log(f"PostInterface IN: {tname} dest={dest[:12]}... len={len(data)}", RNS.LOG_NOTICE)

        # Fix: the PHP relay passes proofs through unchanged, preserving
        # the hop count set by the responder (browser), which is always 0.
        # RNS Transport expects the proof's hop count to match the
        # forward-path remaining_hops for LRPROOF (link table check), and
        # while regular proofs use the reverse table (interface-based, not
        # hop-based), incrementing is harmless and ensures consistency.
        if len(data) >= 2:
            flags = data[0]
            pkt_type = flags & 0x03
            if pkt_type == 0x03:  # PROOF
                hops = data[1]
                if hops == 0:
                    data = bytearray(data)
                    data[1] = 1
                    data = bytes(data)

        # Forward to RNS transport for processing and forwarding to backbone
        self.owner.inbound(data, self)

    def process_outgoing(self, data):
        """Called by RNS when it wants to send a packet through this interface.
        We queue it for the next exchange with the PHP node.
        """
        if self.online:
            with self._queue_lock:
                self._outgoing_queue.append(data)
            self.txb += len(data)
            if len(data) >= 18:
                dest = data[2:18].hex() if len(data) >= 18 else '?'
                pkt_type = data[0] & 0x03 if data else -1
                types = {0:'DATA',1:'ANNOUNCE',2:'LINK',3:'PROOF'}
                tname = types.get(pkt_type, str(pkt_type))
                RNS.log(f"PostInterface OUT: {tname} dest={dest[:12]}... len={len(data)}", RNS.LOG_NOTICE)

    # ---- Wake HTTP server ----

    def _start_wake_server(self):
        """Start a lightweight HTTP server to receive /v1/wake from the PHP node."""
        iface = self  # capture for the handler

        class WakeHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # suppress access logs

            def do_POST(self):
                if self.path != '/v1/wake':
                    self.send_error(404)
                    return

                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = json.loads(self.rfile.read(length))
                    waker_url = body.get('waker_url', '')

                    # Security: only accept wakes from our configured PHP node.
                    if not waker_url or not waker_url.startswith(iface.node_url):
                        self.send_error(403)
                        return

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'ok'}).encode())

                    # Trigger an immediate exchange from the poll loop.
                    with iface._wake_lock:
                        iface._pending_wake = True
                    RNS.log(f"PostInterface[{iface.name}]: Wake received from {waker_url}", RNS.LOG_DEBUG)

                except Exception as e:
                    self.send_error(400)

            def do_GET(self):
                if self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'ok', 'mode': 'wake'}).encode())
                else:
                    self.send_error(404)

        try:
            self._wake_server = HTTPServer((self.wake_listen_host, self.wake_listen_port), WakeHandler)
            self._wake_server_thread = threading.Thread(
                target=self._wake_server.serve_forever, daemon=True
            )
            self._wake_server_thread.start()
            RNS.log(
                f"PostInterface[{self.name}]: Wake server listening on "
                f"{self.wake_listen_host}:{self.wake_listen_port}",
                RNS.LOG_NOTICE
            )
        except Exception as e:
            RNS.log(f"PostInterface[{self.name}]: Wake server failed to start: {e}", RNS.LOG_ERROR)

    # ---- Exchange loop ----

    def _poll_loop(self):
        """Background thread that periodically exchanges packets with the PHP node.

        In poll mode (no wake_url): polls at the configured interval.
        In wake mode (wake_url set): polls at a much lower frequency as a
        fallback. The primary trigger is the PHP node waking us via /v1/wake,
        which sets _pending_wake for immediate exchange.
        """
        last_exchange = 0
        _min_interval = 3.0
        _wake_fallback_interval = 60.0

        while self._running:
            now = time.time()

            # Check for pending wake OR queued outbound packets.
            with self._wake_lock:
                triggered = self._pending_wake
                self._pending_wake = False

            with self._queue_lock:
                has_outbound = len(self._outgoing_queue) > 0

            if not triggered and not has_outbound:
                # Determine poll interval.
                if self._poll_interval is not None:
                    interval = max(self._poll_interval, _min_interval)
                elif self.wake_url is not None:
                    interval = _wake_fallback_interval
                else:
                    interval = max(self._idle_ms / 2000.0, _min_interval)

                if now - last_exchange < interval:
                    time.sleep(0.5)
                    continue

            try:
                self._do_exchange()
                last_exchange = now
            except Exception as e:
                RNS.log(f"PostInterface[{self.name}]: Exchange error: {e}", RNS.LOG_WARNING)
                time.sleep(1)

    def _do_exchange(self):
        """Perform a single exchange with the PHP node."""
        with self._queue_lock:
            packets = self._outgoing_queue[:self._max_batch]
            self._outgoing_queue = self._outgoing_queue[self._max_batch:]
            ack_ids = list(self._ack_ids)
            self._ack_ids = []

        body = {
            'interface_id': self._interface_id,
            'session_token': self._session_token,
            'ack_batch_ids': ack_ids,
            'max_packets': self._max_batch,
            'packets': [base64.b64encode(p).decode('ascii') for p in packets],
        }
        if packets:
            self._batch_seq += 1
            body['batch_id'] = f'rns-post-{int(time.time()*1000)}-{self._batch_seq}'

        resp = self._http_post(f"{self.node_url}/v1/interfaces/exchange", body)

        # Process delivery packets → send them as incoming.
        delivery = resp.get('delivery_packets', [])
        delivery_batch = resp.get('delivery_batch_id')

        for pkt_b64 in delivery:
            if not isinstance(pkt_b64, str) or not pkt_b64:
                continue
            try:
                raw = base64.b64decode(pkt_b64)
                self.process_incoming(raw)
            except Exception as e:
                RNS.log(f"PostInterface[{self.name}]: Failed to decode delivery packet: {e}", RNS.LOG_WARNING)

        if isinstance(delivery_batch, str) and delivery_batch:
            self._ack_ids.append(delivery_batch)

        return resp

    def should_ingress_limit(self):
        return False

    def __str__(self):
        return f"PostInterface[{self.name}]"


# Register the interface class
interface_class = PostInterface
