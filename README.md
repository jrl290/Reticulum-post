# Reticulum Post

> **⚠️ Work in Progress** — This project is under active development. APIs, protocols, and the on-disk storage format may change.  
> **🤖 AI-Assisted Development** — A significant portion of this codebase was generated and refined with AI coding assistance (GitHub Copilot / Claude). All generated code has been reviewed and tested by a human developer.

HTTP exchange bridge for the [Reticulum Network Stack](https://reticulum.network/). Provides three components that work together to connect browser clients and Python nodes over standard HTTP — no raw sockets, no WebSockets, no special server modules required.

## Architecture

```
┌──────────────────┐     HTTP POST      ┌──────────────────────────┐
│  Retichat Web    │ ◄────exchange──────►│  Reticulum-post (PHP)    │
│  (Browser JS)    │                    │  ┌────────────────────┐  │
│                  │                    │  │  HTTP Exchange API │  │
│  Pull-poll       │                    │  │  POST /v1/register │  │
│  client          │                    │  │  POST /v1/exchange │  │
└──────────────────┘                    │  └────────┬───────────┘  │
                                        │           │              │
┌──────────────────┐     HTTP POST      │  ┌────────┴───────────┐  │
│  Python RNS Node │ ◄────exchange──────►│  │  Python Bridge     │  │
│  (rnsd)          │                    │  │  (PostInterface)   │  │
│                  │                    │  └────────┬───────────┘  │
│  Push-push       │                    └───────────┼──────────────┘
│  peer            │                                │
└──────────────────┘                        ┌───────┴───────┐
                                            │  Reticulum    │
                                            │  Backbone     │
                                            └───────────────┘
```

## Project Components

### Server: PHP (`php/`)
The HTTP exchange router daemon. Accepts POST requests from both browser clients and Python nodes, routes Reticulum packets between registered interfaces, and maintains path state in SQLite. Designed for shared hosting — runs on any PHP 8.1+ host with `ext-sqlite3` and write access to a `var/` directory.

- **Entry point**: `php/src/index.php`
- **API**: `POST /v1/interfaces/register`, `POST /v1/interfaces/exchange`
- **Storage**: SQLite (`var/reticulum.db`) — interface registry, packet queues, path cache

### Client: Browser JS
The browser-side RNS protocol stack used by [Retichat Web](https://github.com/jrl290/Retichat-js). Pure ES modules loaded via import maps — no npm, no build step. Implements identities, destinations, links, announces, LXMF messaging, and the HTTP exchange transport client. Lives in `js/`.

### Bridge: Python (`python/`)
A `PostInterface` extension for Python RNS nodes. Drop into `~/.reticulum/interfaces/` to connect a standard Python `rnsd` to a Reticulum-post router over HTTP. The Python node registers as an interface and exchanges packets via the same HTTP API as browser clients.

## Transport Mechanisms

### Pull-Poll (One-Way Initiation)

The pull-poll model is designed for **browser clients and firewalled nodes** that cannot accept inbound connections. The client initiates every exchange: it POSTs queued outbound packets and receives any queued inbound packets in the HTTP response.

```
Client                              PHP Router
  │                                     │
  │── POST /register ──────────────────►│  one-time setup
  │◄─ { interface_id, session_token } ─│
  │                                     │
  │── POST /exchange { pkts: [...] } ──►│  upload outbound
  │◄─ { pkts: [...] } ─────────────────│  receive inbound
  │                                     │
  │        ... poll interval ...        │
  │                                     │
  │── POST /exchange { pkts: [...] } ──►│
  │◄─ { pkts: [...] } ─────────────────│
```

- Single HTTP request per exchange cycle
- Client controls timing via poll interval
- No persistent connections, no server push
- Works through NAT, firewalls, proxies, CDNs
- Poll interval is adaptive — speeds up to ~1s when messages are flowing, backs off to ~5s when idle

### Push-Push (Two-Way Initiation)

When two nodes have **both** registered interfaces with the router **and** exchanged announces establishing a mutual path, either node can push packets at any time. This is the native Reticulum transport model adapted to HTTP.

```
Node A                               PHP Router                              Node B
  │                                     │                                      │
  │── POST /exchange {pkts:[announce]}─►│                                      │
  │                                     │── POST /exchange {pkts:[announce]}──►│
  │                                     │◄─ {pkts:[]} ────────────────────────│
  │◄─ {pkts:[]} ───────────────────────│                                      │
  │                                     │                                      │
  │         ╔════ Path Established ════╗│                                      │
  │         ║   (bidirectional)     ║   │                                      │
  │                                     │                                      │
  │── POST /exchange {pkts:[LXMF]} ────►│  A pushes to B                       │
  │                                     │◄─ {pkts:[LXMF]} ────────────────────│
  │                                     │── POST /exchange {pkts:[LXMF]} ─────►│  B pushes to A
  │◄─ {pkts:[LXMF]} ───────────────────│                                      │
```

- Both sides independently POST to the exchange endpoint on their own schedules
- The router maintains per-interface queues and delivers packets on the next exchange
- Enables real-time(-ish) bidirectional chat without WebSockets
- Falls back gracefully to pull-poll if one side goes offline

## Quick Start

### 1. Deploy the PHP router

```bash
cp php/src/config.template.toml php/src/config.toml
# Edit host_url to match your domain
# Point your web server to php/src/
```

### 2. Connect a Python node

```ini
# ~/.reticulum/config
[[PostInterface]]
    type = PostInterface
    enabled = yes
    node_url = https://your-node.example.com/reticulum
```

### 3. Connect from a browser

```javascript
import { Reticulum, PostInterface } from "./lib/rns/reticulum.js";

const rns = new Reticulum();
const iface = new PostInterface("My Client", "https://your-node.example.com/reticulum", myHash);
rns.addInterface(iface);
```

## Requirements

| Component | Requirements |
|-----------|-------------|
| **php/** | PHP 8.1+, ext-sqlite3, write access to `var/` |
| **js/** | Modern browser with ES module support |
| **python/** | Python 3.9+, RNS (`pip install rns`) |

## HTTP Exchange Protocol

All three components speak the same HTTP exchange protocol:

1. **Register** — `POST /v1/interfaces/register` → `{ interface_id, session_token }`
2. **Exchange** — `POST /v1/interfaces/exchange` → upload queued packets, receive delivery packets
3. Packets are base64-encoded raw Reticulum frames transported in JSON

## Related Projects

- [Retichat Web](https://github.com/jrl290/Retichat-js) — Browser chat client using this exchange
- [Reticulum](https://github.com/markqvist/Reticulum) — Python reference implementation
- [Retichat Android](https://github.com/jrl290/Retichat-android) — Native Android client
- [Retichat iOS](https://github.com/jrl290/Retichat-ios) — Native iOS client

## License

MIT — see [LICENSE](LICENSE)
