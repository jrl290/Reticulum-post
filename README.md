# Reticulum Post

HTTP exchange bridge for the [Reticulum Network Stack](https://reticulum.network/). Enables browser-based and shared-hosting Reticulum nodes without raw sockets, WebSockets, or special Apache modules.

## Architecture

```
┌──────────────────┐     HTTP      ┌──────────────────┐     HTTP      ┌──────────────────┐
│  Browser / Node  │ ◄────exchange──►│  Reticulum-php   │ ◄────exchange──►│  Python RNS Node │
│  (JS Client)     │               │  (Router Daemon)  │               │  (PostInterface)  │
└──────────────────┘               └──────────────────┘               └────────┬─────────┘
                                                                               │
                                                                        ┌──────┴──────┐
                                                                        │  Reticulum   │
                                                                        │  Backbone    │
                                                                        └─────────────┘
```

- **php/** — The router daemon. Accepts HTTP exchange requests from clients, routes packets between them, stores path state. Deploy on any PHP 8.1+ host with SQLite.
- **js/** — Browser/client library. Pure ES modules (no npm). Implements the RNS protocol stack (identities, links, announces, LXMF messaging) with HTTP exchange transport.
- **python/** — PostInterface extension for Python RNS nodes. Drop into `~/.reticulum/interfaces/` to connect a Python node to a Reticulum-php router.

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
import Reticulum from "./js/src/reticulum.js";
import HttpExchangeInterface from "./js/src/interfaces/http_exchange_interface.js";

const rns = new Reticulum();
const iface = new HttpExchangeInterface("My Client", "https://your-node.example.com/reticulum");
rns.addInterface(iface);
```

## Requirements

| Component | Requirements |
|-----------|-------------|
| **php/** | PHP 8.1+, ext-sqlite3, write access to `var/` |
| **js/** | Modern browser with ES module support |
| **python/** | Python 3.9+, RNS (`pip install rns`) |

## Protocol

All three components speak the same HTTP exchange protocol:

1. **Register** — `POST /v1/interfaces/register` → get `interface_id` + `session_token`
2. **Exchange** — `POST /v1/interfaces/exchange` → upload queued packets, receive delivery packets
3. Packets are base64-encoded raw Reticulum frames in JSON

## License

MIT — see [LICENSE](LICENSE)
