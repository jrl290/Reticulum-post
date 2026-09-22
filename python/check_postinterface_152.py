#!/usr/bin/env python3
"""
Check that PostInterface satisfies the RNS 1.5.2 interface contract.

Run with the workspace venv, which has rns 1.5.2 installed:

  /Users/james/Offline/Reticulum/.venv/bin/python3 \
      Reticulum-post/python/check_postinterface_152.py

It starts a Reticulum instance on a throwaway config with no interfaces,
constructs a PostInterface against the live selectiv PHP node the same way
application code does (test-harnesses/distro-pipeline/lxmf_distro_sender.py),
and asserts that the interface registered itself through the canonical path
and carries every attribute Transport 1.5.2 reads off an interface.

Exits 0 on success, 1 on the first failed assertion.
"""

import os
import shutil
import sys
import tempfile
import time

import RNS
from RNS.Interfaces.PostInterface import PostInterface

NODE_URL = os.environ.get("CHECK_NODE_URL", "https://selectivesubconscious.com/reticulum")
ONLINE_TIMEOUT = 20.0

# Everything Transport 1.5.2 reads off an interface. The entries after the
# blank-line groups are the ones Reticulum._add_interface() is responsible
# for, which a directly constructed interface used to be missing.
REQUIRED_ATTRIBUTES = [
    # Interface.__init__()
    "rxb", "txb", "arxb", "atxb", "prxb", "ptxb",
    "created", "detached", "online", "bitrate", "HW_MTU",
    "ingress_control", "bootstrap_only", "recursive_prs",
    "announces_from_internal", "announces_to_internal",
    "parent_interface", "spawned_interfaces", "tunnel_id",
    "held_announces", "ia_freq_deque", "oa_freq_deque",
    "ip_freq_deque", "op_freq_deque",
    "ic_max_held_announces", "ic_burst_freq", "ic_burst_freq_new",
    "ic_pr_burst_freq", "ic_pr_burst_freq_new", "ic_new_time",
    "ic_burst_penalty", "ic_held_release_interval", "ec_pr_freq",
    "egress_control", "reports_phy_stats", "phy_keepalive",
    # Reticulum._add_interface() / interface_post_init()
    "mode", "gravity", "IN", "OUT", "ifac_size",
    "ifac_netname", "ifac_netkey", "ifac_identity",
    "announce_cap", "announce_rate_target",
    "announce_rate_grace", "announce_rate_penalty",
]

REQUIRED_METHODS = [
    "received_announce", "sent_announce",
    "received_path_request", "sent_path_request",
    "should_ingress_limit", "should_ingress_limit_pr", "should_egress_limit_pr",
    "hold_announce", "process_held_announces", "process_announce_queue",
    "protocol_violation", "ifac_violation", "packet_filter_hit",
    "get_hash", "optimise_mtu", "final_init", "detach",
    "process_incoming", "process_outgoing",
]

failures = []


def check(condition, description):
    if condition:
        print(f"  ok   {description}")
    else:
        print(f"  FAIL {description}")
        failures.append(description)


def main():
    print(f"RNS {RNS.__version__} from {os.path.dirname(RNS.__file__)}")
    print(f"PostInterface from {sys.modules['RNS.Interfaces.PostInterface'].__file__}")

    configdir = tempfile.mkdtemp(prefix="postinterface-152-")
    with open(os.path.join(configdir, "config"), "w") as handle:
        handle.write("[reticulum]\n  enable_transport = no\n  share_instance = no\n"
                     "[logging]\n  loglevel = 3\n[interfaces]\n")

    reticulum = RNS.Reticulum(configdir=configdir)
    iface = None

    try:
        iface = PostInterface(RNS.Transport, {"name": "check152", "node_url": NODE_URL,
                                              "mode": "full", "poll_interval": 0.5})

        deadline = time.time() + ONLINE_TIMEOUT
        while not iface.online and time.time() < deadline:
            time.sleep(0.25)
        check(iface.online, f"interface came online within {ONLINE_TIMEOUT:.0f}s")

        registered = [i for i in RNS.Transport.interfaces if i is iface]
        check(len(registered) == 1,
              f"interface is in Transport.interfaces exactly once (found {len(registered)})")

        missing = [a for a in REQUIRED_ATTRIBUTES if not hasattr(iface, a)]
        check(not missing, f"all {len(REQUIRED_ATTRIBUTES)} Transport-read attributes present"
                           + (f" — missing {missing}" if missing else ""))

        not_callable = [m for m in REQUIRED_METHODS if not callable(getattr(iface, m, None))]
        check(not not_callable, f"all {len(REQUIRED_METHODS)} contract methods callable"
                                + (f" — missing {not_callable}" if not_callable else ""))

        check(iface.mode == RNS.Interfaces.Interface.Interface.MODE_FULL,
              f"mode is MODE_FULL ({iface.mode})")
        check(iface.ifac_size == iface.DEFAULT_IFAC_SIZE,
              f"ifac_size is the default ({iface.ifac_size})")
        check(abs(iface.announce_cap - RNS.Reticulum.ANNOUNCE_CAP / 100.0) < 1e-9,
              f"announce_cap is ANNOUNCE_CAP/100 ({iface.announce_cap})")
        check(iface.OUT is True and iface.IN is True, "IN and OUT are both set")
        check(isinstance(iface.get_hash(), bytes) and len(iface.get_hash()) == 32,
              "get_hash() returns a 32-byte hash")

        RNS.Transport.add_interface(iface)
        registered = [i for i in RNS.Transport.interfaces if i is iface]
        check(len(registered) == 1,
              f"a second Transport.add_interface() does not duplicate it (found {len(registered)})")

        iface.detach()
        check(iface.detached is True and iface.online is False, "detach() marks the interface detached")
        check(iface._wake_server is None, "detach() left no wake server running")

    finally:
        if iface is not None and not iface.detached:
            iface.detach()
        shutil.rmtree(configdir, ignore_errors=True)

    if failures:
        print(f"\ncheck_postinterface_152: FAIL ({len(failures)} of the checks above)")
        return 1

    print("\ncheck_postinterface_152: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
