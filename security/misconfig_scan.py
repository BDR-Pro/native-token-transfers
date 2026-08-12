#!/usr/bin/env python3
"""
misconfig_scan.py — Live on-chain configuration auditor for Wormhole NTT (EVM).

Reads each deployed NttManager's on-chain config via JSON-RPC and flags the
dangerous inconsistencies that are frequently in-scope for bounty programs and
do not require any source bug:

  HIGH   threshold == 0                         (inbound cannot be approved / invariant broken)
  HIGH   threshold > enabled transceivers       (quorum unreachable -> inbound funds stuck)
  HIGH   peer.tokenDecimals(A->B) != B.tokenDecimals()   (cross-chain decimals mismatch:
                                                  amount inflation/deflation on redeem)
  MED    threshold == 1 with >=2 transceivers   (single-transceiver compromise = forge quorum)
  MED    outbound/inbound limit == 0            (transfers blocked / inbound queued forever)
  MED    owner is an EOA (no code)              (single key controls peers/threshold/upgrade)
  MED    configured peer address == 0           (route mis/half-configured)
  LOW    contract paused
  INFO   rate limit effectively unlimited (uint64 max)

Cross-chain checks run automatically for any two deployments present in the
config (matched by wormhole_chain_id).

Setup:   pip install web3
Usage:   python3 security/misconfig_scan.py --config security/deployments.example.json
Exit code is non-zero if any HIGH finding is present.
"""
import argparse
import json
import sys

try:
    from web3 import Web3
except ImportError:
    sys.exit("Missing dependency. Run:  pip install web3")

U64_MAX = (1 << 64) - 1

ABI = json.loads("""[
 {"name":"getThreshold","inputs":[],"outputs":[{"type":"uint8"}],"stateMutability":"view","type":"function"},
 {"name":"getMode","inputs":[],"outputs":[{"type":"uint8"}],"stateMutability":"view","type":"function"},
 {"name":"tokenDecimals","inputs":[],"outputs":[{"type":"uint8"}],"stateMutability":"view","type":"function"},
 {"name":"isPaused","inputs":[],"outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
 {"name":"owner","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
 {"name":"getTransceivers","inputs":[],"outputs":[{"type":"address[]"}],"stateMutability":"view","type":"function"},
 {"name":"getPeer","inputs":[{"type":"uint16"}],
   "outputs":[{"type":"tuple","components":[{"name":"peerAddress","type":"bytes32"},{"name":"tokenDecimals","type":"uint8"}]}],
   "stateMutability":"view","type":"function"},
 {"name":"getOutboundLimitParams","inputs":[],
   "outputs":[{"type":"tuple","components":[{"name":"limit","type":"uint72"},{"name":"currentCapacity","type":"uint72"},{"name":"lastTxTimestamp","type":"uint64"}]}],
   "stateMutability":"view","type":"function"},
 {"name":"getInboundLimitParams","inputs":[{"type":"uint16"}],
   "outputs":[{"type":"tuple","components":[{"name":"limit","type":"uint72"},{"name":"currentCapacity","type":"uint72"},{"name":"lastTxTimestamp","type":"uint64"}]}],
   "stateMutability":"view","type":"function"}
]""")

FIND = []  # (severity, chain, message)


def add(sev, chain, msg):
    FIND.append((sev, chain, msg))


def trimmed_amount_value(raw):
    """TrimmedAmount is uint72: high 64 bits = amount, low 8 bits = decimals."""
    return raw >> 8, raw & 0xFF


def load(dep):
    w3 = Web3(Web3.HTTPProvider(dep["rpc"], request_kwargs={"timeout": 30}))
    c = w3.eth.contract(address=Web3.to_checksum_address(dep["manager"]), abi=ABI)
    info = {"dep": dep, "w3": w3, "c": c}
    info["threshold"] = c.functions.getThreshold().call()
    info["transceivers"] = c.functions.getTransceivers().call()
    info["decimals"] = c.functions.tokenDecimals().call()
    info["owner"] = c.functions.owner().call()
    info["owner_is_eoa"] = len(w3.eth.get_code(Web3.to_checksum_address(info["owner"]))) == 0
    try:
        info["paused"] = c.functions.isPaused().call()
    except Exception:
        info["paused"] = None
    try:
        raw = c.functions.getOutboundLimitParams().call()
        info["out_limit"] = trimmed_amount_value(raw[0])[0]
    except Exception:
        info["out_limit"] = None  # e.g. NoRateLimiting variant
    return info


def check_single(info):
    dep = info["dep"]
    chain = dep["chain"]
    ntx = len(info["transceivers"])
    th = info["threshold"]

    if th == 0 and ntx > 0:
        # Canonical contracts forbid this via _checkThresholdInvariants; a live hit
        # implies a forked/broken/corrupted deployment -> inbound permanently frozen.
        add("HIGH", chain, f"threshold == 0 with {ntx} registered transceiver(s): inbound cannot be "
                           f"approved -> PERMANENT FREEZE. Canonical NTT forbids this state; a live hit "
                           f"means a non-standard/broken deployment (genuine critical if confirmed).")
    elif th > ntx:
        # Also invariant-protected on canonical contracts (see removeTransceiver / setThreshold).
        add("HIGH", chain, f"threshold ({th}) > enabled transceivers ({ntx}): quorum unreachable -> "
                           f"inbound transfers PERMANENTLY FROZEN. Canonical NTT forbids this; a live "
                           f"hit implies a broken/forked deployment (genuine critical if confirmed).")
    elif th == 1 and ntx >= 2:
        add("MED", chain, f"threshold == 1 with {ntx} transceivers: a single transceiver compromise forges quorum. Consider raising the threshold.")
    elif th == ntx == 1:
        add("INFO", chain, "single transceiver, threshold 1: no attestation redundancy (inherent to 1-transceiver deployments).")

    if info["owner_is_eoa"]:
        add("MED", chain, f"owner {info['owner']} is an EOA (no code): a single key controls peers/threshold/upgrade — centralization / rug risk.")

    if info["paused"]:
        add("LOW", chain, "contract is PAUSED: transfers halted.")

    if info["out_limit"] == 0:
        add("MED", chain, "outbound rate limit == 0: all outbound transfers are blocked/queued.")
    elif info["out_limit"] == U64_MAX:
        add("INFO", chain, "outbound rate limit is effectively unlimited (uint64 max).")


def check_pair(a, b):
    """Cross-chain: a.getPeer(b).tokenDecimals must equal b.tokenDecimals(); and peer must be set."""
    for src, dst in ((a, b), (b, a)):
        dchain = dst["dep"]["wormhole_chain_id"]
        peer = src["c"].functions.getPeer(dchain).call()
        peer_addr, peer_decimals = peer[0], peer[1]
        schain = src["dep"]["chain"]
        if int.from_bytes(peer_addr, "big") == 0:
            add("MED", schain, f"peer for {dst['dep']['chain']} (wh id {dchain}) is UNSET (peerAddress == 0).")
            continue
        if peer_decimals != dst["decimals"]:
            # NOTE: this does NOT inflate value. The receiving manager untrims with
            # its OWN runtime tokenDecimals(), so trim(source)->untrim(dest) preserves
            # value regardless of peer.tokenDecimals (verified empirically). The peer
            # config only affects wire trimming precision, so a mismatch causes extra
            # dust loss and, if peer_decimals is small, TransferAmountHasDust reverts on
            # that route (liveness/UX). Flag as a route-consistency bug, not a drain.
            add("MED", schain,
                f"peer.tokenDecimals for {dst['dep']['chain']} is {peer_decimals}, but "
                f"{dst['dep']['chain']} token decimals is {dst['decimals']}. Route "
                f"inconsistency: extra dust loss / possible dust reverts. Value is "
                f"preserved (not an inflation drain); fix the config for correct UX.")
        try:
            raw = src["c"].functions.getInboundLimitParams(dchain).call()
            if trimmed_amount_value(raw[0])[0] == 0:
                add("MED", schain, f"inbound rate limit from {dst['dep']['chain']} == 0: inbound transfers queue indefinitely.")
        except Exception:
            pass


def amplifier_profile(info):
    """Rank how much this deployment's config AMPLIFIES a hypothetical single
    component bug (a transceiver/VAA-verification weakness, or owner-key exposure)
    into a critical. High score = a medium-severity bug becomes an unbacked-mint or
    total-drain CRITICAL *on this deployment*. This is the targeting signal: pair a
    high-amplifier route with a fresh finding from surface_watch.py.
    Returns (score, [(tag, note), ...])."""
    chain = info["dep"]["chain"]
    ntx = len(info["transceivers"])
    th = info["threshold"]
    score, notes = 0, []

    # 1-of-N quorum: a single forged attestation IS full quorum.
    if th == 1:
        score += 50
        if ntx >= 2:
            notes.append(("CRIT-IF", f"1-of-{ntx} quorum — redundancy exists but is bypassed: ANY single "
                          f"transceiver/VAA-verification bug forges quorum => unbacked-mint critical."))
        else:
            notes.append(("CRIT-IF", f"single transceiver, threshold 1 — no redundancy: one transceiver or "
                          f"VAA-verification bug => unbacked-mint critical."))
    elif th >= 2:
        notes.append(("harder", f"{th}-of-{ntx} quorum: a component bug needs {th} independent compromises "
                      f"to mint => much harder target."))

    # EOA owner: key exposure OR any owner-tricking bug => total drain via setPeer/upgrade.
    if info.get("owner_is_eoa"):
        score += 30
        notes.append(("CRIT-IF", f"EOA owner {info['owner']}: any owner-key exposure or owner-tricking bug "
                      f"(malicious _handleAdditionalPayload override, gov-message parse bug) => setPeer(evil)/"
                      f"upgrade(evil) => total drain."))

    # Not paused + live limits => a working target (amplifies exploitability, not severity).
    if info.get("paused") is False and info.get("out_limit") not in (0, None):
        score += 5

    return score, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="deployments JSON (see deployments.example.json)")
    a = ap.parse_args()

    cfg = json.load(open(a.config))
    infos = []
    for dep in cfg["deployments"]:
        try:
            infos.append(load(dep))
            print(f"[ok] loaded {dep['chain']} @ {dep['manager']}", file=sys.stderr)
        except Exception as e:
            add("ERROR", dep.get("chain", "?"), f"failed to read config: {e}")

    for info in infos:
        check_single(info)
    for i in range(len(infos)):
        for j in range(i + 1, len(infos)):
            try:
                check_pair(infos[i], infos[j])
            except Exception as e:
                add("ERROR", "-", f"pair check {infos[i]['dep']['chain']}/{infos[j]['dep']['chain']} failed: {e}")

    order = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3, "ERROR": 4}
    FIND.sort(key=lambda f: order.get(f[0], 9))
    icon = {"HIGH": "🔴", "MED": "🟠", "LOW": "🟡", "INFO": "🔵", "ERROR": "⚠️"}
    print(f"\n=== NTT deployment misconfig scan: {len(FIND)} finding(s) ===")
    for sev, chain, msg in FIND:
        print(f"{icon.get(sev,'?')} [{sev}] {chain}: {msg}")
    if not FIND:
        print("No misconfigurations detected. ✅")

    # Amplifier ranking — which live route turns a component bug into a critical.
    profiles = sorted(((amplifier_profile(i), i) for i in infos),
                      key=lambda x: -x[0][0])
    print("\n=== Critical-amplifier ranking (target the top routes) ===")
    print("A high score means: if you (or surface_watch.py) find a transceiver/VAA/handler")
    print("bug, it is a CRITICAL *here*. Pair the top route with a fresh finding.\n")
    for (score, notes), info in profiles:
        th, ntx = info["threshold"], len(info["transceivers"])
        eoa = "EOA-owner" if info.get("owner_is_eoa") else "contract-owner"
        band = "🔴 MAX" if score >= 50 else ("🟠 elevated" if score >= 30 else "🟢 hardened")
        print(f"{band}  score={score:>3}  {info['dep']['chain']:<12} "
              f"threshold={th} transceivers={ntx} {eoa}")
        for tag, note in notes:
            print(f"        [{tag}] {note}")

    return 1 if any(f[0] == "HIGH" for f in FIND) else 0


if __name__ == "__main__":
    sys.exit(main())
