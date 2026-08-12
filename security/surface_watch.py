#!/usr/bin/env python3
"""
surface_watch.py — Security-surface change watcher for Wormhole NTT.

Scores a git diff against a curated ruleset of the protocol's critical attack
surface (mint/unlock, attestation/quorum/replay, VAA verification, decimals/
trimming, rate limiting, peer/threshold/upgrade config) so you audit the right
lines first — and are the first to review each new PR before it's audited.

Every real recent NTT finding came from freshly-added code (Sui rate-limiter
#917, EVM executeMsg peer check #918). This flags exactly those diffs.

Usage:
    # what changed on your branch vs upstream main
    python3 security/surface_watch.py --base origin/main --head HEAD

    # audit the last N commits
    python3 security/surface_watch.py --base HEAD~20 --head HEAD

    # point at any clone (e.g. upstream) and emit machine-readable JSON
    python3 security/surface_watch.py --repo /path/to/ntt --base v1.1.0 --head main --format json

Exit code is non-zero when any HIGH-weight surface is touched (useful in CI).
"""
import argparse
import fnmatch
import json
import re
import subprocess
import sys
from collections import defaultdict

# ── Ruleset ────────────────────────────────────────────────────────────────
# Each rule fires when a changed file matches ANY `paths` glob AND (there are no
# `patterns`, i.e. any structural change counts, OR an ADDED line matches a
# `patterns` regex). `weight` 1-10 drives ranking; >=7 is treated as HIGH.
RULES = [
    {
        "id": "mint-unlock",
        "title": "Mint / unlock / burn value movement",
        "weight": 10,
        "why": "Any change to how tokens are minted, unlocked, or burned can break the "
               "1:1 backing invariant (unbacked mint = total-drain critical).",
        "paths": ["*NttManager*.sol", "*/instructions/release_inbound.rs",
                  "*/instructions/transfer.rs", "*ntt.move"],
        "patterns": [r"\b_mintOrUnlockToRecipient\b", r"\b_unlockTokens\b", r"\bmint\s*\(",
                     r"\bburn\s*\(", r"\bmint_or_unlock\b", r"\bmint_to\b", r"safeTransfer\b",
                     r"\bcoin::(mint|take|burn)\b", r"invoke_transfer_checked"],
    },
    {
        "id": "attestation-quorum-replay",
        "title": "Attestation / quorum threshold / replay protection",
        "weight": 10,
        "why": "Quorum and replay logic is the anti-forgery/anti-double-mint core. "
               "Off-by-one or a missing replay flag here is critical.",
        "paths": ["*ManagerBase.sol", "*NttManager.sol", "*/instructions/redeem.rs",
                  "*inbox.move", "*state.move", "*bitmap*", "*queue/inbox.rs"],
        "patterns": [r"\battestationReceived\b", r"\bexecuteMsg\b", r"\b_replayProtect\b",
                     r"\bisMessageApproved\b", r"\b_recordTransceiverAttestation\b",
                     r"\bmessageAttestations\b", r"\bthreshold\b", r"\bcount_enabled_votes\b",
                     r"\brelease_status\b", r"\bReleaseStatus\b", r"\btry_release\b",
                     r"\bcountSetBits\b", r"\.votes\b", r"\breleased\b"],
    },
    {
        "id": "peer-verification",
        "title": "Peer / source-manager / recipient binding",
        "weight": 9,
        "why": "The source→peer binding authenticates cross-chain messages. A weakened "
               "check lets an attacker's manager be accepted as a trusted source.",
        "paths": ["*.sol", "*.rs", "*.move"],
        "patterns": [r"\b_verifyPeer\b", r"\b_verifyBridgeVM\b", r"getWormholePeer",
                     r"\bsource_ntt_manager\b", r"\brecipient_ntt_manager\b",
                     r"\bInvalidPeer\b", r"peer\.address", r"borrow_peer\b",
                     r"recipientNttManagerAddress", r"sourceNttManagerAddress"],
    },
    {
        "id": "vaa-verification",
        "title": "VAA / guardian-signature verification",
        "weight": 10,
        "why": "The guardian signature is the root of trust. Any change to how a VAA "
               "is parsed/verified, or which span is hashed, can enable forgery.",
        "paths": ["*WormholeTransceiver*.sol", "*/wormhole/*.rs", "*vaa_body.rs",
                  "*wormhole_transceiver.move", "*Governance.sol", "*governance.move",
                  "*governance.rs"],
        "patterns": [r"parseAndVerifyVM", r"verify_hash", r"parse_and_verify",
                     r"\bdigest\b", r"secp256k_hash", r"take_emitter_info_and_payload",
                     r"isVAAConsumed", r"_setVAAConsumed", r"guardian", r"emitter"],
    },
    {
        "id": "decimals-trimming",
        "title": "Decimals / TrimmedAmount / scaling",
        "weight": 8,
        "why": "Decimals confusion is the classic bridge drain. untrim() feeds the mint "
               "amount; a bound or units change can inflate value.",
        "paths": ["*TrimmedAmount.sol", "*trimmed_amount*", "*ntt.rs", "*.move", "*NttManager.sol"],
        "patterns": [r"\buntrim\b", r"\btrim\b", r"\bscale\b", r"numDecimals",
                     r"\btokenDecimals\b", r"get_decimals", r"remove_dust",
                     r"TrimmedAmount", r"packTrimmedAmount"],
    },
    {
        "id": "rate-limit",
        "title": "Rate limiter / backflow accounting",
        "weight": 6,
        "why": "Rate-limit units/backflow bugs (cf. Sui #917) can desync accounting; "
               "escalates if it enables over-withdrawal.",
        "paths": ["*RateLimiter.sol", "*rate_limit*", "*queue/rate_limit.rs", "*ntt.move"],
        "patterns": [r"consume_or_delay", r"\brefill\b", r"backfill", r"_consume\w*Amount",
                     r"capacity", r"currentCapacity", r"last_tx_timestamp", r"lastTxTimestamp",
                     r"set_limit", r"_setOutboundLimit", r"_setInboundLimit"],
    },
    {
        "id": "handler-override",
        "title": "Integrator handler override (_handleMsg / additionalPayload)",
        "weight": 9,
        "why": "Overridable hooks are the most likely place for a future critical: an "
               "override can let an un-attested or attacker-shaped payload reach mint.",
        "paths": ["*.sol"],
        "patterns": [r"\b_handleMsg\b", r"\b_handleTransfer\b", r"\b_handleAdditionalPayload\b",
                     r"\b_prepareNativeTokenTransfer\b", r"\b_enqueueOrConsume\w+RateLimit\b"],
    },
    {
        "id": "new-transceiver",
        "title": "New / modified transceiver implementation",
        "weight": 9,
        "why": "A non-Wormhole or weaker transceiver is a new trust root; its verification "
               "must be as strong as the guardian check.",
        "paths": ["*/Transceiver/*", "*/transceivers/*", "*transceiver*.move",
                  "*ntt-transceiver/*", "*Transceiver*.sol"],
        "patterns": [],  # any structural change to a transceiver file is worth review
    },
    {
        "id": "access-upgrade",
        "title": "Access control / upgrade / initialization / storage layout",
        "weight": 7,
        "why": "Owner/admin gating, upgrade paths, initializers, and custom storage slots "
               "govern privilege and delegatecall safety.",
        "paths": ["*.sol", "*.rs", "*.move"],
        "patterns": [r"onlyOwner", r"onlyOwnerOrPauser", r"has_one\s*=\s*owner", r"AdminCap",
                     r"\b_migrate\b", r"\binitialize\b", r"reinitializer", r"_upgrade\b",
                     r"upgrade_authority", r"assembly", r"\.slot\b", r'keccak256\("ntt\.',
                     r"set_authority", r"transferOwnership", r"UpgradeCap"],
    },
    {
        "id": "serialization",
        "title": "Message (de)serialization / wire format",
        "weight": 7,
        "why": "Parser length/offset handling and dual (Anchor vs wire) encodings can "
               "create aliasing, replay-key, or field-confusion bugs.",
        "paths": ["*TransceiverStructs.sol", "*messages*.rs", "*messages/*.move",
                  "*transceiver.rs", "*ntt_manager.rs", "*parse.move", "*layouts*"],
        "patterns": [r"checkLength", r"read_slice", r"read_payload", r"asBytes\d+",
                     r"asUint\d+", r"sliceUnchecked", r"take_bytes", r"destroy_empty",
                     r"payload_len", r"additionalPayload", r"additional_payload"],
    },
]

HIGH = 7


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args],
                          capture_output=True, text=True, check=True).stdout


def changed(repo, base, head):
    """Return {path: [added_line, ...]} for the base..head diff (added lines only)."""
    out = git(repo, "diff", "--unified=0", "--no-color", f"{base}..{head}")
    files, cur = defaultdict(list), None
    for line in out.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:]
        elif line.startswith("+++ "):
            cur = None  # /dev/null etc.
        elif cur and line.startswith("+") and not line.startswith("+++"):
            files[cur].append(line[1:])
    return files


def path_matches(path, globs):
    base = path.split("/")[-1]
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(base, g)
               or (g.strip("*") in path) for g in globs)


def scan(files):
    findings = []
    for path, added in files.items():
        blob = "\n".join(added)
        for rule in RULES:
            if not path_matches(path, rule["paths"]):
                continue
            if rule["patterns"]:
                hits = sorted({p for p in rule["patterns"] if re.search(p, blob)})
                if not hits:
                    continue
                samples = [ln.strip()[:120] for ln in added
                           if any(re.search(p, ln) for p in hits)][:3]
            else:
                hits, samples = ["<file touched>"], []
            findings.append({
                "rule": rule["id"], "title": rule["title"], "weight": rule["weight"],
                "why": rule["why"], "file": path,
                "matched": hits, "samples": samples, "added_lines": len(added),
            })
    findings.sort(key=lambda f: (-f["weight"], f["file"]))
    return findings


def render_text(findings, base, head):
    if not findings:
        return f"No critical-surface changes in {base}..{head}. ✅"
    out = [f"# Security-surface changes in {base}..{head}", ""]
    hi = [f for f in findings if f["weight"] >= HIGH]
    out.append(f"**{len(findings)} hit(s), {len(hi)} HIGH.** Audit HIGH first.\n")
    for f in findings:
        tag = "🔴 HIGH" if f["weight"] >= HIGH else "🟡"
        out.append(f"## {tag} [{f['weight']}] {f['title']}  —  `{f['file']}`")
        out.append(f"- why: {f['why']}")
        out.append(f"- matched: {', '.join('`'+m+'`' for m in f['matched'])}")
        for s in f["samples"]:
            out.append(f"    + {s}")
        out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    a = ap.parse_args()

    try:
        files = changed(a.repo, a.base, a.head)
    except subprocess.CalledProcessError as e:
        print(f"git error: {e.stderr.strip()}", file=sys.stderr)
        return 2

    findings = scan(files)
    if a.format == "json":
        print(json.dumps({"base": a.base, "head": a.head, "findings": findings}, indent=2))
    else:
        print(render_text(findings, a.base, a.head))

    return 1 if any(f["weight"] >= HIGH for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
