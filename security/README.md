# NTT security tooling

Two auditor tools produced during the critical-severity review. Neither reports
a live vulnerability in the current code — they are for catching the *next* one
(new code) and for auditing *live deployments* (configuration), which is where
realistic bounty value remains on a heavily-audited protocol.

## (a) `surface_watch.py` — new-code / PR risk watcher

Scores a git diff against a curated ruleset of the protocol's critical attack
surface (mint/unlock, attestation/quorum/replay, VAA verification, decimals,
rate limiting, handler overrides, new transceivers, access/upgrade,
serialization) so you audit the highest-risk lines first — and are first to
review each new PR before it is formally audited. Every recent real NTT finding
came from freshly-added code (Sui rate-limiter #917, EVM `executeMsg` peer check
#918); this flags exactly those diffs.

```bash
# your branch vs upstream
python3 security/surface_watch.py --base origin/main --head HEAD
# last 20 commits, JSON out
python3 security/surface_watch.py --base HEAD~20 --head HEAD --format json
```

Exit code is non-zero when a HIGH-weight surface is touched. The same script runs
automatically on every PR via `.github/workflows/security-surface-watch.yml`,
which posts a summary and annotates HIGH-risk PRs. Tune `RULES` in the script as
the codebase evolves.

## (b) `misconfig_scan.py` — live deployment config auditor (EVM)

Reads each deployed `NttManager`'s on-chain config via JSON-RPC and flags
dangerous inconsistencies that require no source bug and are frequently in
bounty scope:

- **HIGH** `threshold == 0`, `threshold > enabled transceivers` (quorum
  unreachable → stuck funds), or a **cross-chain `tokenDecimals` mismatch**
  (`A.getPeer(B).tokenDecimals != B.tokenDecimals()` → amount inflation/deflation
  on redeem — the decimals-drain class).
- **MED** single-transceiver quorum (`threshold == 1` with ≥2 transceivers),
  zero rate limits, EOA owner (single-key control of peers/threshold/upgrade),
  unset peer.
- **LOW/INFO** paused; effectively-unlimited rate limit.

```bash
pip install web3
cp security/deployments.example.json security/deployments.json
# edit deployments.json with real manager addresses + RPCs (>=2 chains enables
# the cross-chain peer/decimals checks), then:
python3 security/misconfig_scan.py --config security/deployments.json
```

Exit code is non-zero if any HIGH finding is present. Scanner reads EVM managers;
extend `check_pair` with the corresponding Solana/Sui config reads to cover those
sides of a route.

> Note: a HIGH from the scanner is a *lead*, not a confirmed exploit. Verify the
> other side of the route and the intended configuration before reporting — and
> never submit an unreproduced finding.
