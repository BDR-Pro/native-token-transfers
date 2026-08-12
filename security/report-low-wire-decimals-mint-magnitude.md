# [Low — "likely to occur in future stages"] Inbound `numDecimals` is trusted from the wire and controls mint magnitude with no bound / peer cross-check

**Severity:** Low (maps to the program's *"Bugs that are likely to occur in future stages of development but do not manifest themselves yet"* category)
**Target:** `evm/src/NttManager/NttManager.sol` (`_handleTransfer`) + `evm/src/libraries/TransceiverStructs.sol` (`parseNativeTokenTransfer`)
**Impact ceiling if the latent condition is met:** unbacked mint (Critical-class)
**Impact today:** none — gated by guardian attestation (see honest scoping)

---

## Description

An inbound `NativeTokenTransfer` carries a 1-byte `numDecimals` field on the
wire. `parseNativeTokenTransfer` packs it directly into the amount:

```solidity
// TransceiverStructs.parseNativeTokenTransfer
uint8 numDecimals;
(numDecimals, offset) = encoded.asUint8Unchecked(offset);
uint64 amount;
(amount, offset) = encoded.asUint64Unchecked(offset);
nativeTokenTransfer.amount = packTrimmedAmount(amount, numDecimals);
```

`_handleTransfer` then computes the minted/unlocked amount by `untrim`-ing with
the **local** token decimals:

```solidity
// NttManager._handleTransfer
uint8 toDecimals = tokenDecimals();
TrimmedAmount nativeTransferAmount =
    (nativeTokenTransfer.amount.untrim(toDecimals)).trim(toDecimals, toDecimals);
```

`untrim` scales by `10^(toDecimals - numDecimals)`. There is **no on-chain bound
on `numDecimals`, and no cross-check against the peer's configured
`tokenDecimals`**. Consequently the magnitude minted for a given on-wire `amount`
is a direct function of the attacker-shaped `numDecimals` byte.

## Proof of Concept (mechanism)

`evm/test/PoC_WireDecimalsMintMagnitude.t.sol` (fork-free) rebuilds the exact
receive-side computation and shows the same on-wire `amount = 1000` mints `10^8x`
more purely by choosing `numDecimals = 0` instead of the canonical `8`:

```
minted (numDecimals=0) = 1000 * 10^18
minted (numDecimals=8) = 1000 * 10^10
inflation factor from the decimals byte = 10^8
```

Run: `forge test --match-contract PoC_WireDecimalsMintMagnitude -vvv`

## Honest scoping — why this is Low / future-stages and NOT exploitable today

To reach `_handleTransfer`, a message must pass:
1. `_verifyPeer(sourceChainId, sourceNttManagerAddress)` — source must equal the
   registered peer, and
2. `isMessageApproved(digest)` — `>= threshold` guardian-attested transceiver
   deliveries of the exact bytes.

An honest source `NttManager` always emits `numDecimals = min(8, srcDecimals,
peerDecimals) <= dstDecimals`, so `untrim`/`trim` round-trips exactly and no
inflation occurs. Producing an attacker-chosen `numDecimals` therefore requires
either forging a guardian VAA or compromising a registered peer — both outside
an unprivileged attacker's reach. **So there is no current exploit.**

It becomes a live unbacked-mint the moment any future code lets an un-attested
or attacker-shaped `NativeTokenTransfer` reach `_handleTransfer`, e.g.:
- an integrator override of `_handleMsg` / `_handleAdditionalPayload` /
  `_enqueueOrConsumeInboundRateLimit` that relaxes or reorders the checks, or
- a new, weaker (non-Wormhole) transceiver whose verification is not equivalent
  to a guardian quorum, especially where the manager `threshold == 1`.

The program's rubric explicitly places "not currently exploitable but may become
exploitable in future stages (config or likely code change)" at **Low**, with the
WH team judging feasibility — hence this classification.

## Recommendation (defense-in-depth)

Add an inbound bound / cross-check so the receive path does not depend solely on
upstream attestation for amount integrity:

- Reject `numDecimals > TRIMMED_DECIMALS` (8) on parse, and/or
- Cross-check the message `numDecimals` against `_getPeersStorage()[sourceChainId].tokenDecimals`
  (which is already stored via `setPeer` but currently unused on the inbound
  path), reverting on mismatch.

Either check makes the mint magnitude independent of an unvalidated wire byte,
so a future handler/transceiver change cannot silently turn it into an unbacked
mint.

## Notes

Reported honestly as **Low / future-stages**, not as a present Critical. The
current attestation gate is sound; this is a missing inbound bound / defense-in-depth
observation with a Critical impact ceiling if that gate is ever bypassed by new code.
