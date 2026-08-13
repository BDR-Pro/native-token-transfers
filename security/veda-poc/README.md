# Veda / BoringVault — Odos `inputReceiver` PoC (external)

> **This is not NTT code.** These files belong to a *separate* Immunefi bug-bounty
> submission against the **Veda / BoringVault** protocol (`ManagerWithMerkleVerification`
> + `OdosDecoderAndSanitizer`). They are stored here only as a research artifact.
> They do **not** compile or run inside this `native-token-transfers` repo — they
> must be run inside the Veda repo (the one with
> `test/integrations/OdosIntegration.t.sol` and `test/resources/MerkleTreeHelper/`).

## What the finding is

`OdosDecoderAndSanitizer.swap` / `swapCompact` build the merkle-verification
`addressesFound` from `inputToken, outputToken, outputReceiver, executor` and
**omit `tokenInfo.inputReceiver`** — so a merkle-restricted strategist can point
`inputReceiver` anywhere while every merkle-bound field stays honest. The field
was previously constrained and was removed in commit `f472aba` ("remove
inputReceiver", 2025-03-14); the sibling 1inch decoder still constrains the
equivalent `srcReceiver`.

## Open question this PoC settles

When `inputReceiver` is diverted to the attacker with `inputAmount = 0` (sweep),
the Odos executor is starved of input, so the router's `require(amountOut >=
outputMin)` may revert and roll back the whole transaction. Whether the drain
actually **executes** or **reverts** is what decides Critical vs. closed. This PoC
runs the real forked `OdosRouterV2` and prints the answer, rather than reproducing
the router's transfer semantics.

## Files

- `OdosInputReceiver_PoC.sol` — the drop-in test function. Paste
  `test_PoC_inputReceiverDrain()` into the `OdosIntegrationTest` contract in
  `test/integrations/OdosIntegration.t.sol` (reuses its forked `setUp` + merkle
  helpers).
- `odos-inputreceiver-poc.patch` — the same change as a git patch.

## Run (inside the Veda repo)

```bash
# option A: apply the patch
git am /path/to/odos-inputreceiver-poc.patch      # or: git apply <patch> && git commit -am poc
# option B: paste the function from OdosInputReceiver_PoC.sol into OdosIntegrationTest

export MAINNET_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/<KEY>"   # archive; free tier OK
forge test --match-test test_PoC_inputReceiverDrain -vvv
```

## Reading the result

- `>>> RESULT: DRAIN SUCCEEDED` — vault→0, attacker→full balance on real forked
  contracts → undeniable Critical.
- `>>> RESULT: REVERTED ... "Slippage Limit Exceeded"` — the merkle layer *did*
  authorize the diverted-`inputReceiver` call (decoder blindness confirmed), but
  the starved executor produced `< outputMin`, so the tx reverts and nothing is
  stolen → the removal is effectively safe; update the report honestly rather than
  claiming a drain.

To actually drain when it reverts, the attacker must supply `>= outputMin` output
independently of the diverted input (pre-position dust `outputToken` + craft a
`pathDefinition` the real executor will forward). Whether the deployed executor
allows that is the remaining open question.
