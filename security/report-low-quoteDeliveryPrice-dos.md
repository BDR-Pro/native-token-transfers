# [Low] `quoteDeliveryPrice` reverts (array out-of-bounds) after a lower-indexed transceiver is removed

**Severity:** Low
**Target:** `evm/src/NttManager/ManagerBase.sol` — `quoteDeliveryPrice()` / `_quoteDeliveryPrice()`
**Type:** Denial of service of a public view function (no loss of funds)
**Status of impact:** View-only. The token `transfer` / send path is **not** affected.

---

## Description

`ManagerBase.quoteDeliveryPrice()` builds the per-transceiver instruction array
sized by the number of **enabled** transceivers, but `_quoteDeliveryPrice()` then
indexes that array by each transceiver's **registered** index. Registered indices
are monotonic and never reused (`TransceiverRegistry._setTransceiver` assigns
`index = _numTransceivers.registered` and only ever increments), while removing a
transceiver decrements the enabled count. Once a lower-indexed transceiver is
removed, an still-enabled transceiver can have `registeredIndex >= enabledCount`,
so the array is read out of bounds and the call reverts with `Panic(0x32)`.

Relevant code:

```solidity
// ManagerBase.sol — quoteDeliveryPrice()
address[] memory enabledTransceivers = _getEnabledTransceiversStorage();
TransceiverStructs.TransceiverInstruction[] memory instructions =
    TransceiverStructs.parseTransceiverInstructions(
        transceiverInstructions, enabledTransceivers.length   // <-- sized by ENABLED count
    );
return _quoteDeliveryPrice(recipientChain, instructions, enabledTransceivers);
```

```solidity
// ManagerBase.sol — _quoteDeliveryPrice()
address transceiverAddr = enabledTransceivers[i];
uint8 registeredTransceiverIndex = transceiverInfos[transceiverAddr].index;   // REGISTERED index
uint256 transceiverPriceQuote = ITransceiver(transceiverAddr)
    .quoteDeliveryPrice(
        recipientChain, transceiverInstructions[registeredTransceiverIndex]   // <-- OOB when registeredIndex >= enabledCount
    );
```

`parseTransceiverInstructions(encoded, numRegisteredTransceivers)` allocates
`new TransceiverInstruction[](numRegisteredTransceivers)` — here that argument is
the *enabled* count, so the array is too short.

## Impact

- The public `quoteDeliveryPrice(uint16,bytes)` view reverts for any caller once
  the configuration reaches the state above (which arises naturally during
  **transceiver rotation**: e.g. register `T0,T1`, later remove `T0` and keep
  `T1`, whose registered index is `1` while the enabled count is `1`).
- Off-chain consumers (SDKs, front-ends, relayer quoting) that call this view to
  price a transfer break for that manager until the config changes.
- **No funds are at risk and transfers still succeed:** the send path
  (`_prepareForTransfer`) sizes the instruction array by
  `_getRegisteredTransceiversStorage().length` (the registered count), so it is
  not affected, and integrators can quote transceivers directly.

Because the trigger is an owner-driven configuration and the impact is limited to
a view function with an available workaround, this is reported as **Low**.

## Steps to reproduce

1. Deploy an `NttManager`, register three transceivers → registered indices `0,1,2`.
2. `removeTransceiver(T0)` and `removeTransceiver(T1)`. Only `T2` (registered
   index `2`) remains enabled; `enabledTransceivers.length == 1`.
3. Call `quoteDeliveryPrice(peerChain, "")` → reverts with `Panic(0x32)` (array
   out of bounds), because the length-1 instruction array is indexed at `2`.

## Proof of Concept

Fork-free Foundry test (in the repo at `evm/test/PoC_QuoteDeliveryPriceDoS.t.sol`):

```solidity
function test_quoteDoS_afterRemovingLowerIndexedTransceivers() public {
    DummyTransceiver t0 = new DummyTransceiver(address(nttManager));
    DummyTransceiver t1 = new DummyTransceiver(address(nttManager));
    DummyTransceiver t2 = new DummyTransceiver(address(nttManager));
    nttManager.setTransceiver(address(t0)); // index 0
    nttManager.setTransceiver(address(t1)); // index 1
    nttManager.setTransceiver(address(t2)); // index 2

    nttManager.quoteDeliveryPrice(peerChain, new bytes(0)); // works with all 3 enabled

    nttManager.removeTransceiver(address(t0));
    nttManager.removeTransceiver(address(t1));

    // enabledTransceivers.length == 1, but t2's registered index == 2
    vm.expectRevert(stdError.indexOOBError);
    nttManager.quoteDeliveryPrice(peerChain, new bytes(0));
}
```

Run:

```
forge test --match-contract PoC_QuoteDeliveryPriceDoS -vvv
```

Expected: the second `quoteDeliveryPrice` call reverts with an array
out-of-bounds panic; the test passes because the revert is asserted.

## Recommended fix

Size the instruction array by the registered transceiver count in the view, to
match the send path:

```solidity
// ManagerBase.quoteDeliveryPrice()
TransceiverStructs.TransceiverInstruction[] memory instructions =
    TransceiverStructs.parseTransceiverInstructions(
        transceiverInstructions,
        _getRegisteredTransceiversStorage().length   // was: enabledTransceivers.length
    );
```

This makes the array large enough to be indexed by any registered index, exactly
as `_prepareForTransfer` already does, and the OOB can no longer occur.

## Notes

Reported honestly at **Low** severity: view-only DoS, owner-triggered
configuration, no fund impact, SDK workaround available. Not claimed to reach any
Critical/High category of the program's severity classification.
