// SPDX-License-Identifier: Apache 2
pragma solidity >=0.8.8 <0.9.0;

// PoC: quoteDeliveryPrice() out-of-bounds revert after transceiver removal.
//
// Root cause (ManagerBase.sol):
//   - public quoteDeliveryPrice() sizes the instruction array by
//     enabledTransceivers.length  (via parseTransceiverInstructions(..., enabledTransceivers.length))
//   - _quoteDeliveryPrice() then indexes that array by the *registered* index
//     (transceiverInfos[addr].index), which is monotonic and never reused.
//   Once earlier transceivers are removed, an enabled transceiver's registered
//   index can be >= enabledTransceivers.length, so instructions[registeredIndex]
//   reads out of bounds -> Panic(0x32) array OOB.
//
// Impact: DoS of the standalone quoteDeliveryPrice VIEW only. The real send path
// (_prepareForTransfer) sizes by registered length and is unaffected. No TVL/mint
// impact. Included as a reproducible low-severity finding.
//
// Run:  forge test --match-contract PoC_QuoteDeliveryPriceDoS -vvv
// (fork-free; no RPC needed)

import "forge-std/Test.sol";
import "../src/NttManager/NttManager.sol";
import "../src/interfaces/IManagerBase.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "wormhole-solidity-sdk/Utils.sol";
import "./mocks/DummyTransceiver.sol";
import "./mocks/MockNttManager.sol";
import "../src/mocks/DummyToken.sol";

contract PoC_QuoteDeliveryPriceDoS is Test {
    MockNttManagerContract nttManager;
    uint16 constant chainId = 7;
    uint16 constant peerChain = 8;

    function setUp() public {
        DummyToken t = new DummyToken();
        NttManager impl =
            new MockNttManagerContract(address(t), IManagerBase.Mode.LOCKING, chainId, 1 days, false);
        nttManager = MockNttManagerContract(address(new ERC1967Proxy(address(impl), "")));
        nttManager.initialize();
        nttManager.setPeer(peerChain, toWormholeFormat(address(0x1)), 9, type(uint64).max);
    }

    function test_quoteDoS_afterRemovingLowerIndexedTransceivers() public {
        // Register three transceivers -> registered indices 0, 1, 2.
        DummyTransceiver t0 = new DummyTransceiver(address(nttManager));
        DummyTransceiver t1 = new DummyTransceiver(address(nttManager));
        DummyTransceiver t2 = new DummyTransceiver(address(nttManager));
        nttManager.setTransceiver(address(t0)); // index 0
        nttManager.setTransceiver(address(t1)); // index 1
        nttManager.setTransceiver(address(t2)); // index 2

        // Sanity: quoting works while all three are enabled.
        nttManager.quoteDeliveryPrice(peerChain, new bytes(0));

        // Owner removes the two lower-indexed transceivers.
        // Now only t2 (registered index == 2) is enabled -> enabledTransceivers.length == 1.
        nttManager.removeTransceiver(address(t0));
        nttManager.removeTransceiver(address(t1));

        // The instruction array is sized to enabledTransceivers.length (==1),
        // but _quoteDeliveryPrice indexes it at t2's registered index (==2).
        // Expect an array out-of-bounds panic.
        vm.expectRevert(stdError.indexOOBError);
        nttManager.quoteDeliveryPrice(peerChain, new bytes(0));
    }

    // Control: the actual transfer/quote-through-send path is NOT affected,
    // because _prepareForTransfer sizes the instruction array by the REGISTERED
    // transceiver count. This documents that the OOB does not escalate to the
    // fund-moving path. (Left as an assertion the reader can extend with a full
    // transfer using a WormholeSimulator harness.)
}
