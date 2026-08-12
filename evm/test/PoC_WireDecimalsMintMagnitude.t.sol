// SPDX-License-Identifier: Apache 2
pragma solidity >=0.8.8 <0.9.0;

// PoC (mechanism): the inbound NativeTokenTransfer `numDecimals` byte is taken
// from the wire and fed directly into untrim() to compute the minted/unlocked
// amount, with no on-chain bound and no cross-check against the peer's
// configured decimals. The magnitude minted for the same on-wire `amount`
// therefore scales by 10^(localDecimals - numDecimals), a factor fully
// determined by the attacker-shaped `numDecimals` byte.
//
// IMPORTANT / HONEST SCOPING: In the current code this is NOT exploitable,
// because to reach _handleTransfer a message must clear _verifyPeer and
// isMessageApproved (>= threshold guardian-attested transceiver deliveries).
// An honest source manager always emits numDecimals = min(8, srcDec, dstDec),
// so untrim/trim round-trips exactly. This PoC demonstrates the *mechanism* /
// missing defense-in-depth: any future code path that lets an un-attested or
// attacker-shaped NativeTokenTransfer reach _handleTransfer (e.g. an integrator
// _handleMsg/_handleAdditionalPayload override, or a weaker non-Wormhole
// transceiver) inherits an unbounded mint. Reported as Low / "future stages".
//
// Run: forge test --match-contract PoC_WireDecimalsMintMagnitude -vvv

import "forge-std/Test.sol";
import "../src/libraries/TransceiverStructs.sol";
import "../src/libraries/TrimmedAmount.sol";

contract PoC_WireDecimalsMintMagnitude is Test {
    using TrimmedAmountLib for TrimmedAmount;

    // Rebuild the exact receive-side amount computation from NttManager._handleTransfer:
    //   nativeTransferAmount = amount.untrim(toDecimals) ; then re-trimmed (value-preserving)
    function _mintAmountFor(uint8 wireDecimals, uint64 wireAmount, uint8 localDecimals)
        internal
        pure
        returns (uint256)
    {
        TransceiverStructs.NativeTokenTransfer memory ntt = TransceiverStructs.NativeTokenTransfer({
            amount: packTrimmedAmount(wireAmount, wireDecimals),
            sourceToken: bytes32(0),
            to: bytes32(uint256(uint160(address(0xBEEF)))),
            toChain: 7,
            additionalPayload: ""
        });
        // round-trip through the wire encoding, exactly like an inbound message
        bytes memory encoded = TransceiverStructs.encodeNativeTokenTransfer(ntt);
        TransceiverStructs.NativeTokenTransfer memory parsed =
            TransceiverStructs.parseNativeTokenTransfer(encoded);
        return parsed.amount.untrim(localDecimals); // this is what gets minted/unlocked
    }

    function test_wireDecimalsByteControlsMintMagnitude() public {
        uint64 wireAmount = 1000;
        uint8 localDecimals = 18;

        // Attacker-shaped numDecimals = 0 -> minted = 1000 * 10^18
        uint256 mintedDec0 = _mintAmountFor(0, wireAmount, localDecimals);
        // Canonical numDecimals = 8 -> minted = 1000 * 10^10
        uint256 mintedDec8 = _mintAmountFor(8, wireAmount, localDecimals);

        assertEq(mintedDec0, uint256(wireAmount) * 10 ** 18);
        assertEq(mintedDec8, uint256(wireAmount) * 10 ** 10);

        // The same on-wire `amount` mints 10^8x more purely by choosing the
        // decimals byte -> the wire `numDecimals` alone controls mint magnitude.
        assertEq(mintedDec0 / mintedDec8, 10 ** 8);

        emit log_named_uint("minted (numDecimals=0)", mintedDec0);
        emit log_named_uint("minted (numDecimals=8)", mintedDec8);
        emit log_named_uint("inflation factor from the decimals byte", mintedDec0 / mintedDec8);
    }
}
