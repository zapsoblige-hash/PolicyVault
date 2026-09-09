//! PolicyVault covenant-call sigscript encoder.
//!
//! Usage:
//!   pv_call_encoder <current-state-source.sil> <constructor-args.json> <call.json>
//!
//! call.json:
//! {
//!   "function": "delegateSpend" | "rolloverAndSpend" | "ownerPause" |
//!               "ownerUnpause" | "ownerRecover",
//!   "successor": {                       // omitted for ownerRecover
//!     "protectedValue": "sompi-digits",
//!     "periodStartDaa": "digits",
//!     "periodSpent": "digits",
//!     "paused": 0 | 1
//!   },
//!   "payAmount": "sompi-digits",         // spend paths only
//!   "recipientIndex": 1..3,              // spend paths only
//!   "periodsElapsed": 1..1000,           // rolloverAndSpend only
//!   "signature": "65-byte-hex"
//! }
//!
//! Prints the covenant-call portion of the signature script as hex on
//! stdout (the redeem-script push is appended by the caller).

use std::{env, fs};

use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, struct_object, CompileOptions, CovenantDeclCallOptions};

fn die(message: &str) -> ! {
    eprintln!("pv_call_encoder: {message}");
    std::process::exit(1);
}

fn hex_bytes(value: &str, expected: usize, label: &str) -> Vec<u8> {
    if value.len() != expected * 2 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        die(&format!("{label} must be {expected}-byte hex"));
    }
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect()
}

/// Parse variable-length hex (may be empty). Used for the Merkle sibling
/// proof, whose length is depth*32 bytes.
fn hex_var(value: &str, label: &str) -> Vec<u8> {
    if value.len() % 2 != 0 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        die(&format!("{label} must be even-length hex"));
    }
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect()
}

fn json_i64(value: &serde_json::Value, label: &str) -> i64 {
    match value {
        serde_json::Value::String(s) => s.parse::<i64>().unwrap_or_else(|_| die(&format!("{label} must be an i64 digit string"))),
        serde_json::Value::Number(n) => n.as_i64().unwrap_or_else(|| die(&format!("{label} must be an i64"))),
        _ => die(&format!("{label} is required")),
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 3 {
        die("usage: pv_call_encoder <source.sil> <constructor-args.json> <call.json>");
    }

    let source = fs::read_to_string(&args[0]).unwrap_or_else(|e| die(&format!("cannot read source: {e}")));
    let ctor_json = fs::read_to_string(&args[1]).unwrap_or_else(|e| die(&format!("cannot read constructor args: {e}")));
    let call_json = fs::read_to_string(&args[2]).unwrap_or_else(|e| die(&format!("cannot read call json: {e}")));

    let constructor_args: Vec<Expr<'_>> =
        serde_json::from_str(&ctor_json).unwrap_or_else(|e| die(&format!("bad constructor args: {e}")));
    let call: serde_json::Value = serde_json::from_str(&call_json).unwrap_or_else(|e| die(&format!("bad call json: {e}")));

    let function = call["function"].as_str().unwrap_or_else(|| die("function is required"));

    /*
     * Contract-version dispatch. Absent field = the original v0.1 encoding
     * (backward compatible with the TESTNET-VERIFIED v0.1 tooling); the
     * explicit v0.2 tag selects the 14-field state shape; anything else
     * fails closed.
     */
    let contract_version = call["contractVersion"].as_str().unwrap_or("policyvault-0.1-beta");

    /*
     * Every generation up to v0.6 carries exactly ONE 65-byte signature per
     * call, so the field is mandatory and parsed here. The v0.7 ORGANIZATIONAL
     * ROOT generation does not: the root's owner authority is a 780-byte
     * M-of-N slot blob, succession carries its own 65-byte gate, and a ROOTED
     * VAULT's owner paths carry NO signature at all (the authority is the root
     * covenant INPUT, not a key). Those arms therefore read their own
     * signature material, and this shared field stays empty for them.
     */
    let v07 = matches!(contract_version, "policyvault-0.7-root" | "policyvault-0.7-payment" | "policyvault-0.7-payment-hd" | "policyvault-0.7-kas");
    let signature = if v07 {
        Vec::new()
    } else {
        hex_bytes(call["signature"].as_str().unwrap_or_else(|| die("signature is required")), 65, "signature")
    };

    /*
     * boundVaultId is filled from the immutable vaultId constructor arg. Its
     * index differs by contract version:
     *   v0.1: (owner, delegate, vaultId, ...)  -> index 2
     *   v0.2: (owner, vaultId, initDelegate, ...) -> index 1
     */
    // The kcc20/1 asset adapter encodes the TOKEN family's own leader call
    // (upstream KCC20 reference program, vendored at contracts/vendor/
    // kcc20-reference.sil): transfer(State[] newStates, sig[] sigs, byte[]
    // witnesses) with the family-LEADER entrypoint. The constructor args are
    // the token input's revealed state (genesisPk, genesisAmount,
    // genesisIdentifierType, genesisIsMinter, maxCovIns, maxCovOuts).
    if contract_version == "kcc20/1" {
        if function != "transfer" {
            die(&format!("unknown kcc20/1 function {function:?} — failing closed"));
        }
        // A family DELEGATE input (v0.6 atomic swaps: the second token note)
        // carries the transfer entrypoint with NO arguments and is_leader=false;
        // the leader carries newStates/sigs/witnesses for the whole family.
        if call["delegate"].as_bool() == Some(true) {
            let contract = compile_contract(Box::leak(source.into_boxed_str()), &constructor_args, CompileOptions::default())
                .unwrap_or_else(|e| die(&format!("compile failed: {e}")));
            let encoded = contract
                .build_sig_script_for_covenant_decl("transfer", vec![], CovenantDeclCallOptions { is_leader: false })
                .unwrap_or_else(|e| die(&format!("delegate call encoding failed: {e}")));
            println!("{}", encoded.iter().map(|b| format!("{b:02x}")).collect::<String>());
            return;
        }
        let states = call["newStates"].as_array().unwrap_or_else(|| die("newStates array is required"));
        if states.is_empty() {
            die("newStates must be non-empty");
        }
        let mut state_exprs: Vec<Expr<'static>> = Vec::new();
        for (i, st) in states.iter().enumerate() {
            let label = format!("newStates[{i}]");
            let ty = json_i64(&st["identifierType"], &format!("{label}.identifierType"));
            if !(0..=2).contains(&ty) {
                die(&format!("{label}.identifierType must be 0, 1 or 2 — failing closed"));
            }
            let amount = json_i64(&st["amount"], &format!("{label}.amount"));
            if amount < 0 {
                die(&format!("{label}.amount must be non-negative — failing closed"));
            }
            let minter = st["isMinter"].as_bool().unwrap_or_else(|| die(&format!("{label}.isMinter must be an explicit boolean")));
            state_exprs.push(struct_object(vec![
                (
                    "ownerIdentifier",
                    Expr::bytes(hex_bytes(
                        st["ownerIdentifier"].as_str().unwrap_or_else(|| die(&format!("{label}.ownerIdentifier is required"))),
                        32,
                        &format!("{label}.ownerIdentifier"),
                    )),
                ),
                ("identifierType", Expr::byte(ty as u8)),
                ("amount", Expr::int(amount)),
                ("isMinter", Expr::bool(minter)),
            ]));
        }
        let sigs: Vec<Expr<'static>> = call["sigs"]
            .as_array()
            .map(|v| v.iter().enumerate().map(|(i, s)| Expr::bytes(hex_bytes(s.as_str().unwrap_or_else(|| die("sigs entries must be hex")), 65, &format!("sigs[{i}]")))).collect())
            .unwrap_or_default();
        let witnesses = Expr::bytes(hex_var(call["witnesses"].as_str().unwrap_or_else(|| die("witnesses hex is required")), "witnesses"));
        let contract = compile_contract(Box::leak(source.into_boxed_str()), &constructor_args, CompileOptions::default())
            .unwrap_or_else(|e| die(&format!("compile failed: {e}")));
        let encoded = contract
            .build_sig_script_for_covenant_decl("transfer", vec![state_exprs.into(), sigs.into(), witnesses], CovenantDeclCallOptions { is_leader: true })
            .unwrap_or_else(|e| die(&format!("call encoding failed: {e}")));
        println!("{}", encoded.iter().map(|b| format!("{b:02x}")).collect::<String>());
        return;
    }

    // v6-pool-fixture/1: the constant-product POOL FIXTURE used as the approved
    // external venue in the v0.6 VM suite and the testnet-10 live proof
    // (contracts/experiments/V6PoolFixture.sil). NOT a PolicyVault product;
    // encoded here so every consensus-visible byte of a proof transaction goes
    // through one deterministic encoder. sellSwap/buySwap(State newState, int
    // amount, int reserveOutIdx, int feeOutIdx, KCC20State reserveNew).
    if contract_version == "v6-pool-fixture/1" {
        if function != "sellSwap" && function != "buySwap" {
            die(&format!("unknown v6-pool-fixture/1 function {function:?} — failing closed"));
        }
        let ns = &call["newState"];
        if ns.is_null() {
            die("newState is required");
        }
        let new_state = struct_object(vec![
            ("kasReserve", Expr::int(json_i64(&ns["kasReserve"], "newState.kasReserve"))),
            ("tokenReserve", Expr::int(json_i64(&ns["tokenReserve"], "newState.tokenReserve"))),
            ("feeBps", Expr::int(json_i64(&ns["feeBps"], "newState.feeBps"))),
            ("nonce", Expr::int(json_i64(&ns["nonce"], "newState.nonce"))),
        ]);
        let rn = &call["reserveNew"];
        if rn.is_null() {
            die("reserveNew is required");
        }
        let ty = json_i64(&rn["identifierType"], "reserveNew.identifierType");
        if ty != 2 {
            die("reserveNew.identifierType must be 2 (covenant-id owner) — failing closed");
        }
        let amount = json_i64(&rn["amount"], "reserveNew.amount");
        if amount < 0 {
            die("reserveNew.amount must be non-negative — failing closed");
        }
        let reserve_new = struct_object(vec![
            ("ownerIdentifier", Expr::bytes(hex_bytes(rn["ownerIdentifier"].as_str().unwrap_or_else(|| die("reserveNew.ownerIdentifier is required")), 32, "reserveNew.ownerIdentifier"))),
            ("identifierType", Expr::byte(2)),
            ("amount", Expr::int(amount)),
            ("isMinter", Expr::bool(false)),
        ]);
        let args = vec![
            new_state,
            Expr::int(json_i64(&call["amount"], "amount")),
            Expr::int(json_i64(&call["reserveOutIdx"], "reserveOutIdx")),
            Expr::int(json_i64(&call["feeOutIdx"], "feeOutIdx")),
            reserve_new,
        ];
        let contract = compile_contract(Box::leak(source.into_boxed_str()), &constructor_args, CompileOptions::default())
            .unwrap_or_else(|e| die(&format!("compile failed: {e}")));
        let encoded = contract
            .build_sig_script_for_covenant_decl(function, args, CovenantDeclCallOptions { is_leader: true })
            .unwrap_or_else(|e| die(&format!("call encoding failed: {e}")));
        println!("{}", encoded.iter().map(|b| format!("{b:02x}")).collect::<String>());
        return;
    }

    let vault_id_index = match contract_version {
        "policyvault-0.1-beta" => 2,
        "policyvault-0.2" => 1,
        "policyvault-0.3" => 1, // (owner, vaultId, initDelegate, ...)
        "policyvault-0.4" => 1, // (owner, vaultId, initAgentRoot, ...)
        "policyvault-0.4.1" => 1, // identical constructor order to v0.4
        "policyvault-0.5" => 1, // (owner, vaultId, descriptorHash, tokenCovenantId, ...)
        "policyvault-0.6" => 1, // identical prefix to v0.5 (+ initSwapRoot, initSwapPrincipal at the end)
        // v0.7 ORGANIZATIONAL ROOT: (orgId, initOwner1..12, ...) -> index 0.
        // `boundOrgId = orgId` is the root's bound-identity field, exactly the
        // role boundVaultId plays in every vault generation.
        "policyvault-0.7-root" => 0,
        // v0.7 ROOTED PAYMENT PROFILE: `pubkey owner` is REMOVED, so the v0.5
        // constructor order shifts down by one and vaultId is index 0.
        "policyvault-0.7-payment" => 0,
        // v0.7 ROOTED HIERARCHICAL DELEGATION (contract `PolicyVaultRootedTokenHD`,
        // tools/gen_v7_payment_hd.js): identical constructor order to
        // policyvault-0.7-payment (the HD delta touches only the delegate
        // entrypoints, never the constructor).
        "policyvault-0.7-payment-hd" => 0,
        // v0.7 ROOTED KAS SAFE-PAYMENT PROFILE: `pubkey owner` is REMOVED from
        // the v0.4.1 constructor order, so vaultId is index 0 (root pins
        // follow, then initAgentRoot/initFeeReserve/approvers/approvalM/initValue).
        "policyvault-0.7-kas" => 0,
        other => die(&format!("unknown contractVersion {other:?} — failing closed")),
    };
    let bound_vault_id =
        constructor_args.get(vault_id_index).unwrap_or_else(|| die("missing vaultId constructor argument")).clone();

    let successor_state_v01 = |call: &serde_json::Value| -> Expr<'static> {
        let successor = &call["successor"];
        if successor.is_null() {
            die("successor is required for this function");
        }
        struct_object(vec![
            ("boundVaultId", bound_vault_id.clone()),
            ("protectedValue", Expr::int(json_i64(&successor["protectedValue"], "successor.protectedValue"))),
            ("periodStartDaa", Expr::int(json_i64(&successor["periodStartDaa"], "successor.periodStartDaa"))),
            ("periodSpent", Expr::int(json_i64(&successor["periodSpent"], "successor.periodSpent"))),
            ("paused", Expr::int(json_i64(&successor["paused"], "successor.paused"))),
        ])
    };

    let successor_state_v02 = |call: &serde_json::Value| -> Expr<'static> {
        let successor = &call["successor"];
        if successor.is_null() {
            die("successor is required for this function");
        }
        let pk = |field: &str| -> Expr<'static> {
            Expr::bytes(hex_bytes(
                successor[field].as_str().unwrap_or_else(|| die(&format!("successor.{field} is required"))),
                32,
                &format!("successor.{field}"),
            ))
        };
        struct_object(vec![
            ("boundVaultId", bound_vault_id.clone()),
            ("protectedValue", Expr::int(json_i64(&successor["protectedValue"], "successor.protectedValue"))),
            ("periodStartDaa", Expr::int(json_i64(&successor["periodStartDaa"], "successor.periodStartDaa"))),
            ("periodSpent", Expr::int(json_i64(&successor["periodSpent"], "successor.periodSpent"))),
            ("paused", Expr::int(json_i64(&successor["paused"], "successor.paused"))),
            ("delegate", pk("delegate")),
            ("maxPerSpend", Expr::int(json_i64(&successor["maxPerSpend"], "successor.maxPerSpend"))),
            ("periodBudget", Expr::int(json_i64(&successor["periodBudget"], "successor.periodBudget"))),
            ("periodLengthDaa", Expr::int(json_i64(&successor["periodLengthDaa"], "successor.periodLengthDaa"))),
            ("recipient1", pk("recipient1")),
            ("recipient2", pk("recipient2")),
            ("recipient3", pk("recipient3")),
            ("delegateActive", Expr::int(json_i64(&successor["delegateActive"], "successor.delegateActive"))),
            ("policyNonce", Expr::int(json_i64(&successor["policyNonce"], "successor.policyNonce"))),
        ])
    };

    // v0.3 full 24-field successor state (matches PolicyVault.v0.3.sil field order).
    let successor_state_v03 = |call: &serde_json::Value| -> Expr<'static> {
        let successor = &call["successor"];
        if successor.is_null() {
            die("successor is required for this function");
        }
        let pk = |field: &str| -> Expr<'static> {
            Expr::bytes(hex_bytes(
                successor[field].as_str().unwrap_or_else(|| die(&format!("successor.{field} is required"))),
                32,
                &format!("successor.{field}"),
            ))
        };
        let int = |field: &str| -> Expr<'static> { Expr::int(json_i64(&successor[field], &format!("successor.{field}"))) };
        let mut fields: Vec<(&str, Expr<'static>)> = vec![
            ("boundVaultId", bound_vault_id.clone()),
            ("protectedValue", int("protectedValue")),
            ("periodStartDaa", int("periodStartDaa")),
            ("periodSpent", int("periodSpent")),
            ("paused", int("paused")),
            ("delegate", pk("delegate")),
            ("delegateActive", int("delegateActive")),
            ("maxPerSpend", int("maxPerSpend")),
            ("periodBudget", int("periodBudget")),
            ("periodLengthDaa", int("periodLengthDaa")),
            ("recipientRoot", pk("recipientRoot")),
        ];
        const APPROVER_NAMES: [&str; 10] = [
            "approver1", "approver2", "approver3", "approver4", "approver5", "approver6", "approver7", "approver8",
            "approver9", "approver10",
        ];
        for name in APPROVER_NAMES {
            fields.push((name, pk(name)));
        }
        fields.push(("approvalM", int("approvalM")));
        fields.push(("approvalThresholdAmount", int("approvalThresholdAmount")));
        fields.push(("policyNonce", int("policyNonce")));
        struct_object(fields)
    };

    // v0.3 delegate-spend shared args: recipient proof + 650-byte approvals blob.
    let v03_spend_proof = |call: &serde_json::Value| -> (Expr<'static>, Expr<'static>, Expr<'static>, Expr<'static>) {
        let recipient_pk = Expr::bytes(hex_bytes(
            call["recipientPk"].as_str().unwrap_or_else(|| die("recipientPk is required")),
            32,
            "recipientPk",
        ));
        let siblings_bytes = hex_var(call["siblings"].as_str().unwrap_or(""), "siblings");
        if siblings_bytes.len() % 32 != 0 {
            die("siblings length must be a multiple of 32 bytes");
        }
        let path_bits = Expr::int(json_i64(&call["pathBits"], "pathBits"));
        let approvals = hex_bytes(call["approvals"].as_str().unwrap_or_else(|| die("approvals is required")), 650, "approvals");
        (recipient_pk, Expr::bytes(siblings_bytes), path_bits, Expr::bytes(approvals))
    };

    // v0.4 full 17-field successor state (matches PolicyVault.v0.4.sil field order).
    let successor_state_v04 = |call: &serde_json::Value| -> Expr<'static> {
        let successor = &call["successor"];
        if successor.is_null() {
            die("successor is required for this function");
        }
        let pk = |field: &str| -> Expr<'static> {
            Expr::bytes(hex_bytes(
                successor[field].as_str().unwrap_or_else(|| die(&format!("successor.{field} is required"))),
                32,
                &format!("successor.{field}"),
            ))
        };
        let int = |field: &str| -> Expr<'static> { Expr::int(json_i64(&successor[field], &format!("successor.{field}"))) };
        let mut fields: Vec<(&str, Expr<'static>)> = vec![
            ("boundVaultId", bound_vault_id.clone()),
            ("protectedValue", int("protectedValue")),
            ("feeReserve", int("feeReserve")),
            ("paused", int("paused")),
            ("agentRoot", pk("agentRoot")),
        ];
        const APPROVER_NAMES: [&str; 10] = [
            "approver1", "approver2", "approver3", "approver4", "approver5", "approver6", "approver7", "approver8",
            "approver9", "approver10",
        ];
        for name in APPROVER_NAMES {
            fields.push((name, pk(name)));
        }
        fields.push(("approvalM", int("approvalM")));
        fields.push(("policyNonce", int("policyNonce")));
        struct_object(fields)
    };

    // v0.4 agentSpend shared args (17 call args after newState): the per-agent
    // leaf policy fields + policy proof + recipient proof + 650-byte approvals.
    let v04_agent_args = |call: &serde_json::Value, signature: Vec<u8>| -> Vec<Expr<'static>> {
        let pk = |field: &str| -> Expr<'static> {
            Expr::bytes(hex_bytes(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), 32, field))
        };
        let policy_sibs = hex_var(call["policySiblings"].as_str().unwrap_or(""), "policySiblings");
        if policy_sibs.len() % 32 != 0 {
            die("policySiblings length must be a multiple of 32 bytes");
        }
        let recip_sibs = hex_var(call["recipientSiblings"].as_str().unwrap_or(""), "recipientSiblings");
        if recip_sibs.len() % 32 != 0 {
            die("recipientSiblings length must be a multiple of 32 bytes");
        }
        let approvals = hex_bytes(call["approvals"].as_str().unwrap_or_else(|| die("approvals is required")), 650, "approvals");
        vec![
            successor_state_v04(call),
            Expr::int(json_i64(&call["payAmount"], "payAmount")),
            pk("agentPk"),
            Expr::int(json_i64(&call["maxPerSpend"], "maxPerSpend")),
            Expr::int(json_i64(&call["periodBudget"], "periodBudget")),
            Expr::int(json_i64(&call["periodLengthDaa"], "periodLengthDaa")),
            Expr::int(json_i64(&call["periodStartDaa"], "periodStartDaa")),
            Expr::int(json_i64(&call["periodSpent"], "periodSpent")),
            Expr::int(json_i64(&call["approvalThreshold"], "approvalThreshold")),
            Expr::int(json_i64(&call["agentMaxFeePerTx"], "agentMaxFeePerTx")),
            pk("agentRecipientRoot"),
            Expr::bytes(policy_sibs),
            Expr::int(json_i64(&call["policyPathBits"], "policyPathBits")),
            Expr::int(json_i64(&call["periodsElapsed"], "periodsElapsed")),
            pk("recipientPk"),
            Expr::bytes(recip_sibs),
            Expr::int(json_i64(&call["recipientPathBits"], "recipientPathBits")),
            Expr::bytes(signature),
            Expr::bytes(approvals),
        ]
    };

    let call_args: Vec<Expr<'static>> = match contract_version {
        "policyvault-0.1-beta" => match function {
            "delegateSpend" => vec![
                successor_state_v01(&call),
                Expr::int(json_i64(&call["payAmount"], "payAmount")),
                Expr::int(json_i64(&call["recipientIndex"], "recipientIndex")),
                Expr::bytes(signature),
            ],
            "rolloverAndSpend" => vec![
                successor_state_v01(&call),
                Expr::int(json_i64(&call["payAmount"], "payAmount")),
                Expr::int(json_i64(&call["recipientIndex"], "recipientIndex")),
                Expr::int(json_i64(&call["periodsElapsed"], "periodsElapsed")),
                Expr::bytes(signature),
            ],
            "ownerPause" | "ownerUnpause" => vec![successor_state_v01(&call), Expr::bytes(signature)],
            "ownerRecover" => vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(signature)],
            other => die(&format!("unknown v0.1 function {other:?} — failing closed")),
        },
        "policyvault-0.2" => match function {
            "delegateSpend" => vec![
                successor_state_v02(&call),
                Expr::int(json_i64(&call["payAmount"], "payAmount")),
                Expr::int(json_i64(&call["recipientIndex"], "recipientIndex")),
                Expr::bytes(signature),
            ],
            "rolloverAndSpend" => vec![
                successor_state_v02(&call),
                Expr::int(json_i64(&call["payAmount"], "payAmount")),
                Expr::int(json_i64(&call["recipientIndex"], "recipientIndex")),
                Expr::int(json_i64(&call["periodsElapsed"], "periodsElapsed")),
                Expr::bytes(signature),
            ],
            "ownerPause" | "ownerUnpause" | "revokeDelegate" | "ownerTopUp" | "migratePolicy" => {
                vec![successor_state_v02(&call), Expr::bytes(signature)]
            }
            "rotateDelegate" => vec![
                successor_state_v02(&call),
                Expr::bytes(hex_bytes(
                    call["newDelegate"].as_str().unwrap_or_else(|| die("newDelegate is required")),
                    32,
                    "newDelegate",
                )),
                Expr::bytes(signature),
            ],
            "ownerRecover" => vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(signature)],
            other => die(&format!("unknown v0.2 function {other:?} — failing closed")),
        },
        "policyvault-0.3" => match function {
            "delegateSpend" => {
                let (recipient_pk, siblings, path_bits, approvals) = v03_spend_proof(&call);
                vec![
                    successor_state_v03(&call),
                    Expr::int(json_i64(&call["payAmount"], "payAmount")),
                    recipient_pk,
                    siblings,
                    path_bits,
                    Expr::bytes(signature),
                    approvals,
                ]
            }
            "rolloverAndSpend" => {
                let (recipient_pk, siblings, path_bits, approvals) = v03_spend_proof(&call);
                vec![
                    successor_state_v03(&call),
                    Expr::int(json_i64(&call["payAmount"], "payAmount")),
                    recipient_pk,
                    siblings,
                    path_bits,
                    Expr::int(json_i64(&call["periodsElapsed"], "periodsElapsed")),
                    Expr::bytes(signature),
                    approvals,
                ]
            }
            "ownerPause" | "ownerUnpause" | "revokeDelegate" | "rotateDelegate" | "ownerTopUp" | "migratePolicy"
            | "ownerSetRecipientRoot" | "ownerSetApprovers" => {
                vec![successor_state_v03(&call), Expr::bytes(signature)]
            }
            "ownerRecover" => vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(signature)],
            other => die(&format!("unknown v0.3 function {other:?} — failing closed")),
        },
        "policyvault-0.4" => match function {
            "agentSpend" => v04_agent_args(&call, signature),
            "ownerSetAgentRoot" | "ownerSetApprovers" | "ownerTopUp" | "ownerTopUpReserve" | "ownerPause" | "ownerUnpause" => {
                vec![successor_state_v04(&call), Expr::bytes(signature)]
            }
            "ownerRecover" => vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(signature)],
            other => die(&format!("unknown v0.4 function {other:?} — failing closed")),
        },
        // v0.4.1 STANDARDNESS REDESIGN: identical state ABI to v0.4, but the six
        // owner operations are consolidated behind ONE ownerControl entrypoint
        // selected by an explicit opSelector call arg (0=setAgentRoot,
        // 1=setApprovers, 2=topUp, 3=topUpReserve, 4=pause, 5=unpause). The six
        // legacy v0.4 owner-op function names are NOT accepted here — a call must
        // name ownerControl and carry a bounded opSelector, or fail closed. This
        // keeps the version boundary crisp and prevents a mis-routed v0.4 owner
        // call from silently encoding under v0.4.1.
        "policyvault-0.4.1" => match function {
            "agentSpend" => v04_agent_args(&call, signature),
            "ownerControl" => {
                // opSelector is a call arg (NOT committed by SIG_HASH_ALL); the
                // successor state IS committed (covenant output), and the
                // covenant's mutually-exclusive branches make any selector/
                // successor mismatch reject (docs/covenant-spec-v0.4.1.md §op-
                // selector-sighash). The encoder still fails closed on a missing
                // or out-of-range selector so it never emits an ambiguous call.
                if call["opSelector"].is_null() {
                    die("opSelector is required for ownerControl (v0.4.1) — failing closed");
                }
                let op = json_i64(&call["opSelector"], "opSelector");
                if !(0..=5).contains(&op) {
                    die(&format!("opSelector {op} out of range [0,5] for ownerControl — failing closed"));
                }
                // successor_state_v04 dies if `successor` is absent, so a
                // recover-shaped ownerControl call (no successor) fails closed.
                vec![successor_state_v04(&call), Expr::int(op), Expr::bytes(signature)]
            }
            "ownerRecover" => {
                // Terminal break-glass: no selector, no successor. Reject a
                // selector here so a control call cannot masquerade as recover.
                if !call["opSelector"].is_null() {
                    die("ownerRecover must NOT carry opSelector (v0.4.1) — failing closed");
                }
                vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(signature)]
            }
            other => die(&format!(
                "unknown v0.4.1 function {other:?} — failing closed (owner ops use ownerControl + opSelector)"
            )),
        },
        // v0.5 TOKEN CONTROLLER (contracts/PolicyVault.v0.5.sil): 5-field state
        // (boundVaultId, feeReserve, paused, agentRoot, policyNonce); KCC20State
        // struct args carry the token continuation states; owner ops behind
        // ownerControl + opSelector 0..3; ownerRecover carries the owner-owned
        // token continuation. Unknown function names fail closed.
        "policyvault-0.5" => {
            let successor_state_v05 = |call: &serde_json::Value| -> Expr<'static> {
                let successor = &call["successor"];
                if successor.is_null() {
                    die("successor is required for this function");
                }
                struct_object(vec![
                    ("boundVaultId", bound_vault_id.clone()),
                    ("feeReserve", Expr::int(json_i64(&successor["feeReserve"], "successor.feeReserve"))),
                    ("paused", Expr::int(json_i64(&successor["paused"], "successor.paused"))),
                    (
                        "agentRoot",
                        Expr::bytes(hex_bytes(
                            successor["agentRoot"].as_str().unwrap_or_else(|| die("successor.agentRoot is required")),
                            32,
                            "successor.agentRoot",
                        )),
                    ),
                    ("policyNonce", Expr::int(json_i64(&successor["policyNonce"], "successor.policyNonce"))),
                ])
            };
            let kcc20_state = |v: &serde_json::Value, label: &str| -> Expr<'static> {
                if v.is_null() {
                    die(&format!("{label} is required"));
                }
                let ty = json_i64(&v["identifierType"], &format!("{label}.identifierType"));
                if !(0..=2).contains(&ty) {
                    die(&format!("{label}.identifierType must be 0, 1 or 2 — failing closed"));
                }
                let amount = json_i64(&v["amount"], &format!("{label}.amount"));
                if amount < 0 {
                    die(&format!("{label}.amount must be non-negative — failing closed"));
                }
                let minter = v["isMinter"].as_bool().unwrap_or_else(|| die(&format!("{label}.isMinter must be an explicit boolean")));
                struct_object(vec![
                    (
                        "ownerIdentifier",
                        Expr::bytes(hex_bytes(
                            v["ownerIdentifier"].as_str().unwrap_or_else(|| die(&format!("{label}.ownerIdentifier is required"))),
                            32,
                            &format!("{label}.ownerIdentifier"),
                        )),
                    ),
                    ("identifierType", Expr::byte(ty as u8)),
                    ("amount", Expr::int(amount)),
                    ("isMinter", Expr::bool(minter)),
                ])
            };
            let pk = |field: &str| -> Expr<'static> {
                Expr::bytes(hex_bytes(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), 32, field))
            };
            let var = |field: &str| -> Expr<'static> {
                Expr::bytes(hex_var(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), field))
            };
            match function {
                "tokenAgentSpend" => vec![
                    successor_state_v05(&call),
                    kcc20_state(&call["selfNew"], "selfNew"),
                    kcc20_state(&call["recipientNew"], "recipientNew"),
                    pk("agentPk"),
                    Expr::int(json_i64(&call["tokenMaxPerSpend"], "tokenMaxPerSpend")),
                    Expr::int(json_i64(&call["tokenPeriodBudget"], "tokenPeriodBudget")),
                    Expr::int(json_i64(&call["periodLengthDaa"], "periodLengthDaa")),
                    Expr::int(json_i64(&call["periodStartDaa"], "periodStartDaa")),
                    Expr::int(json_i64(&call["tokenPeriodSpent"], "tokenPeriodSpent")),
                    Expr::int(json_i64(&call["agentMaxFeePerTx"], "agentMaxFeePerTx")),
                    Expr::int(json_i64(&call["agentMaxCarryKas"], "agentMaxCarryKas")),
                    pk("agentRecipientRoot"),
                    var("policySiblings"),
                    Expr::int(json_i64(&call["policyPathBits"], "policyPathBits")),
                    Expr::int(json_i64(&call["periodsElapsed"], "periodsElapsed")),
                    pk("recipientPk"),
                    var("recipientSiblings"),
                    Expr::int(json_i64(&call["recipientPathBits"], "recipientPathBits")),
                    Expr::bytes(signature),
                ],
                "ownerControl" => {
                    if call["opSelector"].is_null() {
                        die("opSelector is required for ownerControl (v0.5) — failing closed");
                    }
                    let op = json_i64(&call["opSelector"], "opSelector");
                    if !(0..=3).contains(&op) {
                        die(&format!("opSelector {op} out of range [0,3] for ownerControl (v0.5) — failing closed"));
                    }
                    vec![successor_state_v05(&call), Expr::int(op), Expr::bytes(signature)]
                }
                "ownerRecover" => {
                    if !call["opSelector"].is_null() {
                        die("ownerRecover must NOT carry opSelector (v0.5) — failing closed");
                    }
                    vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(signature), kcc20_state(&call["recipientNew"], "recipientNew")]
                }
                other => die(&format!("unknown v0.5 function {other:?} — failing closed")),
            }
        }
        // v0.6 ATOMIC-COMPOSABILITY TOKEN CONTROLLER (contracts/PolicyVault.v0.6.sil
        // CANDIDATE): 7-field state (boundVaultId, feeReserve, swapPrincipal,
        // paused, agentRoot, swapRoot, policyNonce); 12-field agent leaf; 14-field
        // owner swap-policy leaf; tokenAtomicSell / tokenAtomicBuy compose with
        // ONE approved pool; ownerControl opSelector 0..5. Unknown names fail closed.
        "policyvault-0.6" => {
            let successor_state_v06 = |call: &serde_json::Value| -> Expr<'static> {
                let successor = &call["successor"];
                if successor.is_null() {
                    die("successor is required for this function");
                }
                struct_object(vec![
                    ("boundVaultId", bound_vault_id.clone()),
                    ("feeReserve", Expr::int(json_i64(&successor["feeReserve"], "successor.feeReserve"))),
                    ("swapPrincipal", Expr::int(json_i64(&successor["swapPrincipal"], "successor.swapPrincipal"))),
                    ("paused", Expr::int(json_i64(&successor["paused"], "successor.paused"))),
                    (
                        "agentRoot",
                        Expr::bytes(hex_bytes(successor["agentRoot"].as_str().unwrap_or_else(|| die("successor.agentRoot is required")), 32, "successor.agentRoot")),
                    ),
                    (
                        "swapRoot",
                        Expr::bytes(hex_bytes(successor["swapRoot"].as_str().unwrap_or_else(|| die("successor.swapRoot is required")), 32, "successor.swapRoot")),
                    ),
                    ("policyNonce", Expr::int(json_i64(&successor["policyNonce"], "successor.policyNonce"))),
                ])
            };
            let kcc20_state = |v: &serde_json::Value, label: &str| -> Expr<'static> {
                if v.is_null() {
                    die(&format!("{label} is required"));
                }
                let ty = json_i64(&v["identifierType"], &format!("{label}.identifierType"));
                if !(0..=2).contains(&ty) {
                    die(&format!("{label}.identifierType must be 0, 1 or 2 — failing closed"));
                }
                let amount = json_i64(&v["amount"], &format!("{label}.amount"));
                if amount < 0 {
                    die(&format!("{label}.amount must be non-negative — failing closed"));
                }
                let minter = v["isMinter"].as_bool().unwrap_or_else(|| die(&format!("{label}.isMinter must be an explicit boolean")));
                struct_object(vec![
                    (
                        "ownerIdentifier",
                        Expr::bytes(hex_bytes(v["ownerIdentifier"].as_str().unwrap_or_else(|| die(&format!("{label}.ownerIdentifier is required"))), 32, &format!("{label}.ownerIdentifier"))),
                    ),
                    ("identifierType", Expr::byte(ty as u8)),
                    ("amount", Expr::int(amount)),
                    ("isMinter", Expr::bool(minter)),
                ])
            };
            let pk = |field: &str| -> Expr<'static> { Expr::bytes(hex_bytes(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), 32, field)) };
            let var = |field: &str| -> Expr<'static> { Expr::bytes(hex_var(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), field)) };
            let int = |field: &str| -> Expr<'static> { Expr::int(json_i64(&call[field], field)) };
            let agent_fields = |call: &serde_json::Value| -> Vec<Expr<'static>> {
                let _ = call;
                vec![
                    pk("agentPk"),
                    int("tokenMaxPerSpend"),
                    int("tokenPeriodBudget"),
                    int("periodLengthDaa"),
                    int("periodStartDaa"),
                    int("tokenPeriodSpent"),
                    int("agentMaxFeePerTx"),
                    int("agentMaxCarryKas"),
                    int("kasMaxPerSwap"),
                    int("kasPeriodBudget"),
                    int("kasPeriodSpent"),
                    pk("agentRecipientRoot"),
                    var("policySiblings"),
                    int("policyPathBits"),
                    int("periodsElapsed"),
                ]
            };
            let swap_fields = |call: &serde_json::Value| -> Vec<Expr<'static>> {
                let _ = call;
                let scheme = json_i64(&call["destScheme"], "destScheme");
                if scheme != 0 && scheme != 2 {
                    die("destScheme must be 0 (P2PK) or 2 (controller) — failing closed");
                }
                vec![
                    pk("profileHash"),
                    pk("poolCovenantId"),
                    pk("poolTemplateVmHash"),
                    int("poolPrefixLen"),
                    int("poolSuffixLen"),
                    pk("poolFeePk"),
                    int("maxProtocolFeeKas"),
                    int("sellFloorNum"),
                    int("sellFloorDen"),
                    int("buyCeilNum"),
                    int("buyCeilDen"),
                    int("directionMask"),
                    Expr::byte(scheme as u8),
                    pk("destIdentity"),
                    var("swapSiblings"),
                    int("swapPathBits"),
                ]
            };
            match function {
                "tokenAgentSpend" => {
                    let mut v = vec![successor_state_v06(&call), kcc20_state(&call["selfNew"], "selfNew"), kcc20_state(&call["recipientNew"], "recipientNew")];
                    v.extend(agent_fields(&call));
                    v.push(pk("recipientPk"));
                    v.push(var("recipientSiblings"));
                    v.push(int("recipientPathBits"));
                    v.push(Expr::bytes(signature));
                    v
                }
                "tokenAtomicSell" => {
                    let mut v = vec![successor_state_v06(&call), kcc20_state(&call["selfNew"], "selfNew"), kcc20_state(&call["poolNoteNew"], "poolNoteNew")];
                    v.extend(agent_fields(&call));
                    v.extend(swap_fields(&call));
                    v.push(int("amountIn"));
                    v.push(int("minKasOut"));
                    v.push(int("proceedsOutIdx"));
                    v.push(int("feeOutIdx"));
                    v.push(Expr::bytes(signature));
                    v
                }
                "tokenAtomicBuy" => {
                    let mut v = vec![successor_state_v06(&call), kcc20_state(&call["selfNew"], "selfNew"), kcc20_state(&call["poolNoteNew"], "poolNoteNew")];
                    v.extend(agent_fields(&call));
                    v.extend(swap_fields(&call));
                    v.push(int("tokensOut"));
                    v.push(int("maxKasIn"));
                    v.push(int("feeOutIdx"));
                    v.push(Expr::bytes(signature));
                    v
                }
                "ownerControl" => {
                    if call["opSelector"].is_null() {
                        die("opSelector is required for ownerControl (v0.6) — failing closed");
                    }
                    let op = json_i64(&call["opSelector"], "opSelector");
                    if !(0..=5).contains(&op) {
                        die(&format!("opSelector {op} out of range [0,5] for ownerControl (v0.6) — failing closed"));
                    }
                    vec![successor_state_v06(&call), Expr::int(op), Expr::bytes(signature)]
                }
                "ownerRecover" => {
                    if !call["opSelector"].is_null() {
                        die("ownerRecover must NOT carry opSelector (v0.6) — failing closed");
                    }
                    vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(signature), kcc20_state(&call["recipientNew"], "recipientNew")]
                }
                other => die(&format!("unknown v0.6 function {other:?} — failing closed")),
            }
        }
        // v0.7 ORGANIZATIONAL M-of-N OWNER ROOT (contracts/PolicyVault.v0.7-root.sil
        // CANDIDATE): 18-field state — boundOrgId, owner1..owner12, ownerM,
        // emergencyK, recoveryM, then the FIXED-WIDTH TAIL `byte frozen` and
        // `byte[8] rootNonce` LAST, which is what a rooted vault slices and
        // rebuilds. Entrypoints: rootAction(newState, action 0..4, 780-byte
        // ownerSigs blob) and rootSuccession(newState, 65-byte successorSig).
        // Unknown names and out-of-domain values fail closed.
        "policyvault-0.7-root" => {
            const ROOT_SLOTS: usize = 12;
            const SIG_BLOB_LEN: usize = ROOT_SLOTS * 65; // 780
            let root_state = |call: &serde_json::Value| -> Expr<'static> {
                let successor = &call["successor"];
                if successor.is_null() {
                    die("successor is required for this function");
                }
                let int = |field: &str| -> i64 { json_i64(&successor[field], &format!("successor.{field}")) };
                let mut fields: Vec<(&'static str, Expr<'static>)> = vec![("boundOrgId", bound_vault_id.clone())];
                // slot names are fixed by the covenant's field order
                const SLOTS: [&str; ROOT_SLOTS] = [
                    "owner1", "owner2", "owner3", "owner4", "owner5", "owner6", "owner7", "owner8", "owner9", "owner10",
                    "owner11", "owner12",
                ];
                for name in SLOTS {
                    fields.push((
                        name,
                        Expr::bytes(hex_bytes(
                            successor[name].as_str().unwrap_or_else(|| die(&format!("successor.{name} is required (zero = inactive slot)"))),
                            32,
                            &format!("successor.{name}"),
                        )),
                    ));
                }
                let owner_m = int("ownerM");
                let emergency_k = int("emergencyK");
                let recovery_m = int("recoveryM");
                if !(1..=ROOT_SLOTS as i64).contains(&owner_m) {
                    die(&format!("successor.ownerM {owner_m} out of range [1,{ROOT_SLOTS}] — failing closed"));
                }
                if !(1..=owner_m).contains(&emergency_k) {
                    die(&format!("successor.emergencyK {emergency_k} out of range [1,ownerM] — failing closed"));
                }
                if !(0..=owner_m).contains(&recovery_m) {
                    die(&format!("successor.recoveryM {recovery_m} out of range [0,ownerM] — failing closed"));
                }
                fields.push(("ownerM", Expr::int(owner_m)));
                fields.push(("emergencyK", Expr::int(emergency_k)));
                fields.push(("recoveryM", Expr::int(recovery_m)));
                // TAIL: `byte frozen` is one of the two canonical bytes; a
                // numeric range check would admit 0x80 (negative zero), which
                // equals NEITHER and would self-lock the root.
                let frozen = int("frozen");
                if frozen != 0 && frozen != 1 {
                    die(&format!("successor.frozen {frozen} must be 0 or 1 — failing closed"));
                }
                fields.push(("frozen", Expr::byte(frozen as u8)));
                // `byte[8] rootNonce` is the unsigned little-endian encoding
                // OpNum2Bin(n, 8) produces, which is what the covenant demands
                // as `prev + 1`.
                let nonce = json_i64(&successor["rootNonce"], "successor.rootNonce");
                if nonce < 0 {
                    die("successor.rootNonce must be non-negative — failing closed");
                }
                fields.push(("rootNonce", Expr::bytes((nonce as u64).to_le_bytes().to_vec())));
                struct_object(fields)
            };
            if !call["signature"].is_null() {
                die("v0.7-root calls carry ownerSigs / successorSig, never `signature` — failing closed");
            }
            match function {
                "rootAction" => {
                    let action = json_i64(&call["action"], "action");
                    if !(0..=4).contains(&action) {
                        die(&format!("action {action} out of range [0,4] for rootAction (v0.7-root) — failing closed"));
                    }
                    let blob = hex_bytes(
                        call["ownerSigs"].as_str().unwrap_or_else(|| die("ownerSigs is required for rootAction (v0.7-root)")),
                        SIG_BLOB_LEN,
                        "ownerSigs",
                    );
                    vec![root_state(&call), Expr::int(action), Expr::bytes(blob)]
                }
                "rootSuccession" => {
                    if !call["action"].is_null() {
                        die("rootSuccession must NOT carry action (v0.7-root) — failing closed");
                    }
                    let succ = hex_bytes(
                        call["successorSig"].as_str().unwrap_or_else(|| die("successorSig is required for rootSuccession (v0.7-root)")),
                        65,
                        "successorSig",
                    );
                    vec![root_state(&call), Expr::bytes(succ)]
                }
                other => die(&format!("unknown v0.7-root function {other:?} — failing closed")),
            }
        }
        // v0.7 ROOTED PAYMENT PROFILE (contracts/PolicyVault.v0.7-payment.sil
        // CANDIDATE, derived from the FROZEN v0.5 by tools/gen_v7_payment.js):
        // the v0.5 5-field state and the v0.5 tokenAgentSpend ABI verbatim;
        // `ownerControl` gains selector 4 and LOSES its owner signature;
        // `ownerRecover` loses its owner signature. The owner AUTHORITY is the
        // organizational root INPUT, so an owner call carrying a signature is
        // a caller error and fails closed.
        "policyvault-0.7-payment" => {
            let successor_state_v07 = |call: &serde_json::Value| -> Expr<'static> {
                let successor = &call["successor"];
                if successor.is_null() {
                    die("successor is required for this function");
                }
                struct_object(vec![
                    ("boundVaultId", bound_vault_id.clone()),
                    ("feeReserve", Expr::int(json_i64(&successor["feeReserve"], "successor.feeReserve"))),
                    ("paused", Expr::int(json_i64(&successor["paused"], "successor.paused"))),
                    (
                        "agentRoot",
                        Expr::bytes(hex_bytes(
                            successor["agentRoot"].as_str().unwrap_or_else(|| die("successor.agentRoot is required")),
                            32,
                            "successor.agentRoot",
                        )),
                    ),
                    ("policyNonce", Expr::int(json_i64(&successor["policyNonce"], "successor.policyNonce"))),
                ])
            };
            let kcc20_state = |v: &serde_json::Value, label: &str| -> Expr<'static> {
                if v.is_null() {
                    die(&format!("{label} is required"));
                }
                let ty = json_i64(&v["identifierType"], &format!("{label}.identifierType"));
                if !(0..=2).contains(&ty) {
                    die(&format!("{label}.identifierType must be 0, 1 or 2 — failing closed"));
                }
                let amount = json_i64(&v["amount"], &format!("{label}.amount"));
                if amount < 0 {
                    die(&format!("{label}.amount must be non-negative — failing closed"));
                }
                let minter = v["isMinter"].as_bool().unwrap_or_else(|| die(&format!("{label}.isMinter must be an explicit boolean")));
                struct_object(vec![
                    (
                        "ownerIdentifier",
                        Expr::bytes(hex_bytes(
                            v["ownerIdentifier"].as_str().unwrap_or_else(|| die(&format!("{label}.ownerIdentifier is required"))),
                            32,
                            &format!("{label}.ownerIdentifier"),
                        )),
                    ),
                    ("identifierType", Expr::byte(ty as u8)),
                    ("amount", Expr::int(amount)),
                    ("isMinter", Expr::bool(minter)),
                ])
            };
            let pk = |field: &str| -> Expr<'static> {
                Expr::bytes(hex_bytes(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), 32, field))
            };
            let var = |field: &str| -> Expr<'static> {
                Expr::bytes(hex_var(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), field))
            };
            match function {
                "tokenAgentSpend" => {
                    // the ONLY v0.7-payment path with a signature: the agent's
                    let agent_sig = hex_bytes(
                        call["signature"].as_str().unwrap_or_else(|| die("signature (the agent's) is required for tokenAgentSpend")),
                        65,
                        "signature",
                    );
                    vec![
                        successor_state_v07(&call),
                        kcc20_state(&call["selfNew"], "selfNew"),
                        kcc20_state(&call["recipientNew"], "recipientNew"),
                        pk("agentPk"),
                        Expr::int(json_i64(&call["tokenMaxPerSpend"], "tokenMaxPerSpend")),
                        Expr::int(json_i64(&call["tokenPeriodBudget"], "tokenPeriodBudget")),
                        Expr::int(json_i64(&call["periodLengthDaa"], "periodLengthDaa")),
                        Expr::int(json_i64(&call["periodStartDaa"], "periodStartDaa")),
                        Expr::int(json_i64(&call["tokenPeriodSpent"], "tokenPeriodSpent")),
                        Expr::int(json_i64(&call["agentMaxFeePerTx"], "agentMaxFeePerTx")),
                        Expr::int(json_i64(&call["agentMaxCarryKas"], "agentMaxCarryKas")),
                        pk("agentRecipientRoot"),
                        var("policySiblings"),
                        Expr::int(json_i64(&call["policyPathBits"], "policyPathBits")),
                        Expr::int(json_i64(&call["periodsElapsed"], "periodsElapsed")),
                        pk("recipientPk"),
                        var("recipientSiblings"),
                        Expr::int(json_i64(&call["recipientPathBits"], "recipientPathBits")),
                        Expr::bytes(agent_sig),
                    ]
                }
                "ownerControl" => {
                    if !call["signature"].is_null() {
                        die("v0.7-payment ownerControl carries NO signature (the root input is the authority) — failing closed");
                    }
                    if call["opSelector"].is_null() {
                        die("opSelector is required for ownerControl (v0.7-payment) — failing closed");
                    }
                    let op = json_i64(&call["opSelector"], "opSelector");
                    if !(0..=4).contains(&op) {
                        die(&format!("opSelector {op} out of range [0,4] for ownerControl (v0.7-payment) — failing closed"));
                    }
                    vec![successor_state_v07(&call), Expr::int(op)]
                }
                "ownerRecover" => {
                    if !call["signature"].is_null() {
                        die("v0.7-payment ownerRecover carries NO signature (the root input is the authority) — failing closed");
                    }
                    if !call["opSelector"].is_null() {
                        die("ownerRecover must NOT carry opSelector (v0.7-payment) — failing closed");
                    }
                    vec![Vec::<Expr<'static>>::new().into(), kcc20_state(&call["recipientNew"], "recipientNew")]
                }
                other => die(&format!("unknown v0.7-payment function {other:?} — failing closed")),
            }
        }
        // v0.7 ROOTED HIERARCHICAL DELEGATION (contract `PolicyVaultRootedTokenHD`,
        // tools/gen_v7_payment_hd.js): five HD entrypoints (hdSpend / childSpendL2 /
        // childSpendL3 / delegateSetChildRoot1 / delegateSetChildRoot2), each
        // carrying its OWN 65-byte leaf/parent signature (read directly from
        // call["signature"], like v0.7-payment's tokenAgentSpend), PLUS the
        // BYTE-IDENTICAL rooted owner paths (ownerControl / ownerRecover, NO
        // signature — the root input is the authority).
        "policyvault-0.7-payment-hd" => {
            let successor_state_v07 = |call: &serde_json::Value| -> Expr<'static> {
                let successor = &call["successor"];
                if successor.is_null() {
                    die("successor is required for this function");
                }
                struct_object(vec![
                    ("boundVaultId", bound_vault_id.clone()),
                    ("feeReserve", Expr::int(json_i64(&successor["feeReserve"], "successor.feeReserve"))),
                    ("paused", Expr::int(json_i64(&successor["paused"], "successor.paused"))),
                    (
                        "agentRoot",
                        Expr::bytes(hex_bytes(
                            successor["agentRoot"].as_str().unwrap_or_else(|| die("successor.agentRoot is required")),
                            32,
                            "successor.agentRoot",
                        )),
                    ),
                    ("policyNonce", Expr::int(json_i64(&successor["policyNonce"], "successor.policyNonce"))),
                ])
            };
            let kcc20_state = |v: &serde_json::Value, label: &str| -> Expr<'static> {
                if v.is_null() {
                    die(&format!("{label} is required"));
                }
                let ty = json_i64(&v["identifierType"], &format!("{label}.identifierType"));
                if !(0..=2).contains(&ty) {
                    die(&format!("{label}.identifierType must be 0, 1 or 2 — failing closed"));
                }
                let amount = json_i64(&v["amount"], &format!("{label}.amount"));
                if amount < 0 {
                    die(&format!("{label}.amount must be non-negative — failing closed"));
                }
                let minter = v["isMinter"].as_bool().unwrap_or_else(|| die(&format!("{label}.isMinter must be an explicit boolean")));
                struct_object(vec![
                    (
                        "ownerIdentifier",
                        Expr::bytes(hex_bytes(
                            v["ownerIdentifier"].as_str().unwrap_or_else(|| die(&format!("{label}.ownerIdentifier is required"))),
                            32,
                            &format!("{label}.ownerIdentifier"),
                        )),
                    ),
                    ("identifierType", Expr::byte(ty as u8)),
                    ("amount", Expr::int(amount)),
                    ("isMinter", Expr::bool(minter)),
                ])
            };
            let pk = |field: &str| -> Expr<'static> {
                Expr::bytes(hex_bytes(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), 32, field))
            };
            let var = |field: &str| -> Expr<'static> {
                Expr::bytes(hex_var(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), field))
            };
            // one HD leaf BODY (160 bytes, the whole canonical ancestor argument)
            let leaf_body = |field: &str| -> Expr<'static> {
                Expr::bytes(hex_bytes(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), 160, field))
            };
            // "chain" array entries used by the spend entrypoints: one object per
            // ancestor level {leaf, siblings, pathBits, periodsElapsed,
            // recipientSiblings, recipientPathBits}, oldest ancestor first.
            let chain_spend_args = |chain: &serde_json::Value, want: usize, out: &mut Vec<Expr<'static>>| {
                let arr = chain.as_array().unwrap_or_else(|| die("chain must be an array"));
                if arr.len() != want {
                    die(&format!("chain must carry exactly {want} ancestor level(s) for this entrypoint — failing closed"));
                }
                for (i, entry) in arr.iter().enumerate() {
                    let label = format!("chain[{i}]");
                    out.push(Expr::bytes(hex_bytes(
                        entry["leaf"].as_str().unwrap_or_else(|| die(&format!("{label}.leaf is required"))),
                        160,
                        &format!("{label}.leaf"),
                    )));
                    out.push(Expr::bytes(hex_var(entry["siblings"].as_str().unwrap_or_else(|| die(&format!("{label}.siblings is required"))), &format!("{label}.siblings"))));
                    out.push(Expr::int(json_i64(&entry["pathBits"], &format!("{label}.pathBits"))));
                    out.push(Expr::int(json_i64(&entry["periodsElapsed"], &format!("{label}.periodsElapsed"))));
                    out.push(Expr::bytes(hex_var(
                        entry["recipientSiblings"].as_str().unwrap_or_else(|| die(&format!("{label}.recipientSiblings is required"))),
                        &format!("{label}.recipientSiblings"),
                    )));
                    out.push(Expr::int(json_i64(&entry["recipientPathBits"], &format!("{label}.recipientPathBits"))));
                }
            };
            // "chain" array entries used by the delegation entrypoints: one
            // object per MEMBERSHIP-ONLY ancestor above the delegating parent
            // {leaf, siblings, pathBits} — never the parent itself (that is
            // "parentLeaf"/"parentSiblings"/"parentPathBits" below).
            let chain_membership_args = |chain: &serde_json::Value, want: usize, out: &mut Vec<Expr<'static>>| {
                let arr = chain.as_array().unwrap_or_else(|| die("chain must be an array"));
                if arr.len() != want {
                    die(&format!("chain must carry exactly {want} membership-only ancestor level(s) above the delegating parent — failing closed"));
                }
                for (i, entry) in arr.iter().enumerate() {
                    let label = format!("chain[{i}]");
                    out.push(Expr::bytes(hex_bytes(
                        entry["leaf"].as_str().unwrap_or_else(|| die(&format!("{label}.leaf is required"))),
                        160,
                        &format!("{label}.leaf"),
                    )));
                    out.push(Expr::bytes(hex_var(entry["siblings"].as_str().unwrap_or_else(|| die(&format!("{label}.siblings is required"))), &format!("{label}.siblings"))));
                    out.push(Expr::int(json_i64(&entry["pathBits"], &format!("{label}.pathBits"))));
                }
            };
            match function {
                "hdSpend" | "childSpendL2" | "childSpendL3" => {
                    let level = match function {
                        "hdSpend" => 1,
                        "childSpendL2" => 2,
                        _ => 3,
                    };
                    let leaf_sig = hex_bytes(
                        call["signature"].as_str().unwrap_or_else(|| die("signature (the spending leaf's) is required")),
                        65,
                        "signature",
                    );
                    let mut args: Vec<Expr<'static>> = vec![
                        successor_state_v07(&call),
                        kcc20_state(&call["selfNew"], "selfNew"),
                        kcc20_state(&call["recipientNew"], "recipientNew"),
                    ];
                    chain_spend_args(&call["chain"], level, &mut args);
                    args.push(pk("recipientPk"));
                    args.push(Expr::bytes(leaf_sig));
                    args
                }
                "delegateSetChildRoot1" => {
                    let parent_sig = hex_bytes(
                        call["signature"].as_str().unwrap_or_else(|| die("signature (the parent's) is required")),
                        65,
                        "signature",
                    );
                    vec![
                        successor_state_v07(&call),
                        leaf_body("parentLeaf"),
                        var("siblings"),
                        Expr::int(json_i64(&call["pathBits"], "pathBits")),
                        Expr::bytes(hex_bytes(call["newChildRoot"].as_str().unwrap_or_else(|| die("newChildRoot is required")), 32, "newChildRoot")),
                        Expr::bytes(parent_sig),
                    ]
                }
                "delegateSetChildRoot2" => {
                    let parent_sig = hex_bytes(
                        call["signature"].as_str().unwrap_or_else(|| die("signature (the parent's) is required")),
                        65,
                        "signature",
                    );
                    let mut args: Vec<Expr<'static>> = vec![successor_state_v07(&call)];
                    chain_membership_args(&call["chain"], 1, &mut args); // a1 (level-1 grandparent, membership only)
                    args.push(leaf_body("parentLeaf"));
                    args.push(var("siblings2"));
                    args.push(Expr::int(json_i64(&call["pathBits2"], "pathBits2")));
                    args.push(Expr::bytes(hex_bytes(call["newChildRoot"].as_str().unwrap_or_else(|| die("newChildRoot is required")), 32, "newChildRoot")));
                    args.push(Expr::bytes(parent_sig));
                    args
                }
                "ownerControl" => {
                    if !call["signature"].is_null() {
                        die("v0.7-payment-hd ownerControl carries NO signature (the root input is the authority) — failing closed");
                    }
                    if call["opSelector"].is_null() {
                        die("opSelector is required for ownerControl (v0.7-payment-hd) — failing closed");
                    }
                    let op = json_i64(&call["opSelector"], "opSelector");
                    if !(0..=4).contains(&op) {
                        die(&format!("opSelector {op} out of range [0,4] for ownerControl (v0.7-payment-hd) — failing closed"));
                    }
                    vec![successor_state_v07(&call), Expr::int(op)]
                }
                "ownerRecover" => {
                    if !call["signature"].is_null() {
                        die("v0.7-payment-hd ownerRecover carries NO signature (the root input is the authority) — failing closed");
                    }
                    if !call["opSelector"].is_null() {
                        die("ownerRecover must NOT carry opSelector (v0.7-payment-hd) — failing closed");
                    }
                    vec![Vec::<Expr<'static>>::new().into(), kcc20_state(&call["recipientNew"], "recipientNew")]
                }
                other => die(&format!("unknown v0.7-payment-hd function {other:?} — failing closed")),
            }
        }
        // v0.7 ROOTED KAS SAFE-PAYMENT PROFILE (contracts/PolicyVault.v0.7-kas.sil
        // CANDIDATE, derived from the FROZEN v0.4.1 by tools/gen_v7_kas.js): the
        // v0.4.1 17-field successor state and the v0.4.1 agentSpend ABI verbatim;
        // `ownerControl` gains selector 6 (EMERGENCY pause) and LOSES its owner
        // signature (opSelector range 0..6); `ownerRecover` loses its owner
        // signature and carries no token continuation (this profile is plain
        // KAS — no token position exists to preserve). The owner AUTHORITY is
        // the organizational root INPUT, so an owner call carrying a signature
        // is a caller error and fails closed.
        "policyvault-0.7-kas" => {
            let successor_state_v07kas = |call: &serde_json::Value| -> Expr<'static> {
                let successor = &call["successor"];
                if successor.is_null() {
                    die("successor is required for this function");
                }
                let pk = |field: &str| -> Expr<'static> {
                    Expr::bytes(hex_bytes(
                        successor[field].as_str().unwrap_or_else(|| die(&format!("successor.{field} is required"))),
                        32,
                        &format!("successor.{field}"),
                    ))
                };
                let int = |field: &str| -> Expr<'static> { Expr::int(json_i64(&successor[field], &format!("successor.{field}"))) };
                let mut fields: Vec<(&str, Expr<'static>)> = vec![
                    ("boundVaultId", bound_vault_id.clone()),
                    ("protectedValue", int("protectedValue")),
                    ("feeReserve", int("feeReserve")),
                    ("paused", int("paused")),
                    ("agentRoot", pk("agentRoot")),
                ];
                const APPROVER_NAMES: [&str; 10] = [
                    "approver1", "approver2", "approver3", "approver4", "approver5", "approver6", "approver7", "approver8",
                    "approver9", "approver10",
                ];
                for name in APPROVER_NAMES {
                    fields.push((name, pk(name)));
                }
                fields.push(("approvalM", int("approvalM")));
                fields.push(("policyNonce", int("policyNonce")));
                struct_object(fields)
            };
            match function {
                "agentSpend" => {
                    let agent_sig = hex_bytes(
                        call["signature"].as_str().unwrap_or_else(|| die("signature (the agent's) is required for agentSpend")),
                        65,
                        "signature",
                    );
                    let pk = |field: &str| -> Expr<'static> {
                        Expr::bytes(hex_bytes(call[field].as_str().unwrap_or_else(|| die(&format!("{field} is required"))), 32, field))
                    };
                    let policy_sibs = hex_var(call["policySiblings"].as_str().unwrap_or(""), "policySiblings");
                    if policy_sibs.len() % 32 != 0 {
                        die("policySiblings length must be a multiple of 32 bytes");
                    }
                    let recip_sibs = hex_var(call["recipientSiblings"].as_str().unwrap_or(""), "recipientSiblings");
                    if recip_sibs.len() % 32 != 0 {
                        die("recipientSiblings length must be a multiple of 32 bytes");
                    }
                    let approvals = hex_bytes(call["approvals"].as_str().unwrap_or_else(|| die("approvals is required")), 650, "approvals");
                    vec![
                        successor_state_v07kas(&call),
                        Expr::int(json_i64(&call["payAmount"], "payAmount")),
                        pk("agentPk"),
                        Expr::int(json_i64(&call["maxPerSpend"], "maxPerSpend")),
                        Expr::int(json_i64(&call["periodBudget"], "periodBudget")),
                        Expr::int(json_i64(&call["periodLengthDaa"], "periodLengthDaa")),
                        Expr::int(json_i64(&call["periodStartDaa"], "periodStartDaa")),
                        Expr::int(json_i64(&call["periodSpent"], "periodSpent")),
                        Expr::int(json_i64(&call["approvalThreshold"], "approvalThreshold")),
                        Expr::int(json_i64(&call["agentMaxFeePerTx"], "agentMaxFeePerTx")),
                        pk("agentRecipientRoot"),
                        Expr::bytes(policy_sibs),
                        Expr::int(json_i64(&call["policyPathBits"], "policyPathBits")),
                        Expr::int(json_i64(&call["periodsElapsed"], "periodsElapsed")),
                        pk("recipientPk"),
                        Expr::bytes(recip_sibs),
                        Expr::int(json_i64(&call["recipientPathBits"], "recipientPathBits")),
                        Expr::bytes(agent_sig),
                        Expr::bytes(approvals),
                    ]
                }
                "ownerControl" => {
                    if !call["signature"].is_null() {
                        die("v0.7-kas ownerControl carries NO signature (the root input is the authority) — failing closed");
                    }
                    if call["opSelector"].is_null() {
                        die("opSelector is required for ownerControl (v0.7-kas) — failing closed");
                    }
                    let op = json_i64(&call["opSelector"], "opSelector");
                    if !(0..=6).contains(&op) {
                        die(&format!("opSelector {op} out of range [0,6] for ownerControl (v0.7-kas) — failing closed"));
                    }
                    vec![successor_state_v07kas(&call), Expr::int(op)]
                }
                "ownerRecover" => {
                    if !call["signature"].is_null() {
                        die("v0.7-kas ownerRecover carries NO signature (the root input is the authority) — failing closed");
                    }
                    if !call["opSelector"].is_null() {
                        die("ownerRecover must NOT carry opSelector (v0.7-kas) — failing closed");
                    }
                    vec![Vec::<Expr<'static>>::new().into()]
                }
                other => die(&format!("unknown v0.7-kas function {other:?} — failing closed")),
            }
        }
        other => die(&format!("unknown contractVersion {other:?} — failing closed")),
    };

    let contract = compile_contract(
        Box::leak(source.into_boxed_str()),
        &constructor_args,
        CompileOptions::default(),
    )
    .unwrap_or_else(|e| die(&format!("compile failed: {e}")));

    let encoded = contract
        .build_sig_script_for_covenant_decl(function, call_args, CovenantDeclCallOptions::default())
        .unwrap_or_else(|e| die(&format!("call encoding failed: {e}")));

    println!("{}", encoded.iter().map(|b| format!("{b:02x}")).collect::<String>());
}
