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
    let signature = hex_bytes(
        call["signature"].as_str().unwrap_or_else(|| die("signature is required")),
        65,
        "signature",
    );

    /*
     * Contract-version dispatch. Absent field = the original v0.1 encoding
     * (backward compatible with the TESTNET-VERIFIED v0.1 tooling); the
     * explicit v0.2 tag selects the 14-field state shape; anything else
     * fails closed.
     */
    let contract_version = call["contractVersion"].as_str().unwrap_or("policyvault-0.1-beta");

    /*
     * boundVaultId is filled from the immutable vaultId constructor arg. Its
     * index differs by contract version:
     *   v0.1: (owner, delegate, vaultId, ...)  -> index 2
     *   v0.2: (owner, vaultId, initDelegate, ...) -> index 1
     */
    let vault_id_index = match contract_version {
        "policyvault-0.1-beta" => 2,
        "policyvault-0.2" => 1,
        "policyvault-0.3" => 1, // (owner, vaultId, initDelegate, ...)
        "policyvault-0.4" => 1, // (owner, vaultId, initAgentRoot, ...)
        "policyvault-0.4.1" => 1, // identical constructor order to v0.4
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
