# PolicyVault Fee / Mass Specification (Toccata tx version 1)

Source-backed derivation of the exact minimum consensus fee for PolicyVault
transactions on testnet-10. Every rule cites the rusty-kaspa source it was
read from (tag v2.0.1, the version the running node and the encoder are built
against). This replaces the earlier margin-based handling.

## 1. Serialized size

`consensus/core/src/mass/mod.rs::transaction_estimated_serialized_size` and
its input/output helpers:

```
size = 2 (version u16)
     + 8 (input count u64)
     + Σ inputs:  36 (outpoint: 32 txid + 4 index)
                + 8 (sig-script length u64) + len(signatureScript)
                + 8 (sequence u64)
                + 2 (compute_budget u16, present iff version >= 1)
     + 8 (output count u64)
     + Σ outputs: 8 (value u64)
                + 2 (spk version u16)
                + 8 (spk length u64) + len(scriptPublicKey.script)
                + [ 2 (authorizing_input u16) + 32 (covenant_id) iff output.covenant is set ]
     + 8 (lock time u64)
     + 20 (subnetwork id, SUBNETWORK_ID_SIZE)
     + 8 (gas u64)
     + 32 (payload hash, HASH_SIZE)
     + 8 (payload length u64) + len(payload)
```

The covenant-binding bytes on outputs (2 + 32) are the term the WASM helper
omits — the root cause of the earlier discrepancy (see §5).

## 2. Compute mass

`Mass::calc_non_contextual_masses` (same file):

```
compute_mass = size * mass_per_tx_byte
             + (Σ outputs (2 + len(spk.script))) * mass_per_script_pub_key_byte
             + script_mass

script_mass (version >= 1) = GRAMS_PER_COMPUTE_BUDGET_UNIT * Σ inputs.compute_budget
```

Constants (testnet-10 params + `consensus/core/src/mass/units.rs`):

- `mass_per_tx_byte = 1`
- `mass_per_script_pub_key_byte = 10`
- `GRAMS_PER_COMPUTE_BUDGET_UNIT = 100`

(v0's `sig_op_count * GRAMS_PER_SIGOP_COUNT_UNIT` path does not apply to
version-1 transactions — v1 uses compute_budget instead.)

## 3. Transient mass and normalization

```
transient_mass       = size * TRANSIENT_BYTE_TO_MASS_FACTOR      (factor = 4)
normalized_transient = ceil(transient_mass * cofactor_transient)
cofactor_transient   = L_compute / L_transient
```

Post-Toccata block mass limits (`consensus/core/src/config/params.rs`):
`prior_block_mass_limits = with_shared_limit(500_000)` → compute limit
500_000; `new_transient_mass_limit = 1_000_000`. Hence
`cofactor_transient = 500_000 / 1_000_000 = 0.5` and
`normalized_transient = ceil(size * 4 * 0.5) = size * 2`.

## 4. Minimum required fee

`mining/src/mempool/check_transaction_standard.rs`:

```
fee_mass    = max(compute_mass, normalized_transient)      // post-Toccata
minimum_fee = (fee_mass * minimum_relay_transaction_fee) / 1000
            = (fee_mass * 100_000) / 1000
            = fee_mass * 100                                // integer, exact
```

`DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE = 100_000` sompi/kg
(`mining/src/mempool/config.rs`). The `/1000` is exact because `fee_mass`
is an integer and `100_000 / 1000 = 100`.

Storage mass (`calc_storage_mass`, KIP-0009) does **not** add a relay-fee
floor (comment in the same mempool function); it is only checked against the
per-dimension standard mass cap (500_000). PolicyVault outputs carry large
KAS values, so storage mass is ~0 and far under the cap. The module asserts
`fee_mass <= cap` defensively.

## 5. The observed discrepancy — explained

The WASM `calculateTransactionMass` / `calculateTransactionFee` undercount
because the estimated serialized size they use omits the per-output
covenant-binding bytes (2 + 32 = 34 bytes/output) and, in this SDK version,
do not reflect the version-1 compute-budget script-mass consistently. This
is a **WASM-helper limitation for covenant + v1 transactions**, not a node
bug and not a covenant defect. PolicyVault therefore computes mass and fee
directly from the source formulas above (`sdk/src/fee-mass.js`) and no
longer trusts the WASM recalculators for funds paths.

## 6. Fee sourcing invariant

Protected covenant principal is never spent on fees. For covenant-spend
shapes the covenant input value flows exactly to
`authorized payment + successor protected value`; the fee is paid entirely
from ordinary delegate/owner fuel inputs via the ordinary change output:

```
old protected value = authorized payment + successor protected value
fee                 = Σ ordinary fuel inputs − ordinary change
```

The finalizer re-derives the fee from the fully-signed transaction and
rejects if `fee < minimumRequiredFee` or if any protected-value equation
fails.
