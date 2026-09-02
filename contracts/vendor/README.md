# Vendored reference programs (byte-exact copies)

`kcc20-reference.sil` — the upstream KCC20 fungible-token covenant example
(`silverscript-lang/tests/examples/kcc20.sil` in the authoritative
`~/silverscript` checkout), copied VERBATIM (no header, no reformatting) so
its sha256 equals the `sourceSha256` pinned in
`core/assets/test/fixtures/kcc20-template-v1.json`. PolicyVault's `kcc20/1`
asset adapter compiles this program (parameterized by the family bound and
the token input's revealed state) ONLY to encode the token family's own
`transfer` call for a transaction the v0.5 controller authorizes; the
compiled script must reproduce the token UTXO's exact P2SH script public
key before the encoding is used (production-byte rule), otherwise the
adapter fails closed ("unsupported token program"). No runtime dependency
on the mutable reference checkout exists.
