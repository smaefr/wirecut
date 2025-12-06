# Threat model

wirecut parses untrusted WCT1 telemetry frames into structured TLV fields.
There is no cryptography, authentication, compression, or multi-frame
reassembly. The only security property the parser claims is **memory safety
and bounded parsing** of a single datagram-sized buffer.

## Assets

- Host process integrity (no out-of-bounds read/write, no undefined behavior).
- Availability of the parser (bounded work; max 4096-byte frames, at most 255 TLVs).
- Integrity of parsed output: `ParseResult::packet` is meaningful only when
  `status == ParseStatus::Ok`.

## Attack surface

| Surface | Trust | Notes |
| --- | --- | --- |
| Byte buffer passed to `wirecut::parse` | Untrusted | Network, file, stdin, fuzzer corpus |
| `wirecut-parse` CLI file/stdin | Untrusted | Same parser, no extra privileges |
| Build options (`WIRECUT_HISTORICAL_UNSAFE`) | Trusted / must stay off | Compile-time path documenting a fixed bug |

Callers must not treat TLV `tag`/`value` as trusted commands. wirecut does not
interpret tags.

## STRIDE

| Category | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| Spoofing | Attacker forges frames | None. No MAC, signature, or origin check. | Any peer can emit WCT1-looking bytes. |
| Tampering | Mutated magic, version, lengths | Reject bad magic/version; length vs remaining checks. | Valid-looking frames can still carry attacker-chosen TLV values. |
| Repudiation | No audit log | Out of scope. | Callers that need provenance must add it. |
| Information disclosure | OOB read of adjacent heap/stack | Explicit remaining-size checks before every field access; ASan in tests/CI. | Parser does not wipe unused buffer tail. |
| Denial of service | Huge length, many TLVs, deep recursion | Cap 4096 bytes; `n_tlvs` is uint8; no recursion; reject overflow lengths. | A flood of valid max-size frames is a caller/network problem. |
| Elevation of privilege | Parser used to corrupt memory then RCE | No writes into caller memory except the output `Packet`; no `memcpy` of untrusted length without a check. | Downstream interpreters of TLV values are out of scope. |

## Trust boundary

Untrusted bytes enter only at `wirecut::parse(const uint8_t* data, size_t size)`.
The function may read indices `[0, size)` and only after `size <= 4096` and
`data != nullptr` (or `size == 0`). Structured `Packet` fields are trusted
*as parse results*, not as application meaning.

## Tradeoffs

- **No crypto.** Frames are not authenticated. Use TLS or an application MAC
  if the transport is hostile.
- **No reassembly.** Split datagrams are truncated, not stitched. Prevents
  state-machine complexity and reassembly bombs.
- **No TLV schema.** Unknown tags are accepted if the framing is well-formed.
  Policy belongs in the caller.
- **Trailing bytes after `n_tlvs` TLVs are ignored.** Extra tail data is not
  interpreted; it is also not treated as a second frame.
- **Fail-closed on length.** A claimed TLV length larger than remaining bytes
  is `LengthOverflow`, not a truncated success.

## Non-goals

DNS, compression bombs, streaming sockets, privilege separation inside this
library, and constant-time parsing.
