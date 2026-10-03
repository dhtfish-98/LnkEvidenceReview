# Frozen structural profile

The reference is [Microsoft MS-SHLLINK 10.0, 2025-11-21](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943).
The parser inspects only explicitly supplied bytes. It is a format evidence review,
with metadata declarations separated from observations of an actual target.

| Region | Support and unresolved boundary |
|---|---|
| Header | Size/CLSID, all published flags, required zero/reserved fields, file attributes, hotkey, all FILETIME integers, low 32-bit size, signed icon index and default ShowCommand mapping. Unknown flags/attribute bits OPEN; unused flags ignored as specified. |
| TargetIDList / Vista IDList | Complete size/terminal/bounds framing and each ItemID's range, hash and class byte. Arbitrary vendor namespace contents OPEN; no resolution or guessed universal path. |
| LinkInfo | 28-byte or >=36-byte header, both volume/local and network branches, volume labels including Unicode special offset, network provider/flags and optional Unicode offsets, all ANSI/Unicode local/suffix/network/device strings. Unknown header extension and overlapping structures OPEN. |
| StringData | Name, relative path, working directory, arguments and icon location in flag order. Full declared count is consumed. Non-argument count >260 FAIL under the fixed 10.0 profile; arguments are bounded by resource limits, not MAX_PATH. Counted NULs OPEN; invalid Unicode FAIL. |
| Environment / IconEnvironment / Darwin | Exact 0x314 size; both fixed ANSI and Unicode fields, NUL/padding handling, no expansion. Darwin descriptor semantics OPEN. |
| Console | Exact 0xCC size, signed coordinates, font/face/cursor/history fields, positive boolean mapping, all sixteen color DWORDs; undefined unused fields ignored. Unknown fill/font values OPEN. |
| ConsoleFE | Exact 12 bytes and declared display codepage; never a decoder override. |
| Tracker | Exact 0x60, Length 0x58/version0, bounded machine text, all four GUIDs, no tracking service access. |
| SpecialFolder / KnownFolder | Exact 16/28 bytes, folder declaration and ItemID-boundary offset; missing target list OPEN, non-boundary offset FAIL. No folder resolution. |
| Shim | At least 0x88 bytes, even-size Unicode payload, bounded NUL-terminated text; no compatibility-layer activation. |
| PropertyStore | Full size/version/unique-format/storage terminal/value terminal/name reserved/unique identity framing under MS-PROPSTORE; unknown tails OPEN. |
| Unknown / duplicate / terminal | Every block separately recorded with exact physical provenance. Duplicate signatures OPEN, unknown signatures OPEN, terminal DWORD0/1/2/3 accepted, sizes4..7 FAIL, missing terminal FAIL, trailing bytes OPEN. |

MS-PROPSTORE [storage](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-propstore/1eb58eb3-e7d8-4a09-ac0e-8bcb14b6fa0e),
[integer names](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-propstore/2af87219-ce09-4ff0-b0bf-65bcc3db5131)
and [string names](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-propstore/4720a485-d2e5-4a14-8f7e-4befd6516f9d)
are framed independently. The [MS-OLEPS TypedPropertyValue](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oleps/f122b9d7-e5cf-4484-8466-83f6fd94b3cc)
subset is VT_EMPTY/NULL, I2/I4/R4/R8/ERROR/BOOL/I1/UI1/UI2/UI4/I8/UI8/INT/UINT,
FILETIME and CLSID; scalar zero padding/BOOL representation are checked. LPWSTR
has a counted UTF-16 string and four-byte zero padding. BSTR/LPSTR sizes and
terminators are read with codepage semantics OPEN. BLOB/BLOB_OBJECT framing is
checked, payload interpretation OPEN. Other VARTYPEs, including vectors, arrays,
indirect properties, currency, dates and decimals, remain opaque OPEN with byte
provenance. Nonfinite floating values remain OPEN and are never emitted as JSON NaN.
The parser does not infer a FormatID's application-specific property meaning.

All offsets are owner-relative and checked before reads. ForceNoLinkInfo suppresses
resolution semantics, not physical consumption. Unicode path suffix offsets are
used directly. Unicode network extensions are selected by NetNameOffset; a
network-only extension uses the conservative paired 28-byte offset layout, with an
inactive Unicode device offset required to be zero for PASS. The specification's
offset-presence wording is ambiguous for a single-offset 24-byte layout; it is
parsed as bounded evidence with OPEN. A nonzero inactive device offset is also OPEN.
No precedence is
invented between conflicting ANSI/Unicode path declarations, no target paths are
composed, and no code page or environment is discovered from the user's machine.

Input limits, unprocessed payloads, unknown encodings and unknown structures cannot
be hidden by previously observed metadata. Known FAIL remains FAIL if a later
budget or unsupported feature causes OPEN. A report cap can omit detailed records
but keeps a fixed known-failure indicator. The finite protocol profile deliberately
does not promise compatibility with every shell data source or older Windows loader.

No generation/patching, target/icon access, module search, execution, network,
Windows COM, registry lookup, MSI resolution, environment expansion or persistence
is implemented. Scripts in this repository build/test only this trusted project.
No runtime target authenticity, activation behavior, enforcement, CVP eligibility,
applicant identity or organization approval follows from structural PASS.
