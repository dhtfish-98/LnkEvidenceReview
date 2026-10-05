> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# LnkEvidenceReview

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.4**. Upstream authors and reused components retain their original attribution.


Read one caller-supplied Windows `.lnk` byte snapshot and produce bounded structure,
reference-path and argument metadata evidence. The parser is written independently
with Python's standard library. It never follows a target, icon, UNC share or URL,
expands an environment variable, resolves a Shell namespace, invokes MSI, or runs
a command. There are no runtime dependencies.

```sh
python -m pip install --no-index --no-deps dist/lnk_evidence_review-0.1.4-py3-none-any.whl
lnk-evidence-review /absolute/authorized/sample.lnk > review.json
lnk-evidence-review /absolute/authorized/sample.lnk --ansi-codepage cp1252 --show-text
```

Only the explicit local file is opened. On supported POSIX systems the reader holds
ancestor directory descriptors, refuses symlinks and `..` components, uses no-follow
opens, rejects nonregular files without blocking on FIFOs, and checks descriptor
metadata before and after reading. Unsupported platforms or flags return OPEN.
The snapshot check is a bounded consistency observation; it cannot authenticate
the file or prove that an adversary never changed bytes between observations.

```python
from lnk_evidence_review import Limits, review_bytes, encode_report

report = review_bytes(authorized_bytes, limits=Limits(), ansi_codepage="cp1252")
print(encode_report(report), end="")
```

The API accepts immutable `bytes` only. Invalid API types/options raise a fixed
`TypeError` or `ValueError`; malformed or unsupported file structures produce a
report. The CLI emits one ASCII JSON line; exit 0 means PASS, 1 FAIL, 2 OPEN.
Argument/reader errors also emit fixed JSON without echoing supplied paths.
`--help` is ordinary fixed help text. Limits can be lowered with `--input-bytes`
and `--report-bytes`; further finite limits are available through `Limits`.

PASS means this frozen structural profile was completed without a known format
failure or unresolved format feature. FAIL means a definite required-field,
size, encoding or bounds violation was observed. OPEN means an unsupported or
ambiguous field, opaque payload, missing encoding assertion or exhausted budget.
FAIL takes precedence while OPEN findings remain visible. A partial parse cannot
become PASS. All reports keep target/source authenticity, actual resolution or
execution, metadata currentness, maliciousness/safety and CVP eligibility OPEN.
Format PASS therefore does not establish that activating a shortcut is safe.

The format profile covers the fixed ShellLinkHeader; complete ItemID framing;
both local and network LinkInfo branches and their ANSI/Unicode fields; all five
counted StringData fields; all eleven published ExtraData envelopes; their terminal
blocks; and MS-PROPSTORE storage/value framing. Namespace ItemID contents are
vendor-defined and retained with class byte, exact physical range and SHA-256;
they remain OPEN. No universal namespace-to-path decoder is claimed. Darwin's
descriptor is read as text but its MSI packed-identifier semantics remain OPEN.
Property values support a documented finite scalar/string/GUID subset; other
variants and opaque blobs remain OPEN. See [DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>).

Every admitted structure has a physical input offset, size and SHA-256. Unknown
blocks are preserved as separate records, including duplicates and trailing bytes;
the original immutable input plus a record's exact range can reconstruct its bytes.
Hashes and locations are provenance, not authenticity. Input above the byte budget
is not hashed or admitted. Reports contain no input pathname.

Text, machine GUIDs, drive serials, property names and property scalars are redacted
by default. `--show-text` is an explicit disclosure option for escaped strings, GUIDs
and property values. Output uses JSON ASCII escaping, including controls and bidi
characters, and never copies a string into a command or terminal action. Finite
indicators such as UNC/URL shape, environment markers, shell metacharacters or
parent segments describe text shape and do not establish maliciousness. ANSI text
outside ASCII remains OPEN unless the caller asserts the supported single-byte
`cp1252` or `cp437` encoding. Console display-codepage metadata does not select a
decoder, and OLEPS CodePageString semantics remain OPEN.

The default budget is 4 MiB input, 4096 structure records, 512 ItemIDs, 128 ExtraData
blocks, 512 property values, 256 KiB aggregate decoded text, 64 KiB per text field,
256 distinct findings and 2 MiB JSON output including its newline. Values may only
be lowered; report output must allow at least 2048 bytes. If the report is too large,
records are omitted with OPEN and any known FAIL retained. Exact limits are included
in each report. Fixed-field bytes after their first NUL are undefined and are never
interpreted as text, but the containing structure hash includes them.

The original selected source, independent implementation boundaries and attribution
are documented in [ORIGIN.md](<ORIGIN.md>), [SOURCE_REVIEW.json](<SOURCE_REVIEW.json>)
and [NOTICE](<NOTICE>). Validation evidence is in [VALIDATION.md](<VALIDATION.md>).

Safe local file input requires positive integer `O_DIRECTORY`, `O_NOFOLLOW`, `O_CLOEXEC`, `O_NONBLOCK` flags, plus directory-relative operations only where used by this reader. Missing, None, zero or boolean flags return the existing controlled unsupported/error result before opening input. File-reader validation covers macOS/Linux; native Windows safe file reading is not established.
