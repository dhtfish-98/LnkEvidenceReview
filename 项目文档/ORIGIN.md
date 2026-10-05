# Source and independent implementation

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.4**. Upstream authors and reused components retain their original attribution.


The reference project is [Matmaus/LnkParse3](https://github.com/Matmaus/LnkParse3),
fixed at `ad4230280b4ee1ceb3cdf5f274e6d92fb12e7abb`, under MIT. No LnkParse3 runtime or original sample is bundled, so its separate reference
license copy is omitted. `SOURCE_REVIEW.json` records
all 48 selected Python files (4093 physical lines), README and LICENSE: 50 full
reads, each matched to local bytes, fixed Git tree blob identity and independently
retrieved fixed raw bytes. This does not claim the complete repository's tests,
binary samples or all 142 repository blobs were audited.

New implementation author: dhtfish98. Runtime, tests and packaging implement the declared finite scope.
The project does not call or bundle the old parser. Microsoft Open Specifications
define the format independently; this is a finite structural review, not a full
rewrite of every Windows Shell namespace or application-specific property decoder.
The original selected source contains namespace TODO classes and unsupported
property types, which are not silently treated as understood here.

Original-risk observations informed independent checks: StringData cannot clamp
the declared count before advancing; a Unicode suffix offset cannot add four;
Shim text is Unicode; local/network flags can both be set; all console colors are
present; duplicate ExtraData entries cannot overwrite one another; and signed I2
properties include checked padding instead of a four-byte unpack on two bytes.
These observations are not a claim of complete upstream security auditing.

The 459-byte `tests/ms-shllink-10.0-file.hex` fixture is the exact file example in
MS-SHLLINK 10.0 section 3.1, SHA-256
`09ac337f52c4c9dc49772e97060145a316cb4af076cfb122fb4a219ecbfbfdd7`.
It contains the documented `C:\test\a.txt` example and is parsed only as bytes.
Microsoft's Open Specifications intellectual-property notice permits sample
implementations/examples. Only this small published format example is included;
the complete reference PDF/DOCX is excluded from the package and source archive.

There are no bundled third-party runtime dependencies. Python's standard library,
its finite built-in codecs and the host interpreter are trusted implementation
dependencies. Build tools are separately fixed in `requirements-build.lock`;
they are not target content and are not required by an installed wheel.

The repository URL names the intended publishing destination. Local completion
does not prove that destination exists, remote CI passes, or a CVP application is
approved. Root publication review and CVP/application identity remain separate.
