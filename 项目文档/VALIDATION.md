> 本页保留 0.1.2 的历史验证记录；0.1.3 的发布验证状态请以对应提交的 GitHub Actions 和 Release 资产为准。

# Current licensing validation — 0.1.2

This patch removes only 1 confirmed unused complete reference-license/notice copies. New implementation author remains dhtfish98. Runtime parsing and evidence interpretation are unchanged; runtime changes are package version constants and any existing version display. The new source suite ran **43 unittest methods with nonzero PASS**. Current source identities are in SOURCE_MANIFEST.json, and LICENSE_CLEANUP.json describes the exact licensing boundary. Wheel and sdist reconstruction, fresh isolated consumer tests, CLI contracts, runtime/notice byte identity and package metadata are independently bound to the new assets in the batch release records; source tests alone do not prove those outcomes. New hosted CI and publication remain separate observations.

The original Microsoft 459-byte format example and unchanged separately released offline build-tool archive remain attributed. Every original tool/runtime/vendor notice remains inside that archive.

## Historical validation evidence

All following earlier version/count/native observations are historical evidence, not validation of this new patch. Statements below about then-retained reference copies describe the earlier artifacts. Current licensing membership is LICENSE_CLEANUP.json.

# Current validation — 0.1.1

The 2026-10-03 attribution update identifies the new implementation author and maintainer as dhtfish98. The final wheel and sdist were rebuilt, and a fresh isolated consumer ran **43 existing and targeted unittest methods successfully**, imported the installed package from site-packages, exercised the declared CLI contract and matched every shipped runtime/notice byte to current source. Wheel metadata records author dhtfish98 and version 0.1.1; RECORD and source-distribution contents were checked. Current runtime identities are in SOURCE_MANIFEST.json; ATTRIBUTION_UPDATE.json records the exact selected validation scope. The matching private build/install/test logs and artifact hashes are retained in the batch validation records, outside this public project.

This update also checks every required safe-read flag for exact positive integer capability before input is opened. API/CLI tests cover missing, None, zero and boolean flags, ordinary files and symbolic links. The PDF reader additionally refuses a FIFO before open when nonblocking capability is unavailable.

The current safe-file capability gate also requires set/frozenset directory-relative support declarations containing each actually used operation before opening input. Missing, None, empty, malformed or operation-incomplete collections yield the existing controlled unsupported result. Normal set/frozenset declarations and API/CLI rejection-before-open are regression tested.

## Historical validation evidence

The following earlier records retain their original versions, counts and fixed source identities. They are historical observations, not evidence that an old artifact is the current package.

# Validation contract and local evidence

Local validation uses Python 3.14.6 on macOS arm64, standard-library runtime only.
38 unittest methods cover all eleven ExtraData envelopes, all five string fields,
local/network and ANSI/Unicode variants, Unicode network-only and volume labels,
every major relative offset/owner size, duplicate blocks/properties, malformed
types, terminal0/1/2/3, unknown/trailing payload provenance, budget exhaustion,
privacy, FIFO/symlink/platform gates, snapshot change and JSON CLI errors.
The suite includes a fixed-seed 1000-case mutation smoke check and all 459 truncated
prefixes of the official sample; no target shortcut is activated.

The independent reference outline in `tests/fixtures.py` imports no parser code.
It reads persisted flags, region order, count-based strings, LinkInfo suffix and
ExtraData offset/size/signature envelopes independently. Both the Microsoft
459-byte fixed vector and generated benign layouts are compared to this outline.
It is a framing/text cross-check, not an independent implementation of every
property or vendor namespace. Opaque records additionally verify exact hash/range
re-extraction from the original bytes.

A runtime audit-hook test rejects file opens, target imports, socket operations,
process starts and system/exec calls during ten API reviews of UNC/URL/environment
and command-like text; no attempt occurs and the input hash is unchanged. This is
evidence for those reviewed paths, not proof of all interpreter behavior. Trusted
standard-library codec loading and this project's package import precede the hook.

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
python -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
python -m build --no-isolation
python -m venv /absolute/consumer
/absolute/consumer/bin/python -m pip install --no-index --no-deps dist/*.whl
PYTHONPATH='' /absolute/consumer/bin/python -m unittest discover -s tests -v
PYTHONPATH='' /absolute/consumer/bin/python scripts/verify_consumer.py
```

The installed-consumer check verifies every installed runtime file against its
frozen source, imports from the consumer environment, tests API input immutability
and replays 22 actual CLI cases via both installed script and module entry. Cases
include PASS/FAIL/OPEN, Unicode redaction/disclosure, known metadata, input/report
budgets and private argument errors. CLI fixtures are created in a separate real
temporary directory, and neither the tests nor installed package execute them.

Final package identities, full source inventory and actual fresh offline wheel/
sdist install logs are bound in the external engineering report. Local success does
not prove remote publication or CI. The checked-in workflow declares Python3.11/
3.14 Linux verification; its remote results remain OPEN until separately observed.
Source/target authenticity, activation behavior, enforcement, applicant identity,
organization and CVP approval remain OPEN regardless of test results.
