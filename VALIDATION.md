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
