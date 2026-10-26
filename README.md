# dbunk-conformance

Checks that a [dbunk](https://github.com/beardfaceguy/dbunk) worked example follows dbunk's `PROTOCOL.md` and replays as a valid rubber_ducky review protocol v1.3 exchange.

dbunk is a specification with no executable code, and it must not depend on rubber_ducky. This repository holds the check instead. It installs rubber_ducky at the commit dbunk pins, `0ed4576123380169594b48233bb573a573fb094c`.

## What it checks

For one example directory, the check does three things:

1. **Projects** every dbunk message to v1.3, as `PROTOCOL.md` section 8.2 defines. It removes the dbunk extension fields, and makes the packet digest the request's and rebuttals' only payload. It then validates the results against rubber_ducky's v1.3 message models and replays them through `rubber_ducky.core.lifecycle.replay_review`.
2. **Checks the rules that span documents**, which JSON Schema cannot:
   - claim IDs are unique;
   - qualification targets exist, are not the qualification itself, and form no cycle;
   - evidence references resolve;
   - each bundle's manifest matches its file tree;
   - `previous_class` is set exactly when a claim is reclassified;
   - each request and response names the current revision;
   - every rebuttal that ACCEPTs a concern changes the packet digest;
   - concern `claim_ids` exist in the reviewed revision.
3. **Tracks verification records** across revisions, with carry-over under the rules in section 7.3. After every response it enforces:
   - no claim is left unaccounted for;
   - APPROVE comes only when every claim has a record;
   - evidence that fails its digest is never recorded as checked, and is always named by an open blocking concern.

It prints the per-claim status after every response, and exits non-zero on any error.

## Run it

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12 or later.

```bash
git clone https://github.com/beardfaceguy/dbunk
git -C dbunk checkout a31c82d450f3fb6ea10f289d1d4054d503d37f50   # the example this check was last run against
uv sync
uv run dbunk-conformance dbunk/examples/credential-audit
DBUNK_EXAMPLE=dbunk/examples/credential-audit uv run pytest
```

The tests copy the example and break one rule at a time. Each test expects the check to catch the break.

## Example layout

An example directory holds:

- `packet-*.json`, the packet revisions;
- `bundle-*/`, the bundles, each a `manifest.json` beside a `files/` tree;
- `messages/`, whose files sort into conversation order and name their type: `review-request`, `review-response`, `rebuttal` or `escalation-summary`.
