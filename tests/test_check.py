"""Each test breaks one rule in a copy of the dbunk example and expects the check to catch it.

Set DBUNK_EXAMPLE to a dbunk checkout's examples/credential-audit directory.
"""

import json
import os
import shutil
from hashlib import sha256
from pathlib import Path

import pytest

from dbunk_conformance.check import check_example

EXAMPLE = os.environ.get("DBUNK_EXAMPLE")
pytestmark = pytest.mark.skipif(not EXAMPLE, reason="DBUNK_EXAMPLE is not set")


@pytest.fixture
def example(tmp_path: Path) -> Path:
    copy = tmp_path / "example"
    shutil.copytree(EXAMPLE, copy)
    return copy


def read(path: Path) -> dict:
    return json.loads(path.read_bytes())


def write(path: Path, value: dict) -> str:
    data = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    path.write_bytes(data)
    return sha256(data).hexdigest()


def errors_mentioning(example: Path, text: str) -> list[str]:
    return [error for error in check_example(example).errors if text in error]


def test_unmodified_example_conforms(example: Path) -> None:
    report = check_example(example)
    assert report.errors == []
    assert report.final_status == "approved"


def test_accept_without_new_packet_digest(example: Path) -> None:
    rebuttal = example / "messages/03-rebuttal.json"
    request = read(example / "messages/01-review-request.json")
    write(rebuttal, {**read(rebuttal), "packet_digest": request["packet_digest"]})
    assert errors_mentioning(example, "does not change the packet digest")


def test_approve_with_unrecorded_claim(example: Path) -> None:
    response = example / "messages/06-review-response.json"
    message = read(response)
    write(response, {**message, "verification_records": message["verification_records"][:1]})
    assert errors_mentioning(example, "APPROVE while a claim lacks a record")


def test_concern_names_absent_claim(example: Path) -> None:
    response = example / "messages/02-review-response.json"
    message = read(response)
    message["blocking_concerns"][1]["claim_ids"] = ["00000000-0000-4000-8000-000000000000"]
    write(response, message)
    assert errors_mentioning(example, "names claims absent")


def test_unaccounted_claim(example: Path) -> None:
    response = example / "messages/02-review-response.json"
    message = read(response)
    write(response, {**message, "verification_records": message["verification_records"][1:]})
    assert errors_mentioning(example, "unaccounted claims")


def test_record_on_evidence_that_fails_its_digest(example: Path) -> None:
    response = example / "messages/02-review-response.json"
    message = read(response)
    packet = read(example / "packet-r1.json")
    policy_claims = [
        claim["id"]
        for claim in packet["claims"]
        if any(reference.get("bundle_path") == "docs/vendor-key-policy.txt" for reference in claim.get("evidence", []))
    ]
    message["verification_records"] = message["verification_records"] + policy_claims
    write(response, message)
    assert errors_mentioning(example, "cites evidence that fails its digest")


def test_qualification_loses_record_with_its_qualified_claim(example: Path) -> None:
    packet = read(example / "packet-r1.json")
    correction = next(claim for claim in packet["claims"] if claim["class"] == "qualification" and len(claim["qualifies"]) == 1)
    response = example / "messages/04-review-response.json"
    message = read(response)
    message["verification_records"] = [claim_id for claim_id in message["verification_records"] if claim_id != correction["id"]]
    write(response, message)
    assert errors_mentioning(example, "unaccounted claims")


def test_qualification_cycle(example: Path) -> None:
    path = example / "packet-r3.json"
    packet = read(path)
    qualifications = [claim for claim in packet["claims"] if claim["class"] == "qualification"]
    qualifications[0]["qualifies"] = [qualifications[1]["id"]]
    qualifications[1]["qualifies"] = [qualifications[0]["id"]]
    write(path, packet)
    assert errors_mentioning(example, "form a cycle")


def test_missing_previous_class(example: Path) -> None:
    path = example / "packet-r2.json"
    packet = read(path)
    for claim in packet["claims"]:
        claim.pop("previous_class", None)
    new_digest = write(path, packet)
    for name in ("messages/03-rebuttal.json", "messages/04-review-response.json"):
        write(example / name, {**read(example / name), "packet_digest": new_digest})
    assert errors_mentioning(example, "previous_class is not")


def test_unlisted_bundle_file(example: Path) -> None:
    (example / "bundle-r2/files/extra.txt").write_text("not in the manifest\n")
    assert errors_mentioning(example, "files on disk and manifest paths differ")


def test_projection_rejected_by_rubber_ducky(example: Path) -> None:
    response = example / "messages/04-review-response.json"
    write(response, {**read(response), "prior_point_responses": []})
    assert errors_mentioning(example, "does not replay through rubber_ducky")
