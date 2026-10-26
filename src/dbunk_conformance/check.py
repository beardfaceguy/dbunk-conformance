"""Check a dbunk worked example against dbunk PROTOCOL.md and rubber_ducky v1.3.

The example directory holds packet-*.json files, bundle-*/ directories (each a
manifest.json beside a files/ tree) and a messages/ directory whose files sort
into conversation order and name their type: review-request, review-response,
rebuttal or escalation-summary.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from rubber_ducky.core.lifecycle import InvalidTransition, ReviewState, replay_review
from rubber_ducky.core.models import (
    Disposition,
    EscalationSummary,
    NonEmptyText,
    RebuttalBase,
    ReviewRequestBase,
    ReviewResponse,
    Verdict,
)
from pydantic import Field, ValidationError

MESSAGE_TYPES = ("review-request", "review-response", "rebuttal", "escalation-summary")


class PacketReviewRequest(ReviewRequestBase):
    """Projected v1.3 request whose only payload field is the packet digest."""

    packet_digest: NonEmptyText


class PacketRebuttal(RebuttalBase):
    """Projected v1.3 rebuttal whose only payload field is the packet digest."""

    packet_digest: NonEmptyText


class PacketReviewState(ReviewState):
    request: PacketReviewRequest
    rebuttals: tuple[PacketRebuttal, ...] = Field(default_factory=tuple)

    request_model = PacketReviewRequest
    rebuttal_model = PacketRebuttal


@dataclass
class Bundle:
    digest: str
    manifest: dict
    mismatched_paths: set[str]


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    status_tables: list[tuple[str, dict[str, str]]] = field(default_factory=list)
    final_status: str | None = None

    def error(self, message: str) -> None:
        self.errors.append(message)


def file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_bundles(example: Path, report: Report) -> dict[str, Bundle]:
    bundles = {}
    for manifest_path in sorted(example.glob("bundle-*/manifest.json")):
        root = manifest_path.parent
        digest = file_digest(manifest_path)
        manifest = json.loads(manifest_path.read_bytes())
        files_root = root / "files"
        listed = [entry["path"] for entry in manifest["files"]]
        if len(listed) != len(set(listed)):
            report.error(f"{root.name}: manifest lists a path twice")
        on_disk = set()
        for path in files_root.rglob("*"):
            if path.is_symlink():
                report.error(f"{root.name}: {path.relative_to(files_root)} is a symbolic link")
            elif path.is_file():
                on_disk.add(path.relative_to(files_root).as_posix())
        if on_disk != set(listed):
            report.error(
                f"{root.name}: files on disk and manifest paths differ: "
                f"unlisted {sorted(on_disk - set(listed))}, missing {sorted(set(listed) - on_disk)}"
            )
        mismatched = set()
        for entry in manifest["files"]:
            path = files_root / entry["path"]
            if not path.is_file() or path.is_symlink() or file_digest(path) != entry["sha256"]:
                mismatched.add(entry["path"])
        if mismatched:
            report.notes.append(f"{root.name}: evidence that fails its digest or is missing: {sorted(mismatched)}")
        bundles[digest] = Bundle(digest, manifest, mismatched)
    return bundles


def has_cycle(qualifies: dict[str, list[str]]) -> bool:
    visiting, done = set(), set()

    def visit(node: str) -> bool:
        if node in done:
            return False
        if node in visiting:
            return True
        visiting.add(node)
        if any(visit(target) for target in qualifies.get(node, [])):
            return True
        visiting.remove(node)
        done.add(node)
        return False

    return any(visit(node) for node in qualifies)


def check_packet(name: str, packet: dict, bundles: dict[str, Bundle], report: Report) -> None:
    claim_ids = [claim["id"] for claim in packet["claims"]]
    if len(claim_ids) != len(set(claim_ids)):
        report.error(f"{name}: claim IDs are not unique")
    present = set(claim_ids)
    qualifies = {}
    for claim in packet["claims"]:
        if "qualifies" in claim:
            if claim["id"] in claim["qualifies"]:
                report.error(f"{name}: qualification {claim['id']} qualifies itself")
            missing = set(claim["qualifies"]) - present
            if missing:
                report.error(f"{name}: qualification {claim['id']} names absent claims {sorted(missing)}")
            qualifies[claim["id"]] = claim["qualifies"]
    if has_cycle(qualifies):
        report.error(f"{name}: qualification lists form a cycle")
    bundle = bundles.get(packet["bundle_digest"])
    if bundle is None:
        report.error(f"{name}: no bundle has digest {packet['bundle_digest']}")
        return
    bundle_paths = {entry["path"] for entry in bundle.manifest["files"]}
    repositories = {repository["url"] for repository in packet["repositories"]}
    for claim in packet["claims"]:
        for reference in claim.get("evidence", []):
            if "bundle_path" in reference and reference["bundle_path"] not in bundle_paths:
                report.error(f"{name}: claim {claim['id']} cites {reference['bundle_path']}, not in its bundle")
            if "repository" in reference and reference["repository"] not in repositories:
                report.error(f"{name}: claim {claim['id']} cites unlisted repository {reference['repository']}")


def check_reclassification(name: str, previous: dict | None, packet: dict, report: Report) -> None:
    previous_classes = {claim["id"]: claim["class"] for claim in previous["claims"]} if previous else {}
    for claim in packet["claims"]:
        before = previous_classes.get(claim["id"])
        reclassified = before is not None and before != claim["class"]
        if reclassified and claim.get("previous_class") != before:
            report.error(f"{name}: claim {claim['id']} was reclassified but previous_class is not {before!r}")
        if not reclassified and "previous_class" in claim:
            report.error(f"{name}: claim {claim['id']} carries previous_class but was not reclassified")


def fingerprint(claim: dict, packet: dict, bundles: dict[str, Bundle]) -> str:
    """Everything a verification record depends on, per PROTOCOL.md 7.3."""

    manifest_digests = {
        entry["path"]: entry["sha256"] for entry in bundles[packet["bundle_digest"]].manifest["files"]
    }
    commits = {repository["url"]: repository["commit"] for repository in packet["repositories"]}
    evidence = []
    for reference in claim.get("evidence", []):
        if "bundle_path" in reference:
            evidence.append([reference, manifest_digests.get(reference["bundle_path"])])
        else:
            evidence.append([reference, commits.get(reference["repository"])])
    return json.dumps(
        [claim["text"], claim["class"], evidence, claim.get("qualifies")], sort_keys=True
    )


def project(kind: str, message: dict):
    if kind == "review-request":
        return PacketReviewRequest.model_validate(
            {key: value for key, value in message.items() if key != "bundle_digest"}
        )
    if kind == "review-response":
        projected = {
            key: value for key, value in message.items() if key not in ("packet_digest", "verification_records")
        }
        for key in ("blocking_concerns", "suggestions"):
            projected[key] = [
                {k: v for k, v in concern.items() if k != "claim_ids"} for concern in message.get(key, [])
            ]
        return ReviewResponse.model_validate(projected)
    if kind == "rebuttal":
        return PacketRebuttal.model_validate(message)
    return EscalationSummary.model_validate(message)


def message_kind(path: Path) -> str:
    for kind in MESSAGE_TYPES:
        if kind in path.name:
            return kind
    raise ValueError(f"{path.name} does not name a message type")


def check_example(example: Path) -> Report:
    report = Report()
    bundles = load_bundles(example, report)
    packets = {}
    for path in sorted(example.glob("packet-*.json")):
        packet = json.loads(path.read_bytes())
        packets[file_digest(path)] = (path.name, packet)
        check_packet(path.name, packet, bundles, report)

    message_paths = sorted((example / "messages").glob("*.json"))
    messages = [(message_kind(path), json.loads(path.read_bytes()), path.name) for path in message_paths]
    if not messages or messages[0][0] != "review-request":
        report.error("the first message must be a review request")
        return report

    try:
        projected = [project(kind, message) for kind, message, _ in messages]
        state = replay_review(projected[0], projected[1:], state_cls=PacketReviewState)
        report.final_status = state.status.value
    except (ValidationError, InvalidTransition) as error:
        report.error(f"projection does not replay through rubber_ducky v1.3: {error}")

    current_digest = None
    previous_packet = None
    open_concerns: dict[str, list[str]] = {}
    records: dict[str, str] = {}
    for kind, message, name in messages:
        if kind in ("review-request", "rebuttal"):
            digest = message["packet_digest"]
            if kind == "rebuttal":
                accepts = any(
                    response["disposition"] == Disposition.ACCEPT.value
                    for response in message["blocking_responses"]
                )
                if accepts and digest == current_digest:
                    report.error(f"{name}: ACCEPTs a concern but does not change the packet digest")
            if digest not in packets:
                report.error(f"{name}: no packet has digest {digest}")
                return report
            packet_name, packet = packets[digest]
            if kind == "review-request" and message["bundle_digest"] != packet["bundle_digest"]:
                report.error(f"{name}: bundle_digest differs from the packet's")
            if digest != current_digest:
                check_reclassification(packet_name, previous_packet, packet, report)
                previous_packet = packet
            current_digest = digest
            continue
        if kind != "review-response":
            continue

        if message["packet_digest"] != current_digest:
            report.error(f"{name}: reviews {message['packet_digest']}, not the current revision")
        packet_name, packet = packets[current_digest]
        claims = {claim["id"]: claim for claim in packet["claims"]}

        for concern_id in message.get("resolved_concern_ids", []):
            open_concerns.pop(concern_id, None)
        for concern in [*message.get("blocking_concerns", []), *message.get("suggestions", [])]:
            absent = set(concern["claim_ids"]) - set(claims)
            if absent:
                report.error(f"{name}: {concern['id']} names claims absent from {packet_name}: {sorted(absent)}")
        for concern in message.get("blocking_concerns", []):
            open_concerns[concern["id"]] = concern["claim_ids"]

        current = {claim_id: fingerprint(claim, packet, bundles) for claim_id, claim in claims.items()}
        carried = {claim_id for claim_id, value in records.items() if current.get(claim_id) == value}
        absent = set(message["verification_records"]) - set(claims)
        if absent:
            report.error(f"{name}: verification records name absent claims {sorted(absent)}")
        # A carried qualification keeps its record only while every claim it qualifies
        # also carries its record. A qualified claim that was re-recorded has changed,
        # so the qualification must be checked again.
        changed = True
        while changed:
            changed = False
            for claim_id in sorted(carried):
                claim = claims.get(claim_id)
                if claim and not set(claim.get("qualifies", [])) <= carried:
                    carried.discard(claim_id)
                    changed = True
        recorded = carried | set(message["verification_records"])
        records = {claim_id: current[claim_id] for claim_id in recorded if claim_id in current}

        blocked = {claim_id for claim_ids in open_concerns.values() for claim_id in claim_ids}
        bad_paths = bundles[packet["bundle_digest"]].mismatched_paths
        for claim_id, claim in claims.items():
            cites_bad = any(reference.get("bundle_path") in bad_paths for reference in claim.get("evidence", []))
            if cites_bad and claim_id in records:
                report.error(f"{name}: {claim_id} has a verification record but cites evidence that fails its digest")
            if cites_bad and claim_id not in blocked:
                report.error(f"{name}: {claim_id} cites evidence that fails its digest but no open blocking concern names it")
        unaccounted = set(claims) - set(records) - blocked
        if unaccounted:
            report.error(f"{name}: unaccounted claims {sorted(unaccounted)}")
        if message["verdict"] == Verdict.APPROVE.value and (set(claims) - set(records) or open_concerns):
            report.error(f"{name}: APPROVE while a claim lacks a record or a blocking concern is open")

        status = {}
        for claim_id in claims:
            if claim_id in blocked:
                status[claim_id] = "blocked by " + ", ".join(
                    concern_id for concern_id, ids in open_concerns.items() if claim_id in ids
                )
            elif claim_id in records:
                status[claim_id] = "verified"
            else:
                status[claim_id] = "unaccounted"
        report.status_tables.append((name, status))
    return report


def run() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("example", type=Path, help="path to a dbunk example directory")
    parser.add_argument("--labels", type=Path, help="optional JSON file mapping short labels to claim IDs")
    arguments = parser.parse_args()
    report = check_example(arguments.example)
    names = {}
    if arguments.labels:
        names = {claim_id: label for label, claim_id in json.loads(arguments.labels.read_text()).items()}
    for note in report.notes:
        print(f"note: {note}")
    for name, status in report.status_tables:
        print(f"\nafter {name}:")
        for claim_id, value in status.items():
            print(f"  {names.get(claim_id, claim_id)}: {value}")
    print(f"\nfinal rubber_ducky status: {report.final_status}")
    for error in report.errors:
        print(f"error: {error}")
    if report.errors:
        sys.exit(1)
    print("conforms")


if __name__ == "__main__":
    run()
