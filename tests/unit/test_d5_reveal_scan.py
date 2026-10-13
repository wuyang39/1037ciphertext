from __future__ import annotations

from pathlib import Path

from infra.reveal_scan import MUST_BE_CLEAN, scan


ROOT = Path(__file__).resolve().parents[2]


def test_production_path_reveals_nothing() -> None:
    report = scan(ROOT)
    assert report["missing_modules"] == []
    assert report["findings"] == []
    assert report["verdict"] == "clean"


def test_every_must_be_clean_module_exists() -> None:
    for relative in MUST_BE_CLEAN:
        assert (ROOT / relative).is_file(), relative


def test_allowlist_records_a_reason_for_each_entry() -> None:
    report = scan(ROOT)
    for record in report["allowlisted"]:
        assert record["reason"]
