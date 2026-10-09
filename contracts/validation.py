"""JSON Schema validation for frozen protocol objects."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator


SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"


class SchemaRegistry:
    """Load and validate protocol objects against packaged schemas."""

    def __init__(self, schema_dir: Path = SCHEMA_DIR) -> None:
        self._schema_dir = schema_dir
        self._validators: dict[str, Draft202012Validator] = {}

    def _load(self, name: str) -> Draft202012Validator:
        if name not in self._validators:
            path = self._schema_dir / f"{name}.schema.json"
            with path.open("r", encoding="utf-8") as handle:
                schema = json.load(handle)
            Draft202012Validator.check_schema(schema)
            self._validators[name] = Draft202012Validator(schema)
        return self._validators[name]

    def validate(self, name: str, value: Mapping[str, Any]) -> None:
        errors = sorted(
            self._load(name).iter_errors(value),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            prefix = f"{location}: " if location else ""
            raise ValueError(f"invalid {name}: {prefix}{errors[0].message}")


@lru_cache(maxsize=1)
def _default_registry() -> SchemaRegistry:
    return SchemaRegistry()


def validate_contract(name: str, value: Mapping[str, Any]) -> None:
    """Validate one named frozen contract with the packaged schema registry."""
    _default_registry().validate(name, value)
