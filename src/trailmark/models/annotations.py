"""Annotations, entrypoint tags, and asset values for the code graph."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AnnotationKind(Enum):
    """Categories of semantic annotations on code units."""

    ASSUMPTION = "assumption"
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    INVARIANT = "invariant"
    BLAST_RADIUS = "blast_radius"
    PRIVILEGE_BOUNDARY = "privilege_boundary"
    TAINT_PROPAGATION = "taint_propagation"
    FINDING = "finding"
    AUDIT_NOTE = "audit_note"


@dataclass(frozen=True)
class Annotation:
    """A semantic annotation attached to a code unit."""

    kind: AnnotationKind
    description: str
    source: str


class AssetValue(Enum):
    """Relative value of data flowing through a code unit."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TrustLevel(Enum):
    """Trust level of data flowing through an entrypoint."""

    UNTRUSTED_EXTERNAL = "untrusted_external"
    SEMI_TRUSTED_EXTERNAL = "semi_trusted_external"
    TRUSTED_INTERNAL = "trusted_internal"


class EntrypointKind(Enum):
    """How external data enters the system."""

    USER_INPUT = "user_input"
    API = "api"
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    THIRD_PARTY = "third_party"


@dataclass(frozen=True)
class EntrypointTag:
    """Tags a code unit as an entrypoint for external data."""

    kind: EntrypointKind
    trust_level: TrustLevel = TrustLevel.UNTRUSTED_EXTERNAL
    description: str | None = None
    asset_value: AssetValue = AssetValue.LOW


@dataclass(frozen=True)
class TypeConstraint:
    """A constraint on a parameter's type or value domain."""

    parameter_name: str
    declared_type: str | None = None
    value_constraint: str | None = None


@dataclass(frozen=True)
class DeclaredContract:
    """What a function declares it accepts/returns.

    Captured from type annotations, docstrings, assertions,
    and explicit validation. Separate from effective input domain,
    which is determined by graph reachability analysis.
    """

    parameter_types: tuple[TypeConstraint, ...] = ()
    return_constraint: str | None = None
    validation_notes: tuple[str, ...] = ()
