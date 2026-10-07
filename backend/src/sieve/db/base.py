"""Declarative base, naming conventions and shared column helpers."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, Column, DateTime, Enum, MetaData, Table, event, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, MappedColumn, mapped_column
from sqlalchemy.sql.elements import conv
from sqlalchemy.sql.schema import SchemaItem

from sieve.core.ids import uuid7

# Deterministic constraint names make migrations reviewable and reversible.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {  # noqa: RUF012 - SQLAlchemy reads this class attribute
        datetime: DateTime(timezone=True),
        dict[str, Any]: JSONB,
        list[dict[str, Any]]: JSONB,
    }


_ENUM_VALUES_KEY = "sieve_enum_values"


def enum_column(enum_cls: type[StrEnum], column_name: str, **kwargs: Any) -> MappedColumn[Any]:
    """Text column constrained to the enum's values by one CHECK constraint named after the
    column (so one table can hold two columns of the same enum, e.g. ``previous_verdict`` and
    ``decided_verdict``).

    The constraint is added at table level when the column is attached (see
    ``_add_enum_check``): Alembic autogenerate renders table-level constraints exactly once, but
    drops column-level ones and duplicates the one ``Enum(create_constraint=True)`` makes.
    """
    values = [member.value for member in enum_cls]
    return mapped_column(
        Enum(
            enum_cls,
            name=column_name,
            native_enum=False,
            create_constraint=False,
            length=max(len(value) for value in values),
            values_callable=lambda members: [member.value for member in members],
            validate_strings=True,
        ),
        info={_ENUM_VALUES_KEY: values},
        **kwargs,
    )


@event.listens_for(Column, "after_parent_attach")
def _add_enum_check(column: Column[Any], table: SchemaItem) -> None:
    values = column.info.get(_ENUM_VALUES_KEY)
    # Only for tables declared on Base. Table.to_metadata() copies (used by Alembic) re-attach
    # columns and also copy existing constraints, so acting there would duplicate them.
    if values is None or not isinstance(table, Table) or table.metadata is not Base.metadata:
        return
    # Declarative may attach copies of the same column more than once; add one constraint.
    name = f"ck_{table.name}_{column.name}"
    if any(constraint.name == name for constraint in table.constraints):
        return
    allowed = ", ".join(f"'{value}'" for value in values)
    # conv(): the name is already final; the naming convention must not be applied again.
    table.append_constraint(CheckConstraint(f"{column.name} IN ({allowed})", name=conv(name)))


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)


class CreatedAt:
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Timestamps(CreatedAt):
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
