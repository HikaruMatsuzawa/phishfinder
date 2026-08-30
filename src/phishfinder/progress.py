from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator
from typing import TypeVar

T = TypeVar("T")


def progress_bar(
    items: Iterable[T],
    *,
    desc: str,
    unit: str = "\u4ef6",
    enabled: bool = True,
) -> Iterable[T]:
    if not enabled:
        return items

    try:
        from tqdm import tqdm
    except ImportError:
        return items

    return tqdm(items, desc=desc, unit=unit, file=sys.stdout, dynamic_ncols=True)


def consume(items: Iterable[T]) -> Iterator[T]:
    yield from items
