"""
RangeMap implementation for fast lookups of ranges of values.
"""

from bisect import bisect_left
from collections.abc import MutableMapping
from typing import Any, Generator, Generic, List, Optional, Tuple, TypeVar, Union

from libnova.typ import Comparable


class RangeMapNotFound:
    """
    A sentinel value indicating that no value was found.
    """

    ...


T = TypeVar("T", bound=Comparable)  # Key (ordering) type
V = TypeVar("V")  # Value type


class RangeMap(MutableMapping, Generic[T, V]):
    """Map ranges to values

    Lookups are done in O(logN) time. There are no limits set on the upper or
    lower bounds of the ranges, but ranges must not overlap.

    """

    def __init__(self, _map: Optional[MutableMapping] = None):
        """
        Initialize the rangemap, optionally with an existing mapping.

        :param _map: Optional mapping to initialize the rangemap with.
        """

        self._upper: List[T] = []
        self._lower: List[T] = []
        self._values: List[V] = []
        if _map is not None:
            self.update(_map)

    def __len__(self) -> int:
        """
        Return the number of values stored in the mapping.
        """
        return len(self._values)

    def __getitem__(self, point_or_range: Union[Tuple[T, T], T]) -> V:
        """
        Retrieve a value by a single point or a specific range.

        :param point_or_range: The value or value range to look up.
        """
        if isinstance(point_or_range, tuple):
            low, high = point_or_range
            i = bisect_left(self._upper, high)
            point = low
        else:
            point = point_or_range
            i = bisect_left(self._upper, point)
        if i >= len(self._values) or self._lower[i] > point:
            raise KeyError
        return self._values[i]

    def __setitem__(self, r: Tuple[T, T], value: Any) -> None:
        """
        Set a value by a single point or a specific range.

        :param r: The range for this value.
        :param value: The value.
        """
        lower, upper = r
        i = bisect_left(self._upper, upper)
        if i < len(self._values) and self._lower[i] < upper:
            raise IndexError(f"No overlaps permitted: {lower}-{upper}")
        self._upper.insert(i, upper)
        self._lower.insert(i, lower)
        self._values.insert(i, value)

    def __delitem__(self, r: Tuple[T, T]) -> None:
        """
        Delete a range and its value from the mapping.
        """
        lower, upper = r
        i = bisect_left(self._upper, upper)
        if self._upper[i] != upper or self._lower[i] != lower:
            raise IndexError(f"Range not in map: {lower}-{upper}")
        del self._upper[i]
        del self._lower[i]
        del self._values[i]

    def __iter__(self) -> Generator[Tuple[T, T], None, None]:
        """
        Create an iterator over this rangemap.
        """
        yield from zip(self._lower, self._upper)

    def __contains__(self, point_or_range: Union[Tuple[T, T], T]) -> bool:  # type: ignore
        """
        Check if a point or range is in the mapping.

        :param point_or_range: The point or range to check.
        """
        if isinstance(point_or_range, tuple):
            low, high = point_or_range
            i = bisect_left(self._upper, high)
            point = low
        else:
            point = point_or_range
            i = bisect_left(self._upper, point)
        if i >= len(self._values) or self._lower[i] > point:
            return False

        return True
