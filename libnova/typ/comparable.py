"""
Comparable type annotation
"""
from abc import ABCMeta, abstractmethod
from typing import Any, TypeVar


class Comparable(metaclass=ABCMeta):
    """
    Type hint for comparable types. Use like:

    ```
    T = TypeVar("T", bound=Comparable)
    ```
    """

    @abstractmethod
    def __lt__(self, other: Any) -> bool:
        ...


CT = TypeVar("CT", bound=Comparable)
