"""
A "replayable" is basically just a function and the args it was
called with so we can play back a sequence of calls, which is useful
for some things like bringing a pwn remote up to the same place as a local
one.
"""

from dataclasses import dataclass
from typing import Any, Callable, Tuple


@dataclass
class MethodReplayable:
    """
    Replayable method call with arguments
    """

    func: str
    args: Tuple[Any]

    def replay(self, obj: Any) -> Any:
        """
        Replay the method call
        """
        return getattr(obj, self.func)(*self.args)
