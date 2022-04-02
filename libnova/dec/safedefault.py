"""
Safe default decorator to prevent the issue where:

```
def x(y: List = []) -> List:
    return y

x().append(10)
assert x()[0] == 10
```
"""

from inspect import Parameter, signature
from typing import Callable, List, Optional


def safedefault(func: Callable) -> Callable:
    """
    Generate a safe default wrapper for a function

    :param callable: The function.
    """
    sig = signature(func)

    def safeparm(parm: Parameter) -> Parameter:
        """
        Creates a safe parameter from a potentially unsafe one.
        """
        return Parameter(
            name=parm.name,
            kind=parm.kind,
            default=None,
            annotation=Optional[parm.annotation],
        )

    safe_parms: List[Parameter] = []
    unsafe_parms = {}
    for parm in sig.parameters.values():
        if parm.default is not Parameter.empty and parm.default is not None:
            safe_parms.append(parm)
        else:
            safe_parms.append(safeparm(parm))
