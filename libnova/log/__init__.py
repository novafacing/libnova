"""
Log module exports for libnova
"""

from logging import getLogger
from typing import Any, Dict, List

import libnova.log.log


def l(*args: List[Any], **kwargs: Dict[str, Any]) -> None:
    """
    Logging wrapper for libnova.
    """
    lg = getLogger(__file__)
    lg.log(*args, **kwargs)  # type: ignore
