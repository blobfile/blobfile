from typing import Optional, Type
from types import TracebackType

class FileLock(object):
    def __init__(self, lock_file: str, timeout: int = ...): ...
    def __enter__(self) -> bool: ...
    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]: ...
