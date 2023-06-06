import concurrent.futures

from typing import (
    TYPE_CHECKING,
    Optional,
)

from blobfile import Stat
if TYPE_CHECKING:
    from typing import Literal


class CacheConfig():
    """
    Cache settings for the blob file.
    Args:
        mode: one of "rt", "rc", "wt", "wc", indicating the caching semantics.
            * `mode=rt` (read-through):
                * The default for cache read.
                * Reads the file from cache. When there is a cache miss, fetch the file from source, cache it, then return the cached copy.
                    Creates a file-does-not-exist entry in the cache if it does not exist at the source.
                    It will maintain one copy of the item in the cache if there are concurrent readers with a cache miss.
                    The write follows the semantics of "write-cache"
            * `mode=rc` (read-cache):
                * Reads from the cache, and falls back to the source if a cached copy does not exist.
            * `mode=wt` (write-through):
                * Writes to the cache and to the source. The write fails only if it fails to write to the source.
                * The cache entry becomes available when the write to the source completes.
                * When concurrent writers are present, the last writer wins.
            * `mode=wc`: (write-cache)
                * Writes to the cache only.
                * The cache entry becomes available when the write completes.
                * When concurrent writers are present, the last writer wins.            
        name: the cache instance to refer to. This allows multiple clients to refer to the same instance.
        ignore_ttl: Ignores the ttl of the cache entry for read. Only set this for read. Defaults to false.
        entry_ttl_s: The ttl in seconds for the cache entry if there is a write to the cache.
            * Read-through may create a cache entry if there is a cache miss.
            * The entry is ignored and deleted from the cache when it expires.
            * The ttl applies to the cache entry where the data exists or is not present in the source.
    """
    def __init__(self, mode: Literal["rt", "rc", "wt", "wc"], name: str, ignore_ttl: bool, entry_ssl_s: int) -> None:
        self.mode = mode
        self.name = name
        self.ignore_ttl = ignore_ttl
        self.entry_ssl_s = entry_ssl_s

def get_or_create_cache(name: str, scope: Literal["job", "cluster"], owner: str, entry_retention_s: int) -> None:
    """
    Returns a handle to the cache. Instantiates and returns it otherwise.
    TODO(clarence): figure if cache creation should be done inside Blobfile?

    Scope:
    The cache may be scoped to a job or the cluster it belongs to. When a cache is scoped
    to a job, the data is deleted when the job completes. When the cache is scoped to
    the cluster, the data is deleted following the retention policy, and will be purged
    after a certain period.

    Eviction policy:
    The cache supports first-in-first-out, and will clear out the older entries to make
    room for new ones when the cache runs out of space.

    Access control:
    By default the cache is "private", and may be accessed by jobs instantiated by the
    the creator of the cache.

    Args:
        name: The globally unique identifier to the cache instance
        scope: the scope of the cache, which affects the lifecycle of the cache and its data
        owner: the owner of the cache. The owner must match if the cache already exists
        entry_retention_s: must be set if the scope of the cache is "cluster". Entries created past
            the retention period will be delete
    """
    pass

def canonical_path(name: str, relative_path: str) -> str:
    """
    Returns the canonical path name.

    Args:
        name: the name of the cache
        relative_path: the path relative to the cache it is referring to.
    """
    return f"c://{name}/{relative_path}"

def exists(path: str) -> bool:
    """
    Returns true if the path exists in the cache.

    Args:
        path: local or remote path
    """
    return True

def stat(path: str) -> Stat:
    """
    Returns the stats of the file or raises FileNotFoundError

    Args:
        path: local or remote path
    """
    return Stat(
        size=0,
        mtime=0,
        ctime=0,
        md5="",
        version="",
    )

def parallel_upload(config: CacheConfig, executor: concurrent.futures.Executor, src: str, dst: str, return_md5: bool) -> Optional[str]:
    """
    Uploads to cache from local src file.
    """
    pass

def parallel_download(config: CacheConfig, src: str, dst: str, return_md5: bool) -> Optional[str]:
    """
    Downloads from cache to local dst file.
    """
    pass

def remote_copy(config: CacheConfig, src: str, dst: str, return_md5: bool) -> Optional[str]:
    """
    Performs a remote copy between two cache paths.
    """
    pass
