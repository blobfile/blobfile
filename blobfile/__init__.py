import os

from blobfile.ops import (
    copy,
    exists,
    glob,
    scanglob,
    isdir,
    listdir,
    scandir,
    makedirs,
    remove,
    rmdir,
    rmtree,
    stat,
    walk,
    basename,
    dirname,
    join,
    get_url,
    md5,
    set_mtime,
    configure,
    BlobFile,
)
from blobfile.common import (
    Request,
    Error,
    RequestFailure,
    RestartableStreamingWriteFailure,
    ConcurrentWriteFailure,
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(SCRIPT_DIR, "VERSION")) as version_file:
    __version__ = version_file.read().strip()

__all__ = [
    "copy",
    "exists",
    "glob",
    "scanglob",
    "isdir",
    "listdir",
    "scandir",
    "makedirs",
    "remove",
    "rmdir",
    "rmtree",
    "stat",
    "walk",
    "basename",
    "dirname",
    "join",
    "get_url",
    "md5",
    "set_mtime",
    "configure",
    "BlobFile",
    "Request",
    "Error",
    "RequestFailure",
    "RestartableStreamingWriteFailure",
    "ConcurrentWriteFailure",
]
