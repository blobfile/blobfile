import concurrent.futures
from typing import Mapping, Any, Optional, Tuple

import urllib3

from blobfile._common import (
    Request,
    Stat,
    Context,
    BaseStreamingReadFile,
    BaseStreamingWriteFile,
)

MAX_EXPIRATION = 7 * 24 * 60 * 60


def makedirs(ctx: Context, path: str) -> None:
    """
    Make any directories necessary to ensure that path is a directory
    """
    raise NotImplementedError()


def build_url(template: str, **data: str) -> str:
    raise NotImplementedError()


def create_api_request(req: Request, access_token: str) -> Request:
    raise NotImplementedError()


def generate_signed_url(
    bucket: str,
    name: str,
    expiration: float,
    method: str = "GET",
    params: Optional[Mapping[str, str]] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> Tuple[str, Optional[float]]:
    raise NotImplementedError()


def split_path(path: str) -> Tuple[str, str]:
    raise NotImplementedError()


def combine_path(bucket: str, obj: str) -> str:
    raise NotImplementedError()


def get_md5(metadata: Mapping[str, Any]) -> Optional[str]:
    raise NotImplementedError()


def make_stat(item: Mapping[str, Any]) -> Stat:
    raise NotImplementedError()


def execute_api_request(ctx: Context, req: Request) -> urllib3.HTTPResponse:
    raise NotImplementedError()


class StreamingReadFile(BaseStreamingReadFile):
    def __init__(self, ctx: Context, path: str) -> None:
        st = maybe_stat(ctx, path)
        if st is None:
            raise FileNotFoundError(f"No such file or bucket: '{path}'")
        super().__init__(ctx=ctx, path=path, size=st.size)

    def _request_chunk(
        self, streaming: bool, start: int, end: Optional[int] = None
    ) -> urllib3.response.HTTPResponse:
        raise NotImplementedError()


class StreamingWriteFile(BaseStreamingWriteFile):
    def __init__(self, ctx: Context, path: str) -> None:
        raise NotImplementedError()

    def _upload_chunk(self, chunk: bytes, finalize: bool) -> None:
        raise NotImplementedError()


def maybe_stat(ctx: Context, path: str) -> Optional[Stat]:
    raise NotImplementedError()


def remove(ctx: Context, path: str) -> bool:
    raise NotImplementedError()


def maybe_update_md5(ctx: Context, path: str, generation: str, hexdigest: str) -> bool:
    raise NotImplementedError()


def parallel_upload(
    ctx: Context,
    executor: concurrent.futures.Executor,
    src: str,
    dst: str,
    return_md5: bool,
) -> Optional[str]:
    raise NotImplementedError()
