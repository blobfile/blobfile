import json
import urllib
from typing import Mapping, Optional, Any, Sequence

import urllib3
import xmltodict


class Request:
    def __init__(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        data: Any = None,
        preload_content: bool = True,
        success_codes: Sequence[int] = (200,),
        # https://cloud.google.com/storage/docs/resumable-uploads#practices
        retry_codes: Sequence[int] = (408, 429, 500, 502, 503, 504),
    ) -> None:
        self.url = url
        self.method = method
        self.params = params
        self.headers = headers
        self.data = data
        self.preload_content = preload_content
        self.success_codes = success_codes
        self.retry_codes = retry_codes

    def __repr__(self):
        return f"<Request method={self.method} url={self.url} params={self.params}>"


def build_url(base_url: str, template: str, **data: str) -> str:
    escaped_data = {}
    for k, v in data.items():
        escaped_data[k] = urllib.parse.quote(v, safe="")
    return base_url + template.format(**escaped_data)


class Error(Exception):
    """Base class for blobfile exceptions."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def _extract_error_description(data: bytes) -> Optional[str]:
    if data.startswith(b"\xef\xbb\xbf<?xml"):
        try:
            result = xmltodict.parse(data)
            return result["Error"]["Code"]
        except Exception:
            pass
    elif data.startswith(b"{"):
        try:
            result = json.loads(data)
            return str(result["error"])
        except Exception:
            pass
    return None


class RequestFailure(Error):
    """
    A request failed, possibly after some number of retries
    """

    def __init__(self, message: str, request: Request, response: urllib3.HTTPResponse):
        self.message = message
        self.request = request
        self.response = response
        if self.response.data is not None:
            err_desc = _extract_error_description(self.response.data)
        else:
            err_desc = None
        super().__init__(
            f"message={self.message}, request={self.request}, status={self.response.status}, error_description={err_desc}"
        )


class RestartableStreamingWriteFailure(RequestFailure):
    """
    A streaming write failed in a permanent way that requires restarting from the beginning of the stream
    """

    pass


class ConcurrentWriteFailure(RequestFailure):
    """
    A write failed due to another concurrent writer
    """

    pass
