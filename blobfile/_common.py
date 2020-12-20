import json
import urllib
from typing import Mapping, Optional, Any, Sequence, Tuple

import urllib3
import xmltodict


class Request:
    """
    A struct representing an HTTP request
    """

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
        self.method: str = method
        self.url: str = url
        self.params: Optional[Mapping[str, str]] = params
        self.headers: Optional[Mapping[str, str]] = headers
        self.data: Any = data
        self.preload_content: bool = preload_content
        self.success_codes: Sequence[int] = success_codes
        self.retry_codes: Sequence[int] = retry_codes

    def __repr__(self) -> str:
        return f"<Request method={self.method} url={self.url} params={self.params}>"


class FileBody:
    """
    A struct for referencing a section of a file on disk to be used as the `data` property
    on a Request
    """

    def __init__(self, path: str, start: int, end: int) -> None:
        self.path: str = path
        self.start: int = start
        self.end: int = end

    def __repr__(self):
        return f"<FileBody path={self.path} start={self.start} end={self.end}>"


def build_url(base_url: str, template: str, **data: str) -> str:
    escaped_data = {}
    for k, v in data.items():
        escaped_data[k] = urllib.parse.quote(v, safe="")
    return base_url + template.format(**escaped_data)


class Error(Exception):
    """Base class for blobfile exceptions."""

    def __init__(self, message: str, *args: Any):
        self.message: str = message
        super().__init__(message, *args)


def _extract_error(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    if data.startswith(b"\xef\xbb\xbf<?xml"):
        try:
            result = xmltodict.parse(data)
            return result["Error"]["Code"], result["Error"].get("Message")
        except Exception:
            pass
    elif data.startswith(b"{"):
        try:
            result = json.loads(data)
            return str(result["error"]), result.get("error_description")
        except Exception:
            pass
    return None, None


class RequestFailure(Error):
    """
    A request failed, possibly after some number of retries
    """

    def __init__(
        self,
        message: str,
        request_string: str,
        response_status: int,
        error: Optional[str],
        error_description: Optional[str],
    ):
        self.request_string: str = request_string
        self.response_status: int = response_status
        self.error: Optional[str] = error
        self.error_description: Optional[str] = error_description
        super().__init__(
            message,
            self.request_string,
            self.response_status,
            self.error,
            self.error_description,
        )

    def __str__(self) -> str:
        return f"message={self.message}, request={self.request_string}, status={self.response_status}, error={self.error} error_description={self.error_description}"

    @classmethod
    def create_from_request_response(
        cls, message: str, request: Request, response: urllib3.HTTPResponse
    ) -> Any:
        # this helper function exists because if you make a custom Exception subclass it cannot
        # be unpickled easily: https://stackoverflow.com/questions/41808912/cannot-unpickle-exception-subclass

        err = None
        err_desc = None
        if response.data is not None:
            err, err_desc = _extract_error(response.data)
        # use string representation since request may not be serializable
        # exceptions need to be serializable when raised from subprocesses
        return cls(
            message=message,
            request_string=str(request),
            response_status=response.status,
            error=err,
            error_description=err_desc,
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
