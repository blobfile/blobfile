import urllib
import urllib3

from typing import Mapping, Optional, Any, Sequence


class Request:
    def __init__(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        data: Any = None,
        success_codes: Sequence[int] = (200,),
        # https://cloud.google.com/storage/docs/resumable-uploads#practices
        retry_codes: Sequence[int] = (408, 429, 500, 502, 503, 504),
    ) -> None:
        self.url = url
        self.method = method
        self.params = params
        self.headers = headers
        self.data = data
        self.success_codes = success_codes
        self.retry_codes = retry_codes

    def __repr__(self):
        return f"<Request method={self.method} url={self.url}>"


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


class RequestFailure(Error):
    """
    A request failed, possibly after some number of retries
    """

    def __init__(self, message: str, request: Request, response: urllib3.HTTPResponse):
        self.message = message
        self.request = request
        self.response = response
        super().__init__(
            f"message={self.message}, request={self.request}, response={self.response}"
        )
