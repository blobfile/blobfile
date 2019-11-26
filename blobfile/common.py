import urllib

from typing import Mapping, Optional, Any


class Request:
    def __init__(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        data: Any = None,
        encoding: Optional[str] = None,
    ):
        self.url = url
        self.method = method
        self.params = params
        self.headers = headers
        self.data = data
        self.encoding = encoding


def build_url(base_url: str, template: str, **data: str) -> str:
    escaped_data = {}
    for k, v in data.items():
        escaped_data[k] = urllib.parse.quote_plus(v)
    return base_url + template.format(**escaped_data)
