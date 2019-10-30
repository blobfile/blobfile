import urllib
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class Request:
    method: str
    url: str
    params: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    data: Any = None
    encoding: Optional[str] = None


def build_url(base_url, template, **data):
    escaped_data = {}
    for k, v in data.items():
        escaped_data[k] = urllib.parse.quote_plus(v)
    return base_url + template.format(**escaped_data)
