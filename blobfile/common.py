import urllib
import json


class Request:
    def __init__(self, method, url, headers=None, data=None):
        self.method = method
        self.url = url
        self.headers = headers
        self.data = data

    def __repr__(self):
        return f"<Request method={self.method} url={self.url} headers={self.headers}>"


def create_oauth_request(access_token, url, method, params=None, data=None):
    headers = {"Authorization": f"Bearer {access_token}"}
    if params is not None:
        if len(params) > 0:
            url += "?" + urllib.parse.urlencode(params)
    if data is not None:
        data = json.dumps(data).encode("utf8")
    return Request(url=url, method=method, headers=headers, data=data)


def build_url(base_url, template, **data):
    escaped_data = {}
    for k, v in data.items():
        escaped_data[k] = urllib.parse.quote_plus(v)
    return base_url + template.format(**escaped_data)
