import urllib


class Request:
    def __init__(
        self, method, url, params=None, headers=None, data=None, encoding=None
    ):
        self.url = url
        self.method = method
        self.params = params
        self.headers = headers
        self.data = data
        self.encoding = encoding


def build_url(base_url, template, **data):
    escaped_data = {}
    for k, v in data.items():
        escaped_data[k] = urllib.parse.quote_plus(v)
    return base_url + template.format(**escaped_data)
