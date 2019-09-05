class Request:
    def __init__(self, method, url, headers=None, data=None):
        self.method = method
        self.url = url
        self.headers = headers
        self.data = data

    def __repr__(self):
        return f"<Request method={self.method} url={self.url} headers={self.headers}>"
