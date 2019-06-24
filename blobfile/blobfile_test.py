import random
import string
import tempfile
import os
import contextlib
import json
import urllib.request
import threading
import http.server

import pytest
from tensorflow.io import gfile  # pylint: disable=import-error
import imageio
import numpy as np

from . import blobfile as bf


@contextlib.contextmanager
def _get_temp_local_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "file.name")
        yield path


@contextlib.contextmanager
def _get_temp_gcs_path():
    path = (
        "gs://csh-test-2/"
        + "".join(random.choice(string.ascii_lowercase) for i in range(16))
        + "/file.name"
    )
    yield path
    gfile.remove(path)


@contextlib.contextmanager
def _get_temp_http_path():
    with tempfile.TemporaryDirectory() as tmpdir:

        class HTTPHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.range = None
                super().__init__(*args, directory=tmpdir, **kwargs)

            # from https://gist.github.com/wassname/d7582bbcbd91189f80d8624ba46542c0
            def send_head(self):
                path = self.translate_path(self.path)
                ctype = self.guess_type(path)

                # Handling file location
                # If directory, let SimpleHTTPRequestHandler handle the request
                if os.path.isdir(path):
                    return http.server.SimpleHTTPRequestHandler.send_head(self)

                # Handle file not found
                if not os.path.exists(path):
                    return self.send_error(404, self.responses.get(404)[0])

                # Handle file request
                f = open(path, "rb")
                fs = os.fstat(f.fileno())
                size = fs[6]

                # Parse range header
                # Range headers look like 'bytes=500-1000'
                start, end = 0, size - 1
                if "Range" in self.headers:
                    start, end = (
                        self.headers.get("Range").strip().strip("bytes=").split("-")
                    )
                if start == "":
                    # If no start, then the request is for last N bytes
                    # e.g. bytes=-500
                    try:
                        end = int(end)
                    except ValueError:
                        self.send_error(400, "invalid range")
                    start = size - end
                else:
                    try:
                        start = int(start)
                    except ValueError:
                        self.send_error(400, "invalid range")
                    if start > size:
                        # If requested start is greater than filesize
                        self.send_error(416, self.responses.get(416)[0])
                    if end == "":
                        # If only start is provided then serve till end
                        end = size - 1
                    else:
                        try:
                            end = int(end)
                        except ValueError:
                            self.send_error(400, "invalid range")

                # Correct the values of start and end
                start = max(start, 0)
                end = min(end, size - 1)
                self.range = (start, end)
                # Setup headers and response
                content_length = end - start + 1
                if "Range" in self.headers:
                    self.send_response(206)
                else:
                    self.send_response(200)
                self.send_header("Content-type", ctype)
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Range", "bytes %s-%s/%s" % (start, end, size))
                self.send_header("Content-Length", str(content_length))
                self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
                self.end_headers()
                return f

            def copyfile(self, source, outputfile):
                if "Range" not in self.headers:
                    http.server.SimpleHTTPRequestHandler.copyfile(
                        self, source, outputfile
                    )
                    return

                start, end = self.range
                source.seek(start)
                bufsize = 64 * 1024  # 64KB
                remainder = (end - start) % bufsize
                times = int((end - start) / bufsize)
                steps = [bufsize] * times + [remainder]
                for _ in steps:
                    buf = source.read(bufsize)
                    outputfile.write(buf)

            def do_POST(self):
                filepath = os.path.join(tmpdir, self.path[1:])
                if self.headers["Transfer-Encoding"] == "chunked":
                    contents = b""
                    while True:
                        length = int(self.rfile.readline(), 16)
                        if length == 0:
                            break
                        contents += self.rfile.read(length)
                        self.rfile.read(2)  # CRLF
                else:
                    contents = self.rfile.read(int(self.headers["Content-Length"]))
                with open(filepath, "wb") as f:
                    f.write(contents)
                self.send_response(200)
                self.end_headers()

        with http.server.HTTPServer(("localhost", 0), HTTPHandler) as httpd:
            t = threading.Thread(target=httpd.serve_forever)
            t.daemon = True
            t.start()
            yield f"http://localhost:{httpd.server_port}/file.name"
            httpd.shutdown()


def _write_contents(path, contents):
    if path.startswith("http://"):
        req = urllib.request.Request(url=path, data=contents, method="POST")
        resp = urllib.request.urlopen(req)
        assert resp.getcode() == 200
    else:
        with gfile.GFile(path, "wb") as f:
            f.write(contents)


def _read_contents(path):
    if path.startswith("http://"):
        req = urllib.request.Request(url=path, method="GET")
        resp = urllib.request.urlopen(req)
        assert resp.getcode() == 200
        return resp.read()
    else:
        with gfile.GFile(path, "rb") as f:
            return f.read()


def test_basename():
    testcases = [
        ("a", "a"),
        ("a/b", "b"),
        ("", ""),
        ("gs://a", ""),
        ("gs://a/", ""),
        ("gs://a/b", "b"),
        ("gs://a/b/c/test.filename", "test.filename"),
        ("http://a", ""),
        ("http://a/", ""),
        ("http://a/b", "b"),
        ("http://a/b/c/test.filename", "test.filename"),
    ]
    for input_, desired_output in testcases:
        actual_output = bf.basename(input_)
        assert desired_output == actual_output


def test_dirname():
    testcases = [
        ("a", ""),
        ("a/b", "a"),
        ("a/b/c", "a/b"),
        ("a/b/c/", "a/b/c"),
        ("", ""),
        ("gs://a", "gs://a/"),
        ("gs://a/", "gs://a/"),
        ("gs://a/b", "gs://a/"),
        ("gs://a/b/c/test.filename", "gs://a/b/c/"),
        ("gs://a/b/c/", "gs://a/b/"),
        ("http://a", "http://a/"),
        ("http://a/b", "http://a/"),
        ("http://a/b/c/test.filename", "http://a/b/c/"),
        ("http://a/b/c/", "http://a/b/"),
    ]
    for input_, desired_output in testcases:
        actual_output = bf.dirname(input_)
        assert desired_output == actual_output, f"{input_}"


def test_join():
    testcases = [
        ("a", "b", "a/b"),
        ("a/b", "c", "a/b/c"),
        ("a/b/", "c", "a/b/c"),
        ("a/b/", "c/", "a/b/c/"),
        ("a/b/", "/c/", "/c/"),
        ("", "", ""),
        ("gs://a", "b", "gs://a/b"),
        ("gs://a/b", "c", "gs://a/b/c"),
        ("gs://a/b/", "c", "gs://a/b/c"),
        ("gs://a/b/", "c/", "gs://a/b/c/"),
        ("gs://a/b/", "/c/", "gs://a/c/"),
        ("http://a", "b", "http://a/b"),
        ("http://a/b", "c", "http://a/b/c"),
        ("http://a/b/", "c", "http://a/b/c"),
        ("http://a/b/", "c/", "http://a/b/c/"),
        ("http://a/b/", "/c/", "http://a/c/"),
    ]
    for input_a, input_b, desired_output in testcases:
        actual_output = bf.join(input_a, input_b)
        assert desired_output == actual_output, f"{input_a} {input_b}"


def test_cache_key():
    contents = b"meow!"
    for ctx in [_get_temp_local_path, _get_temp_gcs_path, _get_temp_http_path]:
        with ctx() as path:
            _write_contents(path, contents)
            first_key = bf.cache_key(path)
            _write_contents(path, contents + contents)
            second_key = bf.cache_key(path)
            assert first_key != second_key


def test_get_url():
    contents = b"meow!"
    for ctx in [_get_temp_local_path, _get_temp_gcs_path, _get_temp_http_path]:
        with ctx() as path:
            _write_contents(path, contents)
            url = bf.get_url(path)
            assert urllib.request.urlopen(url).read() == contents


def test_read_write():
    contents = b"meow!"
    for ctx in [_get_temp_local_path, _get_temp_gcs_path, _get_temp_http_path]:
        with ctx() as path:
            with bf.BlobFile(path, "wb") as w:
                w.write(contents)
            with bf.BlobFile(path, "rb") as r:
                assert r.read() == contents


def test_copy():
    contents = b"meow!"
    with _get_temp_local_path() as local_path1, _get_temp_local_path() as local_path2, _get_temp_local_path() as local_path3, _get_temp_local_path() as local_path4, _get_temp_gcs_path() as gcs_path1, _get_temp_gcs_path() as gcs_path2, _get_temp_http_path() as http_path1, _get_temp_http_path() as http_path2:
        with pytest.raises(FileNotFoundError):
            bf.copy(gcs_path1, gcs_path2)

        with pytest.raises(FileNotFoundError):
            bf.copy(http_path1, http_path2)

        _write_contents(local_path1, contents)

        testcases = [
            (local_path1, local_path2),
            (local_path1, gcs_path1),
            (gcs_path1, gcs_path2),
            (gcs_path2, local_path3),
            (local_path1, http_path1),
            (local_path1, http_path2),
            (http_path2, local_path4),
        ]

        for src, dst in testcases:
            bf.copy(src, dst)
            assert _read_contents(dst) == contents
            with pytest.raises(FileExistsError):
                bf.copy(src, dst)
            bf.copy(src, dst, overwrite=True)
            assert _read_contents(dst) == contents


def test_exists():
    contents = b"meow!"
    for ctx in [_get_temp_local_path, _get_temp_gcs_path, _get_temp_http_path]:
        with ctx() as path:
            assert not bf.exists(path)
            _write_contents(path, contents)
            assert bf.exists(path)


@pytest.mark.parametrize("local", [True, False])
@pytest.mark.parametrize("binary", [True, False])
@pytest.mark.parametrize("streaming", [True, False])
@pytest.mark.parametrize("kind", ["local", "gcs", "http"])
def test_more_read_write(local, binary, streaming, kind):
    rng = np.random.RandomState(0)

    if kind == "local":
        ctx = _get_temp_local_path
    elif kind == "gcs":
        ctx = _get_temp_gcs_path
    elif kind == "http":
        ctx = _get_temp_http_path
    else:
        raise Exception("unrecognized path")

    with ctx() as path:
        if binary:
            read_mode = "rb"
            write_mode = "wb"
        else:
            read_mode = "r"
            write_mode = "w"

        with bf.BlobFile(path, write_mode, streaming=streaming) as w:
            pass

        with bf.BlobFile(path, read_mode, streaming=streaming) as r:
            assert len(r.read()) == 0

        contents = b"meow!"
        if not binary:
            contents = contents.decode("utf8")

        with bf.BlobFile(path, write_mode, streaming=streaming) as w:
            w.write(contents)

        with bf.BlobFile(path, read_mode, streaming=streaming) as r:
            assert r.read() == contents

        with bf.BlobFile(path, read_mode, streaming=streaming) as r:
            for i in range(len(contents)):
                assert r.read(1) == contents[i : i + 1]
            assert len(r.read()) == 0
            assert len(r.read()) == 0

        contents = b"meow!\n\nmew!\n"
        lines = [b"meow!\n", b"\n", b"mew!\n"]
        if not binary:
            contents = contents.decode("utf8")
            lines = [line.decode("utf8") for line in lines]

        with bf.BlobFile(path, write_mode, streaming=streaming) as w:
            w.write(contents)

        with bf.BlobFile(path, read_mode, streaming=streaming) as r:
            assert r.readlines() == lines

        with bf.BlobFile(path, read_mode, streaming=streaming) as r:
            assert [line for line in r] == lines

        if binary:
            contents = rng.randint(0, 256, size=12_345_678, dtype=np.uint8).tobytes()

            with bf.BlobFile(path, write_mode, streaming=streaming) as w:
                w.write(contents)

            with bf.BlobFile(path, read_mode, streaming=streaming) as r:
                size = rng.randint(0, 1_000_000)
                buf = b""
                while True:
                    b = r.read(size)
                    if b == b"":
                        break
                    buf += b
                assert buf == contents
        else:
            obj = {"a": 1}

            with bf.BlobFile(path, write_mode, streaming=streaming) as w:
                json.dump(obj, w)

            with bf.BlobFile(path, read_mode, streaming=streaming) as r:
                assert json.load(r) == obj


@pytest.mark.parametrize("streaming", [True, False])
@pytest.mark.parametrize("kind", ["local", "gcs", "http"])
def test_video(streaming, kind):
    rng = np.random.RandomState(0)
    shape = (256, 64, 64, 3)
    video_data = rng.randint(0, 256, size=np.prod(shape), dtype=np.uint8).reshape(shape)

    if kind == "local":
        ctx = _get_temp_local_path
    elif kind == "gcs":
        ctx = _get_temp_gcs_path
    elif kind == "http":
        ctx = _get_temp_http_path
    else:
        raise Exception("unrecognized path")

    with ctx() as path:
        with bf.BlobFile(path, mode="wb", streaming=streaming) as wf:
            with imageio.get_writer(
                wf,
                format="ffmpeg",
                quality=None,
                codec="libx264rgb",
                pixelformat="bgr24",
                output_params=["-f", "mp4", "-crf", "0"],
            ) as w:
                for frame in video_data:
                    w.append_data(frame)

        with bf.BlobFile(path, mode="rb", streaming=streaming) as rf:
            with imageio.get_reader(
                rf, format="ffmpeg", input_params=["-f", "mp4"]
            ) as r:
                for idx, frame in enumerate(r):
                    assert np.array_equal(frame, video_data[idx])


def test_retry():
    i = 0

    def f():
        nonlocal i
        i += 1

    bf.retry(f, attempts=3, min_backoff=0.01)
    assert i == 1

    i = 0

    class Failed(Exception):
        pass

    def f2():
        nonlocal i
        i += 1
        raise Failed("oh no")

    with pytest.raises(Failed):
        bf.retry(f2, attempts=3, min_backoff=0.01)
    assert i == 3
