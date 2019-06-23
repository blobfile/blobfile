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
def _get_temp_gcs_dir():
    remotedir = (
        "gs://csh-test-2/"
        + "".join(random.choice(string.ascii_lowercase) for i in range(16))
        + "/"
    )
    yield remotedir
    gfile.rmtree(remotedir)


@contextlib.contextmanager
def _get_temp_http_dir():
    with tempfile.TemporaryDirectory() as tmpdir:

        class HTTPHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=tmpdir, **kwargs)

        with http.server.HTTPServer(("localhost", 0), HTTPHandler) as httpd:
            t = threading.Thread(target=httpd.serve_forever)
            t.start()
            yield f"http://localhost:{httpd.server_port}/"
            httpd.shutdown()
            t.join()


def _write_contents(path, contents):
    with gfile.GFile(path, "wb") as f:
        f.write(contents)


def _read_contents(path):
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
    with tempfile.TemporaryDirectory() as tmpdir, _get_temp_gcs_dir() as remote_tmpdir:
        local_path = os.path.join(tmpdir, "file.name")
        remote_path = remote_tmpdir + "file.name"

        for path in [local_path, remote_path]:
            _write_contents(path, contents)
            first_key = bf.cache_key(path)
            _write_contents(path, contents + contents)
            second_key = bf.cache_key(path)
            assert first_key != second_key


def test_get_url():
    contents = b"meow!"
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_temp_gcs_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "file.name"

        for path in [local_path, remote_path]:
            _write_contents(path, contents)
            url = bf.get_url(path)
            assert urllib.request.urlopen(url).read() == contents


def test_read_write():
    contents = b"meow!"
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_temp_gcs_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "file.name"

        for path in [local_path, remote_path]:
            with bf.BlobFile(path, "wb") as w:
                w.write(contents)
            with bf.BlobFile(path, "rb") as r:
                assert r.read() == contents


def test_copy():
    contents = b"meow!"
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_temp_gcs_dir() as remote_tmpdir:
        local_path1 = os.path.join(local_tmpdir, "file1.name")
        local_path2 = os.path.join(local_tmpdir, "file2.name")
        remote_path1 = remote_tmpdir + "file1.name"
        remote_path2 = remote_tmpdir + "file2.name"

        _write_contents(local_path1, contents)
        assert _read_contents(local_path1) == contents

        with pytest.raises(FileNotFoundError):
            bf.copy(remote_path1, remote_path2)

        testcases = [
            (local_path1, local_path2),
            (local_path1, remote_path1),
            (remote_path1, remote_path2),
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
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_temp_gcs_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "file.name"
        assert not bf.exists(local_path)
        assert not bf.exists(remote_path)
        _write_contents(local_path, contents)
        _write_contents(remote_path, contents)
        assert bf.exists(local_path)
        assert bf.exists(remote_path)


@pytest.mark.parametrize("local", [True, False])
@pytest.mark.parametrize("binary", [True, False])
@pytest.mark.parametrize("streaming", [True, False])
def test_more_read_write(local, binary, streaming):
    rng = np.random.RandomState(0)

    if local:
        dir_context_manager = tempfile.TemporaryDirectory()
    else:
        dir_context_manager = _get_temp_gcs_dir()

    with dir_context_manager as tmpdir:
        if local:
            path = os.path.join(tmpdir, "file.name")
        else:
            path = tmpdir + "file.name"

        print("path", path)

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


def test_video():
    rng = np.random.RandomState(0)
    shape = (256, 64, 64, 3)
    video_data = rng.randint(0, 256, size=np.prod(shape), dtype=np.uint8).reshape(shape)

    with tempfile.TemporaryDirectory() as local_tmpdir, _get_temp_gcs_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "file.name"
        for streaming in [False, True]:
            for path in [local_path, remote_path]:
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
