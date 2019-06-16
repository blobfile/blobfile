import random
import string
import hashlib
import tempfile
import os
import contextlib

import pytest
from tensorflow.io import gfile  # pylint: disable=import-error
import imageio
import numpy as np

from . import blobfile as bf


@contextlib.contextmanager
def _get_test_dir():
    remotedir = "gs://csh-test-2/" + "".join(
        random.choice(string.ascii_lowercase) for i in range(16)
    )
    yield remotedir
    gfile.rmtree(remotedir)


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
        ("gs://a", "gs://a"),
        ("gs://a/b", "gs://a"),
        ("gs://a/b/c/test.filename", "gs://a/b/c"),
        ("gs://a/b/c/", "gs://a/b/c"),
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
    ]
    for input_a, input_b, desired_output in testcases:
        actual_output = bf.join(input_a, input_b)
        assert desired_output == actual_output, f"{input_a} {input_b}"


def test_md5():
    contents = b"meow!"
    meow_hash = hashlib.md5(contents).hexdigest()
    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = os.path.join(tmpdir, "file.name")
        with open(local_path, "wb") as f:
            f.write(contents)
        assert bf.md5(local_path) == meow_hash

    with _get_test_dir() as tmpdir:
        remote_path = tmpdir + "/file.name"
        _write_contents(remote_path, contents)
        assert bf.md5(remote_path) == meow_hash


def test_read_write():
    contents = b"meow!"
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_test_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "/file.name"

        for path in [local_path, remote_path]:
            with bf.BlobFile(path, "wb") as w:
                w.write(contents)
            with bf.BlobFile(path, "rb") as r:
                assert r.read() == contents


def test_copy():
    contents = b"meow!"
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_test_dir() as remote_tmpdir:
        local_path1 = os.path.join(local_tmpdir, "file1.name")
        local_path2 = os.path.join(local_tmpdir, "file2.name")
        remote_path1 = remote_tmpdir + "/file1.name"
        remote_path2 = remote_tmpdir + "/file2.name"

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
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_test_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "/file.name"
        assert not bf.exists(local_path)
        assert not bf.exists(remote_path)
        _write_contents(local_path, contents)
        _write_contents(remote_path, contents)
        assert bf.exists(local_path)
        assert bf.exists(remote_path)


def test_more_read_write():
    rng = np.random.RandomState(0)
    with tempfile.TemporaryDirectory() as local_tmpdir, _get_test_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "/file.name"
        for path in [local_path, remote_path]:
            print("path", path)
            contents = b"meow!"
            _write_contents(path, contents)

            with bf.BlobFile(path, "rb") as r:
                assert r.read() == contents

            with bf.BlobFile(path, "rb") as r:
                for i in range(len(contents)):
                    assert r.read(1) == contents[i : i + 1]
                assert r.read() == b""
                assert r.read() == b""

            contents = b"meow!\n\nmew!\n"
            lines = [b"meow!\n", b"\n", b"mew!\n"]
            _write_contents(path, contents)

            with bf.BlobFile(path, "rb") as r:
                assert r.readlines() == lines

            with bf.BlobFile(path, "rb") as r:
                assert [line for line in r] == lines

            contents = rng.randint(0, 256, size=12_345_678, dtype=np.uint8).tobytes()
            _write_contents(path, contents)

            with bf.BlobFile(path, "rb") as r:
                size = rng.randint(0, 1_000_000)
                buf = b""
                while True:
                    b = r.read(size)
                    if b == b"":
                        break
                    buf += b
                assert buf == contents


def test_video():
    rng = np.random.RandomState(0)
    shape = (256, 64, 64, 3)
    video_data = rng.randint(0, 256, size=np.prod(shape), dtype=np.uint8).reshape(shape)

    with tempfile.TemporaryDirectory() as local_tmpdir, _get_test_dir() as remote_tmpdir:
        local_path = os.path.join(local_tmpdir, "file.name")
        remote_path = remote_tmpdir + "/file.name"
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
