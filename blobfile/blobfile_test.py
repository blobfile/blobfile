import random
import string
import tempfile
import os
import contextlib
import json
import urllib.request
import hashlib
import time
import subprocess as sp
import multiprocessing as mp
import platform
import av

import pytest
from tensorflow.io import gfile  # pylint: disable=import-error
import imageio
import numpy as np

from . import blobfile as bf, azure

GCS_TEST_BUCKET = "csh-test-2"
AS_TEST_BUCKET = "cshteststorage2-testcontainer"


@contextlib.contextmanager
def _get_temp_local_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "file.name")
        yield path


@contextlib.contextmanager
def _get_temp_gcs_path():
    path = f"gs://{GCS_TEST_BUCKET}/" + "".join(
        random.choice(string.ascii_lowercase) for i in range(16)
    )
    gfile.mkdir(path)
    yield path + "/name"
    gfile.rmtree(path)


@contextlib.contextmanager
def _get_temp_as_path():
    random_id = "".join(random.choice(string.ascii_lowercase) for i in range(16))
    path = f"as://{AS_TEST_BUCKET}/" + random_id
    account, _sep, container = AS_TEST_BUCKET.partition("-")
    yield path + "/name"
    sp.run(
        [
            "az",
            "storage",
            "blob",
            "delete-batch",
            "--account-name",
            account,
            "--source",
            container,
            "--pattern",
            f"{random_id}/*",
        ],
        check=True,
        shell=platform.system() == "Windows",
    )


def _write_contents(path, contents):
    if path.startswith("as://"):
        with tempfile.TemporaryDirectory() as tmpdir:
            account, container, blob = azure.split_url(path)
            filepath = os.path.join(tmpdir, "tmp")
            with open(filepath, "wb") as f:
                f.write(contents)
            sp.run(
                [
                    "az",
                    "storage",
                    "blob",
                    "upload",
                    "--account-name",
                    account,
                    "--container-name",
                    container,
                    "--name",
                    blob,
                    "--file",
                    filepath,
                ],
                check=True,
                shell=platform.system() == "Windows",
                stdout=sp.DEVNULL,
                stderr=sp.DEVNULL,
            )
    else:
        with gfile.GFile(path, "wb") as f:
            f.write(contents)


def _read_contents(path):
    if path.startswith("as://"):
        with tempfile.TemporaryDirectory() as tmpdir:
            account, container, blob = azure.split_url(path)
            filepath = os.path.join(tmpdir, "tmp")
            sp.run(
                [
                    "az",
                    "storage",
                    "blob",
                    "download",
                    "--account-name",
                    account,
                    "--container-name",
                    container,
                    "--name",
                    blob,
                    "--file",
                    filepath,
                ],
                check=True,
                shell=platform.system() == "Windows",
                stdout=sp.DEVNULL,
                stderr=sp.DEVNULL,
            )
            with open(filepath, "rb") as f:
                return f.read()
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


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_cache_key(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        first_key = bf.cache_key(path)
        _write_contents(path, contents + contents)
        second_key = bf.cache_key(path)
        assert first_key != second_key


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_get_url(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        url = bf.get_url(path)
        assert urllib.request.urlopen(url).read() == contents


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_read_write(ctx):
    contents = b"meow!\npurr\n"
    with ctx() as path:
        with bf.BlobFile(path, "wb") as w:
            w.write(contents)
        with bf.BlobFile(path, "rb") as r:
            assert r.read() == contents
        with bf.BlobFile(path, "rb") as r:
            lines = list(r)
            assert b"".join(lines) == contents


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_stat(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        s = bf.stat(path)
        assert s.size == len(contents)
        assert 0 <= abs(time.time() - s.mtime) <= 5


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_rename(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        new_path = path + ".new"
        bf.rename(path, new_path)
        with bf.BlobFile(new_path, "rb") as f:
            assert f.read() == contents


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_remove(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        assert bf.exists(path)
        bf.remove(path)
        assert not bf.exists(path)


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_makedirs(ctx):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.join(path, "x", "x", "x")
        bf.makedirs(dirpath)
        assert bf.exists(dirpath)
        _write_contents(bf.join(dirpath, "testfile"), contents)


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_isdir(ctx):
    contents = b"meow!"
    with ctx() as path:
        assert not bf.isdir(path)
        _write_contents(path, contents)
        assert not bf.isdir(path)
        dirpath = path + ".dir"
        bf.makedirs(dirpath)
        assert bf.isdir(dirpath)


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_listdir(ctx):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.dirname(path)
        a_path = bf.join(dirpath, "a")
        with bf.BlobFile(a_path, "wb") as w:
            w.write(contents)
        b_path = bf.join(dirpath, "b")
        with bf.BlobFile(b_path, "wb") as w:
            w.write(contents)
        assert sorted(list(bf.listdir(dirpath))) == ["a", "b"]


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_glob(ctx):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.dirname(path)
        a_path = bf.join(dirpath, "ab")
        with bf.BlobFile(a_path, "wb") as w:
            w.write(contents)
        b_path = bf.join(dirpath, "bb")
        with bf.BlobFile(b_path, "wb") as w:
            w.write(contents)

        def assert_listing_equal(actual, desired):
            actual = [bf.basename(p) for p in sorted(list(bf.glob(actual)))]
            assert actual == desired

        assert_listing_equal(bf.join(dirpath, "*b"), ["ab", "bb"])
        assert_listing_equal(bf.join(dirpath, "a*"), ["ab"])
        assert_listing_equal(bf.join(dirpath, "*"), ["ab", "bb"])
        assert_listing_equal(bf.join(dirpath, "bb"), ["bb"])


def test_copy():
    contents = b"meow!"
    with _get_temp_local_path() as local_path1, _get_temp_local_path() as local_path2, _get_temp_local_path() as local_path3, _get_temp_gcs_path() as gcs_path1, _get_temp_gcs_path() as gcs_path2:
        with pytest.raises(FileNotFoundError):
            bf.copy(gcs_path1, gcs_path2)

        _write_contents(local_path1, contents)

        testcases = [
            (local_path1, local_path2),
            (local_path1, gcs_path1),
            (gcs_path1, gcs_path2),
            (gcs_path2, local_path3),
        ]

        for src, dst in testcases:
            bf.copy(src, dst)
            assert _read_contents(dst) == contents
            with pytest.raises(FileExistsError):
                bf.copy(src, dst)
            bf.copy(src, dst, overwrite=True)
            assert _read_contents(dst) == contents


@pytest.mark.parametrize("ctx", [_get_temp_local_path, _get_temp_gcs_path])
def test_exists(ctx):
    contents = b"meow!"
    with ctx() as path:
        assert not bf.exists(path)
        _write_contents(path, contents)
        assert bf.exists(path)


@pytest.mark.parametrize("binary", [True, False])
@pytest.mark.parametrize("blobfile", [bf.BlobFile, bf.LocalBlobFile])
@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_more_read_write(binary, blobfile, ctx):
    rng = np.random.RandomState(0)

    with ctx() as path:
        if binary:
            read_mode = "rb"
            write_mode = "wb"
        else:
            read_mode = "r"
            write_mode = "w"

        with blobfile(path, write_mode) as w:
            pass

        with blobfile(path, read_mode) as r:
            assert len(r.read()) == 0

        contents = b"meow!"
        if not binary:
            contents = contents.decode("utf8")

        with blobfile(path, write_mode) as w:
            w.write(contents)

        with blobfile(path, read_mode) as r:
            assert r.read() == contents

        with blobfile(path, read_mode) as r:
            for i in range(len(contents)):
                assert r.read(1) == contents[i : i + 1]
            assert len(r.read()) == 0
            assert len(r.read()) == 0

        contents = b"meow!\n\nmew!\n"
        lines = [b"meow!\n", b"\n", b"mew!\n"]
        if not binary:
            contents = contents.decode("utf8")
            lines = [line.decode("utf8") for line in lines]

        with blobfile(path, write_mode) as w:
            w.write(contents)

        with blobfile(path, read_mode) as r:
            assert r.readlines() == lines

        with blobfile(path, read_mode) as r:
            assert [line for line in r] == lines

        if binary:
            for size in [2 * 2 ** 20, 12_345_678]:
                contents = rng.randint(0, 256, size=size, dtype=np.uint8).tobytes()

                with blobfile(path, write_mode) as w:
                    w.write(contents)

                with blobfile(path, read_mode) as r:
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

            with blobfile(path, write_mode) as w:
                json.dump(obj, w)

            with blobfile(path, read_mode) as r:
                assert json.load(r) == obj


@pytest.mark.parametrize("blobfile", [bf.BlobFile, bf.LocalBlobFile])
@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_video(blobfile, ctx):
    rng = np.random.RandomState(0)
    shape = (256, 64, 64, 3)
    video_data = rng.randint(0, 256, size=np.prod(shape), dtype=np.uint8).reshape(shape)

    with ctx() as path:
        with blobfile(path, mode="wb") as wf:
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

        with blobfile(path, mode="rb") as rf:
            with imageio.get_reader(
                rf, format="ffmpeg", input_params=["-f", "mp4"]
            ) as r:
                for idx, frame in enumerate(r):
                    assert np.array_equal(frame, video_data[idx])

        with blobfile(path, mode="rb") as rf:
            container = av.open(rf)
            stream = container.streams.video[0]
            for idx, frame in enumerate(container.decode(stream)):
                assert np.array_equal(frame.to_image(), video_data[idx])


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_md5(ctx):
    contents = b"meow!"
    meow_hash = hashlib.md5(contents).hexdigest()

    with ctx() as path:
        _write_contents(path, contents)
        assert bf.md5(path) == meow_hash


def _get_http_pool_id(q):
    q.put(id(bf._get_http_pool()))  # pylint: disable=protected-access


def test_fork():
    q = mp.Queue()
    # this reference should keep the old http client alive in the child process
    # to ensure that a new one does not recycle the memory address
    http1 = bf._get_http_pool()  # pylint: disable=protected-access
    parent1 = id(http1)
    p = mp.Process(target=_get_http_pool_id, args=(q,))
    p.start()
    p.join()
    http2 = bf._get_http_pool()  # pylint: disable=protected-access
    parent2 = id(http2)

    child = q.get()
    assert parent1 == parent2
    assert child != parent1
