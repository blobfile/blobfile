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
import base64

import av
import pytest
from tensorflow.io import gfile
import imageio
import numpy as np

import blobfile as bf
from . import ops, azure

GCS_TEST_BUCKET = "csh-test-2"
AS_TEST_BUCKET = "cshteststorage2-testcontainer"


@contextlib.contextmanager
def _get_temp_local_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert isinstance(tmpdir, str)
        path = os.path.join(tmpdir, "file.name")
        yield path


@contextlib.contextmanager
def _get_temp_gcs_path():
    path = f"gs://{GCS_TEST_BUCKET}/" + "".join(
        random.choice(string.ascii_lowercase) for i in range(16)
    )
    gfile.mkdir(path)
    yield path + "/file.name"
    gfile.rmtree(path)


@contextlib.contextmanager
def _get_temp_as_path():
    random_id = "".join(random.choice(string.ascii_lowercase) for i in range(16))
    path = f"as://{AS_TEST_BUCKET}/" + random_id
    account, _sep, container = AS_TEST_BUCKET.partition("-")
    yield path + "/file.name"
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
            assert isinstance(tmpdir, str)
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
            assert isinstance(tmpdir, str)
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
        ("as://a", ""),
        ("as://a/", ""),
        ("as://a/b", "b"),
        ("as://a/b/c/test.filename", "test.filename"),
    ]
    for input_, desired_output in testcases:
        actual_output = bf.basename(input_)
        assert desired_output == actual_output


def test_dirname():
    testcases = [
        ("a", ""),
        ("a/b", "a/"),
        ("a/b/c", "a/b/"),
        ("a/b/c/", "a/b/c/"),
        ("", ""),
        ("gs://a", "gs://a/"),
        ("gs://a/", "gs://a/"),
        ("gs://a/b", "gs://a/"),
        ("gs://a/b/c/test.filename", "gs://a/b/c/"),
        ("gs://a/b/c/", "gs://a/b/"),
        ("as://a", "as://a/"),
        ("as://a/", "as://a/"),
        ("as://a/b", "as://a/"),
        ("as://a/b/c/test.filename", "as://a/b/c/"),
        ("as://a/b/c/", "as://a/b/"),
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
        ("as://a", "b", "as://a/b"),
        ("as://a/b", "c", "as://a/b/c"),
        ("as://a/b/", "c", "as://a/b/c"),
        ("as://a/b/", "c/", "as://a/b/c/"),
        ("as://a/b/", "/c/", "as://a/c/"),
    ]
    for input_a, input_b, desired_output in testcases:
        actual_output = bf.join(input_a, input_b)
        assert desired_output == actual_output, f"{input_a} {input_b}"


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_get_url(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        url, _expiration = bf.get_url(path)
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


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_stat(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        s = bf.stat(path)
        assert s.size == len(contents)
        assert 0 <= abs(time.time() - s.mtime) <= 5


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_remove(ctx):
    contents = b"meow!"
    with ctx() as path:
        _write_contents(path, contents)
        assert bf.exists(path)
        bf.remove(path)
        assert not bf.exists(path)


@pytest.mark.parametrize(
    # don't test local path because that has slightly different behavior
    "ctx",
    [_get_temp_gcs_path, _get_temp_as_path],
)
def test_rmdir(ctx):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.dirname(path)
        # this is an error for a local path but not for a blob path
        bf.rmdir(bf.join(dirpath, "fakedirname"))
        new_dirpath = bf.join(dirpath, "dirname")
        bf.makedirs(new_dirpath)
        assert bf.exists(new_dirpath)
        bf.rmdir(new_dirpath)
        assert not bf.exists(new_dirpath)

        # double delete is fine
        bf.rmdir(new_dirpath)

        # implicit dir
        new_filepath = bf.join(dirpath, "dirname", "name")
        _write_contents(new_filepath, contents)
        with pytest.raises(OSError):
            # not empty dir
            bf.rmdir(new_dirpath)
        bf.remove(new_filepath)
        bf.rmdir(new_dirpath)


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_makedirs(ctx):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.join(path, "x", "x", "x")
        bf.makedirs(dirpath)
        assert bf.exists(dirpath)
        _write_contents(bf.join(dirpath, "testfile"), contents)


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_isdir(ctx):
    contents = b"meow!"
    with ctx() as path:
        assert not bf.isdir(path)
        _write_contents(path, contents)
        assert not bf.isdir(path)
        dirpath = path + ".dir"
        bf.makedirs(dirpath)
        assert bf.isdir(dirpath)
        assert not bf.isdir(dirpath[:-1])


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
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
        bf.makedirs(bf.join(dirpath, "c"))
        assert sorted(list(bf.listdir(dirpath))) == ["a", "b", "c/"]


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_walk(ctx):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.dirname(path)
        a_path = bf.join(dirpath, "a")
        with bf.BlobFile(a_path, "wb") as w:
            w.write(contents)
        bf.makedirs(bf.join(dirpath, "c/d"))
        b_path = bf.join(dirpath, "c/d/b")
        with bf.BlobFile(b_path, "wb") as w:
            w.write(contents)
        assert list(bf.walk(dirpath)) == [
            (dirpath, ["c/"], ["a"]),
            (bf.join(dirpath, "c/"), ["d/"], []),
            (bf.join(dirpath, "c", "d/"), [], ["b"]),
        ]


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
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

        path = bf.join(dirpath, "subdir", "test.txt")
        bf.makedirs(bf.dirname(path))
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)
        path = bf.join(dirpath, "subdir", "subsubdir", "test.txt")
        bf.makedirs(bf.dirname(path))
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)

        assert_listing_equal(bf.join(dirpath, "*/test.txt"), ["test.txt"])
        assert_listing_equal(bf.join(dirpath, "*/test"), [])


def test_copy():
    contents = b"meow!"
    with _get_temp_local_path() as local_path1, _get_temp_local_path() as local_path2, _get_temp_local_path() as local_path3, _get_temp_gcs_path() as gcs_path1, _get_temp_gcs_path() as gcs_path2, _get_temp_as_path() as as_path1, _get_temp_as_path() as as_path2:
        with pytest.raises(FileNotFoundError):
            bf.copy(gcs_path1, gcs_path2)
        with pytest.raises(FileNotFoundError):
            bf.copy(as_path1, as_path2)

        _write_contents(local_path1, contents)

        testcases = [
            (local_path1, local_path2),
            (local_path1, gcs_path1),
            (gcs_path1, gcs_path2),
            (gcs_path2, as_path1),
            (as_path1, as_path2),
            (as_path2, local_path3),
        ]

        for src, dst in testcases:
            h = bf.copy(src, dst, return_md5=True)
            assert h == hashlib.md5(contents).hexdigest()
            assert _read_contents(dst) == contents
            with pytest.raises(FileExistsError):
                bf.copy(src, dst)
            bf.copy(src, dst, overwrite=True)
            assert _read_contents(dst) == contents


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_exists(ctx):
    contents = b"meow!"
    with ctx() as path:
        assert not bf.exists(path)
        _write_contents(path, contents)
        assert bf.exists(path)


@pytest.mark.parametrize("buffer_size", [1, 100])
@pytest.mark.parametrize("ctx", [_get_temp_gcs_path, _get_temp_as_path])
def test_read_stats(buffer_size, ctx):
    with ctx() as path:
        contents = b"meow!"

        with bf.BlobFile(path, "wb") as w:
            w.write(contents)

        with bf.BlobFile(path, "rb", buffer_size=buffer_size) as r:
            r.read(1)

        if buffer_size == 1:
            assert r.raw.bytes_read == 1  # type: ignore
        else:
            assert r.raw.bytes_read == len(contents)  # type: ignore

        with bf.BlobFile(path, "rb", buffer_size=buffer_size) as r:
            r.read(1)
            r.seek(4)
            r.read(1)

        if buffer_size == 1:
            assert r.raw.requests == 2  # type: ignore
            assert r.raw.bytes_read == 2  # type: ignore
        else:
            assert r.raw.requests == 1  # type: ignore
            assert r.raw.bytes_read == len(contents)  # type: ignore


@pytest.mark.parametrize("ctx", [_get_temp_gcs_path, _get_temp_as_path])
def test_cache_dir(ctx):
    cache_dir = tempfile.mkdtemp()
    contents = b"meow!"
    alternative_contents = b"purr!"
    with ctx() as path:
        with bf.BlobFile(path, mode="wb") as f:
            f.write(contents)
        with bf.LocalBlobFile(path, mode="rb", cache_dir=cache_dir) as f:
            assert f.read() == contents
        content_hash = hashlib.md5(contents).hexdigest()
        cache_path = bf.join(cache_dir, content_hash, bf.basename(path))
        with open(cache_path, "rb") as f:
            assert f.read() == contents
        # alter the cached file to make sure we are not re-reading the remote file
        with open(cache_path, "wb") as f:
            f.write(alternative_contents)
        with bf.LocalBlobFile(path, mode="rb", cache_dir=cache_dir) as f:
            assert f.read() == alternative_contents


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_truncation(ctx):
    chunk_size = 2 ** 20
    contents = b"\x00" * chunk_size * 3
    alternative_contents = b"\xFF" * chunk_size * 2
    with ctx() as path:
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)
        with bf.BlobFile(path, "rb") as f:
            read_contents = f.read(chunk_size)
            with bf.BlobFile(path, "wb") as f2:
                f2.write(alternative_contents)
            # close underlying connection
            f.raw._f = None  # type: ignore
            read_contents += f.read(chunk_size)
            read_contents += f.read(chunk_size)
            assert (
                read_contents
                == contents[:chunk_size]
                + alternative_contents[chunk_size : chunk_size * 2]
            )


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_overwrite_while_reading(ctx):
    chunk_size = 2 ** 20
    contents = b"\x00" * chunk_size * 2
    alternative_contents = b"\xFF" * chunk_size * 4
    with ctx() as path:
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)
        with bf.BlobFile(path, "rb") as f:
            read_contents = f.read(chunk_size)
            with bf.BlobFile(path, "wb") as f2:
                f2.write(alternative_contents)
            # close underlying connection
            f.raw._f = None  # type: ignore
            read_contents += f.read(chunk_size)
            assert (
                read_contents
                == contents[:chunk_size]
                + alternative_contents[chunk_size : chunk_size * 2]
            )


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
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)
        assert bf.md5(path) == meow_hash
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)
        assert bf.md5(path) == meow_hash


@pytest.mark.parametrize("ctx", [_get_temp_as_path])
def test_azure_maybe_update_md5(ctx):
    contents = b"meow!"
    meow_hash = hashlib.md5(contents).hexdigest()
    alternative_contents = b"purr"
    purr_hash = hashlib.md5(alternative_contents).hexdigest()

    with ctx() as path:
        _write_contents(path, contents)
        _isfile, metadata = ops._azure_isfile(path)
        assert ops._azure_maybe_update_md5(path, metadata["ETag"], meow_hash)
        _write_contents(path, alternative_contents)
        assert not ops._azure_maybe_update_md5(path, metadata["ETag"], meow_hash)
        _isfile, metadata = ops._azure_isfile(path)
        assert base64.b64decode(metadata["Content-MD5"]).hex() == purr_hash


def _get_http_pool_id(q):
    q.put(id(ops._get_http_pool()))


def test_fork():
    q = mp.Queue()
    # this reference should keep the old http client alive in the child process
    # to ensure that a new one does not recycle the memory address
    http1 = ops._get_http_pool()
    parent1 = id(http1)
    p = mp.Process(target=_get_http_pool_id, args=(q,))
    p.start()
    p.join()
    http2 = ops._get_http_pool()
    parent2 = id(http2)

    child = q.get()
    assert parent1 == parent2
    assert child != parent1
