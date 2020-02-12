# https://github.com/tensorflow/tensorflow/issues/27023
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

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

GCS_TEST_BUCKET = "csh-test-3"
AS_TEST_ACCOUNT = "cshteststorage2"
AS_TEST_CONTAINER = "testcontainer2"

AZURE_VALID_CONTAINER = (
    f"https://{AS_TEST_ACCOUNT}.blob.core.windows.net/{AS_TEST_CONTAINER}"
)
AZURE_INVALID_CONTAINER = f"https://{AS_TEST_ACCOUNT}.blob.core.windows.net/{AS_TEST_CONTAINER}-does-not-exist"
AZURE_INVALID_ACCOUNT = f"https://{AS_TEST_ACCOUNT}-does-not-exist.blob.core.windows.net/{AS_TEST_CONTAINER}"
GCS_VALID_BUCKET = f"gs://{GCS_TEST_BUCKET}"
GCS_INVALID_BUCKET = f"gs://{GCS_TEST_BUCKET}-does-not-exist"


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
    path = (
        f"https://{AS_TEST_ACCOUNT}.blob.core.windows.net/{AS_TEST_CONTAINER}/"
        + random_id
    )
    yield path + "/file.name"
    sp.run(
        [
            "az",
            "storage",
            "blob",
            "delete-batch",
            "--account-name",
            AS_TEST_ACCOUNT,
            "--source",
            AS_TEST_CONTAINER,
            "--pattern",
            f"{random_id}/*",
        ],
        check=True,
        shell=platform.system() == "Windows",
    )


def _write_contents(path, contents):
    if ".blob.core.windows.net" in path:
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
    if ".blob.core.windows.net" in path:
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
        ("/", ""),
        ("a/", ""),
        ("a", "a"),
        ("a/b", "b"),
        ("", ""),
        ("gs://a", ""),
        ("gs://a/", ""),
        ("gs://a/b/", ""),
        ("gs://a/b", "b"),
        ("gs://a/b/c/test.filename", "test.filename"),
        ("https://a.blob.core.windows.net/b", ""),
        ("https://a.blob.core.windows.net/b/", ""),
        ("https://a.blob.core.windows.net/b/c/", ""),
        ("https://a.blob.core.windows.net/b/c", "c"),
        ("https://a.blob.core.windows.net/b/c/test.filename", "test.filename"),
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
        ("gs://a/", "gs://a"),
        ("gs://a/b", "gs://a"),
        ("gs://a/b/c/test.filename", "gs://a/b/c"),
        ("gs://a/b/c/", "gs://a/b"),
        (
            "https://a.blob.core.windows.net/container",
            "https://a.blob.core.windows.net/container",
        ),
        (
            "https://a.blob.core.windows.net/container/",
            "https://a.blob.core.windows.net/container",
        ),
        (
            "https://a.blob.core.windows.net/container/b",
            "https://a.blob.core.windows.net/container",
        ),
        (
            "https://a.blob.core.windows.net/container/b/c/test.filename",
            "https://a.blob.core.windows.net/container/b/c",
        ),
        (
            "https://a.blob.core.windows.net/container/b/c/",
            "https://a.blob.core.windows.net/container/b",
        ),
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
        ("gs://a/b/", "../c", "gs://a/c"),
        ("gs://a/b/", "../c/", "gs://a/c/"),
        ("gs://a/b/", "../../c/", "gs://a/c/"),
        (
            "https://a.blob.core.windows.net/container",
            "b",
            "https://a.blob.core.windows.net/container/b",
        ),
        (
            "https://a.blob.core.windows.net/container/b",
            "c",
            "https://a.blob.core.windows.net/container/b/c",
        ),
        (
            "https://a.blob.core.windows.net/container/b/",
            "c",
            "https://a.blob.core.windows.net/container/b/c",
        ),
        (
            "https://a.blob.core.windows.net/container/b/",
            "c/",
            "https://a.blob.core.windows.net/container/b/c/",
        ),
        (
            "https://a.blob.core.windows.net/container/b/",
            "/c/",
            "https://a.blob.core.windows.net/container/c/",
        ),
        (
            "https://a.blob.core.windows.net/container/b/",
            "../c",
            "https://a.blob.core.windows.net/container/c",
        ),
        (
            "https://a.blob.core.windows.net/container/b/",
            "../c/",
            "https://a.blob.core.windows.net/container/c/",
        ),
        (
            "https://a.blob.core.windows.net/container/b/",
            "../../c/",
            "https://a.blob.core.windows.net/container/c/",
        ),
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
        url, _ = bf.get_url(path)
        assert urllib.request.urlopen(url).read() == contents


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_read_write(ctx):
    contents = b"meow!\npurr\n"
    with ctx() as path:
        path = bf.join(path, "a folder", "a.file")
        bf.makedirs(bf.dirname(path))
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
def test_append(ctx):
    contents = b"meow!\n"
    additional_contents = b"purr\n"
    with ctx() as path:
        with bf.LocalBlobFile(path, "ab") as w:
            w.write(contents)
        with bf.LocalBlobFile(path, "ab") as w:
            w.write(additional_contents)
        with bf.BlobFile(path, "rb") as r:
            assert r.read() == contents + additional_contents


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
        assert sorted(list(bf.listdir(dirpath))) == ["a", "b", "c"]


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_listdir_sharded(ctx):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.dirname(path)
        with bf.BlobFile(bf.join(dirpath, "a"), "wb") as w:
            w.write(contents)
        with bf.BlobFile(bf.join(dirpath, "aa"), "wb") as w:
            w.write(contents)
        with bf.BlobFile(bf.join(dirpath, "b"), "wb") as w:
            w.write(contents)
        with bf.BlobFile(bf.join(dirpath, "ca"), "wb") as w:
            w.write(contents)
        bf.makedirs(bf.join(dirpath, "c"))
        with bf.BlobFile(bf.join(dirpath, "c/a"), "wb") as w:
            w.write(contents)
        # this should also test shard_prefix_length=2 but that takes too long
        assert sorted(list(bf.listdir(dirpath, shard_prefix_length=1))) == [
            "a",
            "aa",
            "b",
            "c",
            "ca",
        ]


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
            (dirpath, ["c"], ["a"]),
            (bf.join(dirpath, "c"), ["d"], []),
            (bf.join(dirpath, "c", "d"), [], ["b"]),
        ]


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
@pytest.mark.parametrize("parallel", [False, True])
def test_glob(ctx, parallel):
    contents = b"meow!"
    with ctx() as path:
        dirpath = bf.dirname(path)
        a_path = bf.join(dirpath, "ab")
        with bf.BlobFile(a_path, "wb") as w:
            w.write(contents)
        b_path = bf.join(dirpath, "bb")
        with bf.BlobFile(b_path, "wb") as w:
            w.write(contents)

        def assert_listing_equal(path, desired):
            desired = sorted([bf.join(dirpath, p) for p in desired])
            actual = sorted(list(bf.glob(path, parallel=parallel)))
            assert actual == desired, f"{actual} != {desired}"

        assert_listing_equal(bf.join(dirpath, "*b"), ["ab", "bb"])
        assert_listing_equal(bf.join(dirpath, "a*"), ["ab"])
        assert_listing_equal(bf.join(dirpath, "ab*"), ["ab"])
        assert_listing_equal(bf.join(dirpath, "*"), ["ab", "bb"])
        assert_listing_equal(bf.join(dirpath, "bb"), ["bb"])

        path = bf.join(dirpath, "test.txt")
        with bf.BlobFile(path, "wb") as w:
            w.write(contents)
        path = bf.join(dirpath, "subdir", "test.txt")
        bf.makedirs(bf.dirname(path))
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)
        path = bf.join(dirpath, "subdir", "subsubdir", "test.txt")
        if "://" not in path:
            # implicit directory
            bf.makedirs(bf.dirname(path))
        with bf.BlobFile(path, "wb") as f:
            f.write(contents)

        assert_listing_equal(bf.join(dirpath, "*/test.txt"), ["subdir/test.txt"])
        assert_listing_equal(bf.join(dirpath, "*/*.txt"), ["subdir/test.txt"])
        if "://" in path:
            # local glob doesn't handle ** the same way as remote glob
            assert_listing_equal(
                bf.join(dirpath, "**.txt"),
                ["test.txt", "subdir/test.txt", "subdir/subsubdir/test.txt"],
            )
        else:
            assert_listing_equal(bf.join(dirpath, "**.txt"), ["test.txt"])
        assert_listing_equal(bf.join(dirpath, "*/test"), [])
        assert_listing_equal(bf.join(dirpath, "subdir/test.txt"), ["subdir/test.txt"])

        # directories
        assert_listing_equal(bf.join(dirpath, "*"), ["ab", "bb", "subdir", "test.txt"])
        assert_listing_equal(bf.join(dirpath, "subdir"), ["subdir"])
        assert_listing_equal(bf.join(dirpath, "subdir/"), ["subdir"])
        assert_listing_equal(bf.join(dirpath, "*/"), ["subdir"])
        assert_listing_equal(bf.join(dirpath, "*dir"), ["subdir"])
        assert_listing_equal(bf.join(dirpath, "subdir/*dir"), ["subdir/subsubdir"])
        assert_listing_equal(bf.join(dirpath, "subdir/*dir/"), ["subdir/subsubdir"])
        assert_listing_equal(bf.join(dirpath, "su*ir/*dir/"), ["subdir/subsubdir"])


@pytest.mark.parametrize(
    "ctx", [_get_temp_local_path, _get_temp_gcs_path, _get_temp_as_path]
)
def test_rmtree(ctx):
    contents = b"meow!"
    with ctx() as path:
        root = bf.dirname(path)
        destroy_path = bf.join(root, "destroy")
        bf.makedirs(destroy_path)
        save_path = bf.join(root, "save")
        bf.makedirs(save_path)

        # implicit dir
        if not "://" in path:
            bf.makedirs(bf.join(destroy_path, "adir"))
        with bf.BlobFile(bf.join(destroy_path, "adir/b"), "wb") as w:
            w.write(contents)

        # explicit dir
        bf.makedirs(bf.join(destroy_path, "bdir"))
        with bf.BlobFile(bf.join(destroy_path, "bdir/b"), "wb") as w:
            w.write(contents)

        bf.makedirs(bf.join(save_path, "somedir"))
        with bf.BlobFile(bf.join(save_path, "somefile"), "wb") as w:
            w.write(contents)

        def assert_listing_equal(path, desired):
            actual = list(bf.walk(path))
            # ordering of os walk is weird, only compare sorted order
            assert sorted(actual) == sorted(desired), f"{actual} != {desired}"

        assert_listing_equal(
            root,
            [
                (root, ["destroy", "save"], []),
                (destroy_path, ["adir", "bdir"], []),
                (bf.join(destroy_path, "adir"), [], ["b"]),
                (bf.join(destroy_path, "bdir"), [], ["b"]),
                (save_path, ["somedir"], ["somefile"]),
                (bf.join(save_path, "somedir"), [], []),
            ],
        )

        bf.rmtree(destroy_path)

        assert_listing_equal(
            root,
            [
                (root, ["save"], []),
                (save_path, ["somedir"], ["somefile"]),
                (bf.join(save_path, "somedir"), [], []),
            ],
        )


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


def test_more_exists():
    testcases = [
        (AZURE_INVALID_CONTAINER, False),
        (AZURE_INVALID_CONTAINER + "/", False),
        (AZURE_INVALID_CONTAINER + "//", False),
        (AZURE_INVALID_CONTAINER + "/invalid.file", False),
        (GCS_INVALID_BUCKET, False),
        (GCS_INVALID_BUCKET + "/", False),
        (GCS_INVALID_BUCKET + "//", False),
        (GCS_INVALID_BUCKET + "/invalid.file", False),
        # azure uses a hostname for each account, if that host does not exist
        # the request fails due to "[Errno -2] Name or service not known when executing http request"
        # (AZURE_INVALID_ACCOUNT, False),
        # (AZURE_INVALID_ACCOUNT + "/", False),
        # (AZURE_INVALID_ACCOUNT + "//", False),
        # (AZURE_INVALID_ACCOUNT + "/invalid.file", False),
        (AZURE_VALID_CONTAINER, True),
        (AZURE_VALID_CONTAINER + "/", True),
        (AZURE_VALID_CONTAINER + "//", False),
        (AZURE_VALID_CONTAINER + "/invalid.file", False),
        (GCS_VALID_BUCKET, True),
        (GCS_VALID_BUCKET + "/", True),
        (GCS_VALID_BUCKET + "//", False),
        (GCS_VALID_BUCKET + "/invalid.file", False),
        (f"/does-not-exist", False),
        (f"/", True),
    ]
    for path, should_exist in testcases:
        assert bf.exists(path) == should_exist


# @pytest.mark.parametrize(
#     "base_path", [AZURE_INVALID_ACCOUNT, AZURE_INVALID_CONTAINER, GCS_INVALID_BUCKET]
# )
@pytest.mark.parametrize("base_path", [AZURE_INVALID_CONTAINER, GCS_INVALID_BUCKET])
def test_invalid_paths(base_path):
    for suffix in ["", "/", "//", "/invalid.file", "/invalid/dir/"]:
        path = base_path + suffix
        print(path)
        if path.endswith("/"):
            expected_error = IsADirectoryError
        else:
            expected_error = FileNotFoundError
        list(bf.glob(path))
        if suffix == "":
            for pattern in ["*", "**"]:
                try:
                    list(bf.glob(path + pattern))
                except bf.Error as e:
                    assert "Wildcards cannot be used" in e.message
        else:
            for pattern in ["*", "**"]:
                list(bf.glob(path + pattern))
        with pytest.raises(FileNotFoundError):
            list(bf.listdir(path))
        assert not bf.exists(path)
        assert not bf.isdir(path)
        with pytest.raises(expected_error):
            bf.remove(path)
        if suffix in ("", "/"):
            try:
                bf.rmdir(path)
            except bf.Error as e:
                assert "Cannot delete bucket" in e.message
        else:
            bf.rmdir(path)
        with pytest.raises(NotADirectoryError):
            bf.rmtree(path)
        with pytest.raises(FileNotFoundError):
            bf.stat(path)
        bf.get_url(path)
        with pytest.raises(FileNotFoundError):
            bf.md5(path)
        with pytest.raises(bf.Error):
            bf.makedirs(path)
        list(bf.walk(path))
        with tempfile.TemporaryDirectory() as tmpdir:
            local_path = os.path.join(tmpdir, "test.txt")
            with pytest.raises(expected_error):
                bf.copy(path, local_path)
            with open(local_path, "w") as f:
                f.write("meow")
            with pytest.raises(expected_error):
                bf.copy(local_path, path)
        for streaming in [False, True]:
            with pytest.raises(expected_error):
                with bf.BlobFile(path, "rb", streaming=streaming) as f:
                    f.read()
            with pytest.raises(expected_error):
                with bf.BlobFile(path, "wb", streaming=streaming) as f:
                    f.write(b"meow")


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
