import time
from typing import List
from blobfile import _auto_parallelizer as parallelizer


def _long_running_function(arr: List[int]):
    for _ in arr:
        time.sleep(0.1)
    return sum(arr)

def _split(arr: List[int]):
    bottom_half = arr[: len(arr) // 2]
    top_half = arr[len(arr) // 2 :]
    res = []
    if len(bottom_half) > 0:
        res.append(bottom_half)
    if len(top_half) > 0:
        res.append(top_half)
    return res

def _merge(results: List[int]):
    return sum(results)


def test_basic():
    arr = list(range(100))

    result = parallelizer.parallelize(_long_running_function, arr, _split, _merge)

    assert result == sum(arr)


def test_empty_input():
    arr = []

    result = parallelizer.parallelize(_long_running_function, arr, _split, _merge)

    assert result == sum(arr)


def test_single_input():
    arr = [1]

    result = parallelizer.parallelize(_long_running_function, arr, _split, _merge)

    assert result == sum(arr)


def test_odd_input():
    arr = list(range(101))

    result = parallelizer.parallelize(_long_running_function, arr, _split, _merge)

    assert result == sum(arr)