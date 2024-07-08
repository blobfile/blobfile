import time
from typing import List
from blobfile import _auto_parallelizer as parallelizer


class ArrayInput(parallelizer.SplittableInput):
    def __init__(self, arr: List[int]):
        self.arr = arr

    def is_splittable(self) -> bool:
        return len(self.arr) > 1

    def split(self) -> List["ArrayInput"]:
        bottom_half = self.arr[: len(self.arr) // 2]
        top_half = self.arr[len(self.arr) // 2 :]
        res = []
        if len(bottom_half) > 0:
            res.append(ArrayInput(bottom_half))
        if len(top_half) > 0:
            res.append(ArrayInput(top_half))
        return res


def _long_running_function(inp: ArrayInput) -> int:
    for _ in inp.arr:
        time.sleep(0.1)
    return sum(inp.arr)


def _slow_long_running_function(inp: ArrayInput) -> int:
    time.sleep(5)
    return _long_running_function(inp)


def _merge(results: List[int]):
    return sum(results)


def test_basic():
    inp = ArrayInput(list(range(100)))

    result = parallelizer.parallelize(_long_running_function, inp, _merge)

    assert result == sum(inp.arr)


def test_empty_input():
    inp = ArrayInput([])
    result = parallelizer.parallelize(_long_running_function, inp, _merge)

    assert result == 0


def test_slow_unsplittable_input():
    inp = ArrayInput([4])
    result = parallelizer.parallelize(_slow_long_running_function, inp, _merge)
    assert result == sum(inp.arr)
