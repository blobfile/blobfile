"""
Module for automatically parallelizing a function that takes a long time to run but can be split into smaller tasks.

See doc string on `parallelize` for more details.
"""
import abc
from typing import Callable, Any, Generator, List
import concurrent.futures
import time
from dataclasses import dataclass
import multiprocessing
from threading import Event
from typing import TypeVar


@dataclass
class _FuncResult:
    did_complete: bool
    result: Any


@dataclass
class _CancellableFuncCall:
    func: Callable[[Any], Any]
    cancel_event: Event

    def __call__(self, input: Any) -> _FuncResult:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(self.func, input)
        while not self.cancel_event.is_set():
            if future.done():
                res = future.result()
                if isinstance(res, Generator):
                    res_list = []
                    for r in res:
                        res_list.append(r)
                        if self.cancel_event.is_set():
                            return _FuncResult(False, None)
                    return _FuncResult(True, res_list)
                else:
                    return _FuncResult(True, res)
            self.cancel_event.wait(0.5)
        return _FuncResult(False, None)


class SplittableInput(abc.ABC):
    def is_splittable(self) -> bool:
        raise NotImplementedError()

    def split(self) -> List["SplittableInput"]:
        raise NotImplementedError()


SI = TypeVar("SI", bound="SplittableInput")


@dataclass
class _RunningTask:
    future: concurrent.futures.Future[Any]
    input: SI
    start_time: float
    cancel_event: Event


def parallelize(
    func: Callable[[SI], Any],
    root_input: SI,
    join: Callable[[List[Any]], Any],
    min_time_per_task_secs: float = 1,
    target_parallelism: int = 5,
) -> Any:
    """Parallelize a function that takes a long time to run but can be split into smaller tasks.

    General idea is to split the input until we hit target parallelism. Then, merge all the results together.

    Pseudocode:
    Start function on root_input
    While there are tasks to run or tasks running:
       If we're running target_parallelism tasks, wait a bit.
       If there are tasks to run, and we're not running target_parallelism tasks, run a task.
       If a task is done, add the result to the results list.
       If we have fewer than target_parallelism tasks running, but tasks are running,
          cancel the oldest task and split its input.
    Merge all the results together and return.

    """

    results = []
    manager = multiprocessing.Manager()

    with concurrent.futures.ProcessPoolExecutor(max_workers=target_parallelism) as executor:
        tasks = [root_input]
        running_tasks: list[_RunningTask] = []
        while len(tasks) > 0 or len(running_tasks) > 0:
            # Pull results from completed tasks
            for task in running_tasks:
                if task.future.done():
                    res: _FuncResult = task.future.result()
                    assert res.did_complete
                    results.append(res.result)
                    running_tasks.remove(task)

            # If we're at our target parallelism, wait a bit
            if len(running_tasks) >= target_parallelism:
                time.sleep(0.5)
                continue

            # If we're below desired parallelism, run a task or split a running task
            while len(running_tasks) < target_parallelism:
                if len(tasks) > 0:
                    task = tasks.pop()
                    cancel_event = manager.Event()
                    func_call = _CancellableFuncCall(func, cancel_event)
                    future = executor.submit(func_call, task)
                    running_tasks.append(_RunningTask(future, task, time.time(), cancel_event))
                else:
                    for task in running_tasks:
                        if task.future.done():
                            continue

                        if (
                            task.input.is_splittable()
                            and time.time() - task.start_time > min_time_per_task_secs
                        ):
                            task.cancel_event.set()
                            running_tasks.remove(task)
                            tasks.extend(task.input.split())
                            break

                    # If we didn't manage to cancel a task, it might be because the tasks are done,
                    # and we just need to pull the results
                    if len(tasks) == 0:
                        break

    return join(results)
