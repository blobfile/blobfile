import multiprocessing as mp
import os
import signal
import time
from typing import cast

import blobfile as bf

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def do_write(path: str, streaming: bool, partial_writes_on_exc: bool) -> None:
    data = [b"ab" * 64 * 1024, b"cd" * 64 * 1024, b"ef" * 64 * 1024, b"gh" * 64 * 1024]
    print(f"child: starting write (streaming={streaming}, partial={partial_writes_on_exc})")
    with bf.BlobFile(
        path, "wb", streaming=streaming, partial_writes_on_exc=partial_writes_on_exc
    ) as f:
        f.write(b"".join(data))
        print("child: wrote data, sleeping")
        time.sleep(10)
        print("child: done sleeping")


def run_case(path: str, streaming: bool, partial_writes_on_exc: bool) -> bool:
    if bf.exists(path):
        bf.remove(path)

    proc = mp.Process(target=do_write, args=(path, streaming, partial_writes_on_exc))
    proc.start()

    print("parent: sleeping for 2 seconds")
    time.sleep(2)
    print(f"parent: interrupting process {proc.pid}")

    # SIGKILL is too aggressive and doesn't cause stack unwinding.
    os.kill(cast(int, proc.pid), signal.SIGINT)
    proc.join()
    print(f"parent: writer process joined: {proc.exitcode}")

    exists = bf.exists(path)
    expected_exists = partial_writes_on_exc
    status = f"{GREEN}PASS{RESET}" if exists == expected_exists else f"{RED}FAIL{RESET}"
    print(
        f"parent: exists={exists} expected={expected_exists} -> {status} "
        f"(streaming={streaming}, partial={partial_writes_on_exc})"
    )
    return exists == expected_exists


if __name__ == "__main__":
    base_path = os.environ.get("BLOBFILE_TEST_BASE_PATH")
    if not base_path:
        raise SystemExit("Set BLOBFILE_TEST_BASE_PATH to your test blob prefix")
    cases = [(True, True), (True, False), (False, True), (False, False)]
    all_ok = True
    for streaming, partial in cases:
        path = f"{base_path}/b_stream_{int(streaming)}_partial_{int(partial)}.txt"
        print("=" * 60)
        print(f"case: streaming={streaming} partial={partial}")
        ok = run_case(path, streaming, partial)
        all_ok = all_ok and ok

    print("=" * 60)
    overall = f"{GREEN}PASS{RESET}" if all_ok else f"{RED}FAIL{RESET}"
    print("overall:", overall)
