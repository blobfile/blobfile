import subprocess as sp
import shlex
import os
import shutil
import argparse


def shell(cmd):
    print("SHELL: " + " ".join(shlex.quote(p) for p in cmd))
    sp.run(cmd, check=True)


def format_files(dirpath, extensions, command):
    for root, dirs, filenames in os.walk(dirpath):
        for filename in filenames:
            _name, ext = os.path.splitext(filename)
            if ext in extensions:
                sp.run(command + [os.path.join(root, filename)], check=True)
        if "third-party" in dirs:
            dirs.remove("third-party")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-only", action="store_true", help="only check files, don't format them"
    )
    args = parser.parse_args()

    assert (
        open("env.yaml").read() == open("testing/env.yaml").read()
    ), "env.yaml files are out of sync"

    print("formatting python files")
    black_cmd = ["black"]
    if args.check_only:
        black_cmd += ["--check"]
    black_cmd += [
        "--target-version=py37",
        r"--exclude=(\.eggs|\.git|\.hg|\.mypy_cache|\.nox|\.tox|\.venv|_build|buck-out|build|dist|third-party|typings)",
        ".",
    ]
    shell(black_cmd)

    print("checking python files")
    shell([shutil.which("pyright"), "--project", "."])


if __name__ == "__main__":
    main()
