import subprocess as sp
import shlex
import os


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
    print("formatting python files")
    shell(
        [
            "black",
            "--target-version=py37",
            r"--exclude=(\.eggs|\.git|\.hg|\.mypy_cache|\.nox|\.tox|\.venv|_build|buck-out|build|dist|third-party|typings)",
            ".",
        ]
    )

    print("checking python files")
    shell(["pyright", "--project", "."])


if __name__ == "__main__":
    main()
