import subprocess as sp
import os

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # disable tensorflow warnings

run = lambda cmd: sp.run(cmd, shell=True, check=True)
run("pip install -e .")
# run("pytest blobfile --typeguard-packages=blobfile -s -k test_glob")
run("pytest blobfile --typeguard-packages=blobfile -s -k test_rmtree")
# run("pytest blobfile --typeguard-packages=blobfile")
