import subprocess as sp

run = lambda cmd: sp.run(cmd, shell=True, check=True)
run("pip install -e .")
run("pytest blobfile --typeguard-packages=blobfile")
