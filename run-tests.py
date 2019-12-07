import subprocess as sp
import sys

run = lambda cmd: sp.run(cmd, shell=True, check=True)
sp.run(["pip", "install", "-e", "."], check=True)
sp.run(
    ["pytest", "blobfile", "--typeguard-packages=blobfile"] + sys.argv[1:], check=True
)
