import subprocess as sp
import sys

sp.run(["pip", "install", "-e", "."], check=True)
sp.run(
    [
        "pytest",
        "blobfile",
        "--typeguard-packages=blobfile",
        "-s",
        "-k",
        "test_glob[_get_temp_gcs_path]",
    ]
    + sys.argv[1:],
    check=True,
)
