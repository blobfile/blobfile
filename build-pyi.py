import subprocess as sp
import tempfile
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

with tempfile.TemporaryDirectory() as tmpdir:
    previous_cwd = os.getcwd()
    os.chdir(tmpdir)
    # TODO: require mypy for this
    module_dirpath = os.path.join(SCRIPT_DIR, "blobfile")
    output_dirpath = os.path.join("out", "blobfile")
    print(module_dirpath)
    sp.run(["stubgen", module_dirpath], check=True)
    for root, dirnames, filenames in os.walk(output_dirpath):
        for filename in filenames:
            input_path = os.path.join(root, filename)
            relpath = os.path.relpath(input_path, output_dirpath)
            output_path = os.path.join(module_dirpath, relpath)
            preamble = "# this file was generated with build-pyi.py\n"
            pyi_in_path = output_path.replace(".pyi", ".pyi.in")
            if os.path.exists(pyi_in_path):
                with open(pyi_in_path, "r") as f:
                    preamble += f.read()
            with open(input_path, "r") as f:
                contents = preamble + f.read()
            with open(output_path, "w") as f:
                f.write(contents)
    os.chdir(previous_cwd)
