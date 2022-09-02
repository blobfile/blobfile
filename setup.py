import os
from setuptools import setup, find_packages


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

README = open(os.path.join(SCRIPT_DIR, "README.md")).read()

with open(os.path.join(SCRIPT_DIR, "blobfile", "VERSION")) as version_file:
    version = version_file.read().strip()


setup_dict = dict(
    name="blobfile",
    version=version,
    description="Read GCS, ABS and local paths with the same interface, clone of tensorflow.io.gfile",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/christopher-hesse/blobfile",
    author="Christopher Hesse",
    license="Public Domain",
    packages=find_packages(),
    install_requires=[
        "pycryptodomex>=3.8",
        "urllib3>=1.25",
        "xmltodict>=0.12.0",
        "filelock>=3.0",
    ],
    python_requires=">=3.7.0",
    # indicate that we have type information
    package_data={"blobfile": ["py.typed", "VERSION"]},
    # mypy cannot find type information in zip files
    zip_safe=False,
)

setup(**setup_dict)
