set -eux
pip install -e .
pytest . -s -k test_glob