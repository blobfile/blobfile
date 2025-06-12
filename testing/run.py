import argparse
import os
import subprocess as sp
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def run_tests_direct(rest, env):
    print("running static checks")

    for kv_pair in env:
        k, _, v = kv_pair.partition("=")
        os.environ[k] = v

    start = time.time()
    sp.run(["python", "testing/run-tests.py", *rest], check=True)
    elapsed = int(time.time() - start)
    print(f"elapsed {elapsed}s")


def run_tests_docker(name, rest, env):
    assert os.path.exists("testing/Dockerfile")

    sp.run(["docker", "build", "--file", "testing/Dockerfile", "--tag", name, "."], check=True)
    google_credentials_path = os.environ.get(
        "GOOGLE_APPLICATION_CREDENTIALS",
        os.path.expanduser("~/.config/gcloud/application_default_credentials.json"),
    )
    azure_credentials_path = os.environ["AZURE_APPLICATION_CREDENTIALS"]
    azure_cli_credentials_path = os.path.expanduser("~/.azure")

    aws_credentials_path = os.environ.get(
        "AWS_SHARED_CREDENTIALS_FILE", os.path.expanduser("~/.aws/credentials")
    )

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--workdir",
        "/host",
        # pass in google cloud credentials
        "--volume",
        f"{google_credentials_path}:/root/.config/gcloud/application_default_credentials.json",
        "--env",
        "GOOGLE_APPLICATION_CREDENTIALS=/root/.config/gcloud/application_default_credentials.json",
        # pass in azure
        "--env",
        "AZURE_APPLICATION_CREDENTIALS=/root/azure_credentials.json",
        "--volume",
        f"{azure_credentials_path}:/root/azure_credentials.json",
        "--volume",
        f"{azure_cli_credentials_path}:/root/.azure",
        # pass in aws
        "--env",
        "AWS_SHARED_CREDENTIALS_FILE=/root/.aws/credentials",
        "--volume",
        f"{aws_credentials_path}:/root/.aws/credentials",
    ]

    for e in env:
        docker_cmd.extend(["--env", e])

    start = time.time()
    sp.run(
        docker_cmd
        + [
            "--volume",
            f"{os.getcwd()}:/host",
            name,
            "python",
            "-c",
            open("testing/run-tests.py").read(),
            *rest,
        ],
        check=True,
    )
    elapsed = int(time.time() - start)
    print(f"elapsed {elapsed}s")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--direct", action="store_true", help="run without docker")
    parser.add_argument("--env", action="append", help="key=value environment variables to set")
    args, rest = parser.parse_known_args()

    os.chdir(os.path.dirname(SCRIPT_DIR))

    if args.direct:
        run_tests_direct(rest, [] if args.env is None else args.env)
    else:
        run_tests_docker("blobfile", rest, [] if args.env is None else args.env)


if __name__ == "__main__":
    main()
