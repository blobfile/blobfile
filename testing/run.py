import os
import time
import argparse
import subprocess as sp

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def run_tests(name, rest, env):
    os.chdir(os.path.dirname(SCRIPT_DIR))

    assert os.path.exists("testing/Dockerfile")

    sp.run(
        ["docker", "build", "--file", "testing/Dockerfile", "--tag", name, "testing"],
        check=True,
    )
    google_credentials_path = os.environ.get(
        "GOOGLE_APPLICATION_CREDENTIALS",
        os.path.expanduser("~/.config/gcloud/application_default_credentials.json"),
    )
    azure_credentials_path = os.environ.get("AZURE_APPLICATION_CREDENTIALS")
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

    print("running static checks")
    start = time.time()

    sp.run(
        docker_cmd
        + [
            "--volume",
            f"{os.getcwd()}:/host",
            name,
            "python",
            "-c",
            open("testing/run-static.py").read(),
        ],
        check=True,
    )
    elapsed = int(time.time() - start)
    print(f"elapsed {elapsed}s")

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
    parser.add_argument("--env", action="append")
    args, rest = parser.parse_known_args()

    run_tests("blobfile", rest, [] if args.env is None else args.env)


if __name__ == "__main__":
    main()
