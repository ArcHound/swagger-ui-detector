#!/usr/bin/python3

import click
from datetime import datetime, timedelta
import git
import math
import os

from src.git_searcher import GitSearcher
from src.swagger_classifier import SwaggerClassifier
from src.snyk_parser import SnykParser

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


def estimate(delta, percent):
    return math.floor(delta.seconds * (100 - percent) / percent)


def print_vulns(url, ver, vulns, one_line):
    vulnerable = False
    xss = False
    if not one_line:
        click.echo(f"")
    if len(vulns) > 0:
        click.echo(f"URL {url} - [VULNERABLE] Version {ver}")
        if one_line:
            return
        click.echo(f"---------")
        click.echo(f"")
        vulnerable = True
        click.echo(f"This swagger-ui is vulnerable to:")
        for v in vulns:
            name = v["name"]
            link = v["link"]
            click.echo(f"  - [{name}]({link})")
    elif ver is not None:
        click.echo(f"URL {url} - [OK] Version {ver}")
        if one_line:
            return
        click.echo(f"---------")
        click.echo(f"This swagger-ui is not vulnerable.")
    elif ver is None:
        click.echo(f"URL {url} - [UNKNOWN] Version unknown.")
        if one_line:
            return
        click.echo(f"---------")
    click.echo(f"")


@click.command()
@click.option(
    "--swagger-ui-repo",
    default="./swagger-ui",
    show_default=True,
    help="Local repository containing swagger-ui",
)
@click.option(
    "--swagger-ui-git-source",
    default="https://github.com/swagger-api/swagger-ui",
    show_default=True,
    help="GIT URL of swagger-ui",
)
@click.option(
    "--url-list",
    prompt_required=True,
    help="File containing URLs pointing to swagger-uis",
)
@click.option(
    "--snyk-url",
    default="https://snyk.io/vuln/npm:swagger-ui",
    show_default=True,
    help="Snyk URL containing swagger-ui vulnerabilities",
)
@click.option(
    "--get-repo",
    is_flag=True,
    flag_value=True,
    default=True,
    show_default=True,
    help="Boolean, specifies whether to get the swagger-ui repo from github",
)
@click.option(
    "--one-line",
    is_flag=True,
    flag_value=True,
    default=False,
    show_default=True,
    help="Boolean, whether to print one line of output per URL.",
)
def main(
    swagger_ui_repo, swagger_ui_git_source, url_list, snyk_url, get_repo, one_line
):
    # Check if user inputed sane options
    if get_repo:
        if os.path.isdir(swagger_ui_repo):
            logging.info("Directory for swagger-ui repo already exists.")
            if len(os.listdir(swagger_ui_repo)) == 0:
                logging.info("Directory is empty.")
                logging.warn(
                    "Cloning swagger-ui repository, this might take a while..."
                )
                git.Repo.clone_from(swagger_ui_git_source, swagger_ui_repo)
            else:
                logging.info("Directory is not empty.")
                try:
                    repo = git.Repo(swagger_ui_repo)
                    _ = repo.git_dir
                    if swagger_ui_git_source in [
                        url for remote in repo.remotes for url in remote.urls
                    ]:
                        logging.info(
                            f"Directory is a valid swagger-ui dir with remote {swagger_ui_git_source}"
                        )
                    else:
                        logging.info(
                            f"Remote {swagger_ui_git_source} not found in directory {swagger_ui_repo}. Aborting!"
                        )
                        return
                except git.exc.InvalidGitRepositoryError:
                    logging.info("Directory is not a git repository! Aborting.")
                    return
        else:
            logging.warn("Cloning swagger-ui repository, this might take a while...")
            git.Repo.clone_from(swagger_ui_git_source, swagger_ui_repo)
    logging.info(f"Using local swagger-ui repository at {swagger_ui_repo}")
    if url_list is None:
        logging.error(f"--url-list option is required! Aborting.")
        return
    if not os.path.isfile(url_list):
        logging.error(f"URL File {url_list} doesn't exist! Aborting.")
        return

    # Start once sane options have been verified
    # for some reason these are not in the repository
    swagger_ui_special_cases = {"a6656ced": "v3.17.1", "7f92cd3c": "v3.7.0"}
    gs = GitSearcher(repo=swagger_ui_repo, special_cases=swagger_ui_special_cases)
    s = SwaggerClassifier(gs)
    p = SnykParser(vuln_url=snyk_url)
    p.load_vulnerabilities()
    with open(url_list, "r") as f:
        lines = f.read().splitlines()
        logging.info(f"Got {len(lines)} URLs to try...")
        checks = {math.floor(len(lines) * x / 20): x * 5 for x in range(20)}
        counter = 0
        start_time = datetime.now()
        for url in lines:
            if counter in checks and counter != 0:
                delta = datetime.now() - start_time
                sec = estimate(delta, checks[counter])
                logging.info(f"Status: {checks[counter]}%, estimated {sec}s left.")
            counter += 1
            ver = s.get_swagger_ui_version(url)
            vulns = []
            if ver is not None and ver != "None":
                vulns = p.get_vulnerabilities_of_version(ver)
            print_vulns(url, ver, vulns, one_line)
    logging.info("Done.")
