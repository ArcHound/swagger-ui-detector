#!/usr/bin/python3

import click
from datetime import datetime, timedelta
import git
import math
import os

from git_searcher import GitSearcher
from swagger_classifier import SwaggerClassifier
from snyk_parser import SnykParser

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


def estimate(delta, percent):
    return math.floor(delta.seconds * (100 - percent) / percent)

def print_vulns(url, ver, vulns):
    vulnerable = False
    xss = False
    click.echo(f"")
    if len(vulns) > 0:
        click.echo(f"URL {url} - [VULNERABLE] Version {ver}")
        click.echo(f"---------")
        click.echo(f"")
        vulnerable = True
        click.echo(f"This swagger-ui is vulnerable to:")
        for v in vulns:
            name = v["name"]
            link = v["link"]
            click.echo(f"  - [{name}]({link})")
    else:
        click.echo(f"URL {url} - [OK] Version {ver}")
        click.echo(f"---------")
        click.echo(f"This swagger-ui is not vulnerable.")
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
    default="https://security.snyk.io/vuln/npm?search=swagger-ui",
    show_default=True,
    help="Snyk URL containing swagger-ui vulnerabilities",
)
@click.option(
    "--get-repo",
    default=True,
    show_default=True,
    help="Boolean, specifies whether should the script get swagger-ui repo from github",
)
def main(swagger_ui_repo, swagger_ui_git_source, url_list, snyk_url, get_repo):
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
                # TODO: check for repo
        else:
            logging.warn("Cloning swagger-ui repository, this might take a while...")
            git.Repo.clone_from(swagger_ui_git_source, swagger_ui_repo)
    logging.info(f"Using local swagger-ui repository at {swagger_ui_repo}")
    # for some reason these are not in the repository
    swagger_ui_special_cases = {"a6656ced": "v3.17.1", "7f92cd3c": "v3.7.0"}
    gs = GitSearcher(repo=swagger_ui_repo, special_cases=swagger_ui_special_cases)
    s = SwaggerClassifier(gs)
    p = SnykParser(vuln_url=snyk_url)
    p.load_vulnerabilities()
    if url_list is None:
        logging.error(f"--url-list option is required! Aborting.")
        return
    if not os.path.isfile(url_list):
        logging.error(f"URL File {url_list} doesn't exist! Aborting.")
        return
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
            if ver is not None and ver != "None":
                vulns = p.get_vulnerabilities_of_version(ver)
                print_vulns(url, ver, vulns)
            else:
                logging.info(f"Failed to detect version of {url}")
    logging.info("Done.")
