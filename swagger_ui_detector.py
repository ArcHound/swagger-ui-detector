#!/usr/bin/python3

from bs4 import BeautifulSoup
import click
import csv
from datetime import datetime, timedelta
import git
import math
import os
from packaging import version
import re
import requests
import sys
import urllib.parse

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


class SnykParser:
    """Object scraping snyk to get data about swagger-ui vulnerabilities

    Parameters:
    vuln_url (string): Url containing the table of vulnerabilities
    """

    def __init__(self, vuln_url):
        self.vuln_url = vuln_url
        self.base_url = f"{urllib.parse.urlparse(vuln_url).scheme}://{urllib.parse.urlparse(vuln_url).netloc}/"

    def load_vulnerabilities(self):
        """Parse html table into vulnerabilities using heuristics (i.e. look at it and figure out what you want)"""
        logging.info(f"Load vulnerabilities from {self.vuln_url} ...")
        self.vulnerabilities = []
        try:
            resp = requests.get(self.vuln_url)
        except requests.exceptions.RequestException as e:
            logging.error(
                f"Failed to load vulnerabilities from {self.vuln_url} - {str(e)}."
            )
        soup = BeautifulSoup(resp.text, features="lxml")
        for tr in soup.find("table").find("tbody").find_all("tr"):
            new_vuln = dict()
            new_vuln["link"] = urllib.parse.urljoin(
                self.base_url, tr.find_all("td")[0].find("a").get("href")
            )
            new_vuln["name"] = tr.find_all("td")[0].find("a").text.strip()
            new_vuln["version"] = (
                tr.find_all("td")[1]
                .find("span", class_="vulns-table__semver")
                .text.strip()
            )
            self.vulnerabilities.append(new_vuln)
        logging.info(f"Loaded {len(self.vulnerabilities)} vulnerabilities.")

    def is_version_vulnerable(self, in_version, vuln_version):
        """Check whether in_version is less than vuln_version or whether it is in between vuln versions (assuming all of these are semvers)

        Parameters:
        in_version (string): semver version to check
        vuln_version (string): either a single semver version with optional comparison indicators or two such versions

        Returns:
        Boolean if we can decide (single version, interval of versions), None otherwise
        """
        vsplit = vuln_version.split(" ")
        if len(vsplit) == 0:
            return None
        vuln_versions = [x.translate(str.maketrans("", "", "=<>")) for x in vsplit]
        if len(vuln_versions) == 1:
            return version.parse(in_version) <= version.parse(vuln_versions[0])
        elif len(vuln_versions) == 2:
            return (version.parse(vuln_versions[0]) <= version.parse(in_version)) and (
                version.parse(in_version) <= version.parse(vuln_versions[1])
            )
        else:
            return None

    def get_vulnerabilities_of_version(self, in_version):
        """For a given version return a list of vulnerabilities that are applicable
        Parameters:
        in_version (string): semver version to check

        Returns:
        list(dictionaries with keys: "link", "name", "version") containing applicable vulnerabilities
        """
        result = []
        for vuln in self.vulnerabilities:
            if self.is_version_vulnerable(in_version, vuln["version"]):
                result.append(vuln)
        return result


class SwaggerGitSearcher:
    """Object to search the repository for a hash, returns version of software that has it

    Parameters:
    repo (string): Path to the git repository containing swagger-ui
    """

    def __init__(self, repo):
        """Constructor

        Parameters:
        repo (string): Path to the git repository containing swagger-ui
        """
        self.g = git.cmd.Git(repo)

    def get_version_from_shorthash(self, shorthash):
        """Searches for the shorthash in the repo attempting to return the version containing the commit

        Parameters:
        shorthash (string): hash of the commit identified in the swagger

        Returns:
        version (string): version containing commit specified by shorthash
        """
        # for some reason these are not in the repository
        if shorthash == "a6656ced":
            return "v3.17.1"
        elif shorthash == "7f92cd3c":
            return "v3.7.0"
        versions = self.g.tag(contains=shorthash).split("\n")
        if "$GIT_TAG" in versions:
            versions.remove("$GIT_TAG")
        if len(versions) > 0:
            versions.sort(key=version.parse)
            return versions[0]
        else:
            logging.info(f'Unable to find version for tag "{shorthash}".')
            return None


class SwaggerDetector:
    """Attempts to detect swagger version based on a set of heuristics, needs a git repository of swagger-ui"""

    def __init__(self, git_obj):
        self.SGS = git_obj

    def detect_major(self, srcs):
        """Attempts to detect major version of swagger-ui used based on script links in main swagger-ui page

        Parameters:
        srcs (list(string)): links to javascripts in main swagger-ui page

        Returns:
        int: Major version (>=3, <=2 or 0 if fail)
        """
        # The idea is - if it gets swagger-ui-bundle.js is present then it's at least v3
        if len([x for x in srcs if "swagger-ui-bundle.js" in str(x)]) > 0:
            return 3
        elif len([x for x in srcs if "swagger-ui.js" in str(x)]) > 0:
            return 2
        else:
            logging.info(f"Unable to detect major swagger-ui version.")
            return 0

    def detect_minor_3(self, url, srcs):
        """Attempts to detect minor version of a v3+ swagger-ui

        Parameters:
        srcs (list(string)): links to javascripts in main swagger-ui page
        url (string): Swagger-ui URL

        Returns:
        version (string): exact semver version of swagger-ui used (or v3 if failed)
        """
        logging.debug(srcs)
        result = None
        bundle = [x for x in srcs if "swagger-ui-bundle.js" in str(x)][0]
        swag_bundle_url = ""
        if urllib.parse.urlparse(bundle).scheme != "":
            swag_bundle_url = bundle
        else:
            swag_bundle_url = urllib.parse.urljoin(url, bundle)
        logging.debug(swag_bundle_url)
        try:
            # The main idea - there is only one string satisfying the regex below
            # this string without g is a short hash of a commit that is deployed
            response = requests.get(swag_bundle_url, timeout=5)
            matches = re.search(r'"g[a-f0-9]{5,20}"', response.text)
            logging.debug(matches[0][2:-1])
            result = self.SGS.get_version_from_shorthash(matches[0][2:-1])
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to get swagger-ui bundle - {str(e)}")
            result = "v3"
        except (IndexError, TypeError) as e:
            logging.info(f"Unable to detect minor swagger-ui version.")
            result = "v3"
        return result

    def detect_minor_2(self, url, srcs):
        """Attempts to detect minor version of a v2 swagger-ui

        Parameters:
        srcs (list(string)): links to javascripts in main swagger-ui page
        url (string): Swagger-ui URL

        Returns:
        version (string): exact semver version of swagger-ui used (or v2 if failed)
        """
        result = None
        bundle = [x for x in srcs if "swagger-ui.js" in str(x)][0]
        logging.debug(f"bundle: {bundle}")
        swag_bundle_url = ""
        if urllib.parse.urlparse(bundle).scheme != "":
            swag_bundle_url = bundle
        else:
            swag_bundle_url = urllib.parse.urljoin(
                "https://" + urllib.parse.urlparse(url).netloc, bundle
            )
        logging.debug(f"swag_bundle url: {swag_bundle_url}")
        try:
            # The main idea - version is mentioned at the start of swagger-ui.js file
            # go regex that version, it's the first occurence
            response = requests.get(swag_bundle_url, timeout=5)
            matches = re.search(r" * @version v[0-9a-z.]*", response.text)
            result = matches[0].split(" ")[2]
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to get swagger-ui bundle - {str(e)}")
            result = "v2"
        except (IndexError, TypeError) as e:
            logging.info(f"Unable to detect minor swagger-ui version.")
            result = "v2"
        return result

    def get_swagger_ui_version(self, url):
        """Attempts to get the swagger-ui version

        Parameters:
        url (string): url to the swagger-ui app

        Returns:
        version (string): semver version of swagger-ui used (hopefully exact) or None
        """
        logging.debug(url)
        srcs = []
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, features="lxml")
            srcs = [x.get("src") for x in soup.find_all("script")]
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to get swagger-ui - {str(e)}")
            return None
        major_version = self.detect_major(srcs)
        if major_version == 3:
            return self.detect_minor_3(url, srcs)
        elif major_version == 2:
            return self.detect_minor_2(url, srcs)
        else:
            return None


def estimate(delta, percent):
    return math.floor(delta.seconds * (100 - percent) / percent)


def print_vulns(url, ver, vulns):
    click.echo(f"")
    click.echo(f"URL {url}")
    click.echo(f"---------")
    click.echo(f"Detected swagger-ui version {ver}.")
    click.echo(f"")
    vulnerable = False
    xss = False
    if len(vulns) > 0:
        vulnerable = True
        click.echo(f"This swagger-ui is vulnerable to:")
        for v in vulns:
            name = v["name"]
            link = v["link"]
            click.echo(f"  - [{name}]({link})")
    else:
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
    g = SwaggerGitSearcher(repo=swagger_ui_repo)
    s = SwaggerDetector(g)
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
