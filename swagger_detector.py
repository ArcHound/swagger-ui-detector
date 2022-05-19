#!/usr/bin/python3

import csv
import requests
import urllib.parse
from bs4 import BeautifulSoup
import sys
import git
import re
import math
from packaging import version
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("debug.log"), logging.StreamHandler()],
)


SWAGGER_UI_REPO = "./swagger-ui"
# SWAGGERS_FILE = "./simple_and_nuclei_grouped.log"
SWAGGERS_FILE = "./urls_debug.txt"
SNYK_URL = "https://security.snyk.io/vuln/npm?search=swagger-ui"
OUTFILE = "./swaggers_rated_debug.csv"


class SnykParser:
    """Object scraping snyk to get data about swagger-ui vulnerabilities

    Parameters:
    vuln_url (string): Url containing the table of vulnerabilities
    """

    def __init__(self, vuln_url=SNYK_URL):
        self.vuln_url = vuln_url
        self.base_url = f"{urllib.parse.urlparse(vuln_url).scheme}://{urllib.parse.urlparse(vuln_url).netloc}/"

    def load_vulnerabilities(self):
        """Parse html table into vulnerabilities using heuristics (i.e. look at it and figure out what you want)"""
        logging.info(f"Load vulnerabilities from {self.vuln_url}...")
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

    def __init__(self, repo=SWAGGER_UI_REPO):
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
        if len(versions) > 0:
            if versions[0] == "$GIT_TAG":
                return versions[1]
            else:
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


if __name__ == "__main__":
    g = SwaggerGitSearcher()
    s = SwaggerDetector(g)
    p = SnykParser()
    p.load_vulnerabilities()
    # print("url;version")
    with open(SWAGGERS_FILE, "r") as f:
        with open(OUTFILE, "w") as csv_outfile:
            writer = csv.DictWriter(
                csv_outfile,
                delimiter=";",
                quotechar='"',
                fieldnames=["url", "version", "xss", "known_vulnerabilities"],
            )
            writer.writeheader()
            row = dict()

            lines = f.read().splitlines()

            checks = {math.floor(len(lines) * x / 100): x for x in range(100)}
            counter = 0

            for url in lines:
                if counter in checks:
                    logging.info(f"Status: {checks[counter]}%")
                row["url"] = url
                row["version"] = s.get_swagger_ui_version(url)
                if row["version"] is not None and row["version"] != "None":
                    vulns = p.get_vulnerabilities_of_version(row["version"])
                    if len([x for x in vulns if "XSS" in x["name"]]) > 0:
                        row["known_vulnerabilities"] = True
                        row["xss"] = True
                    else:
                        row["known_vulnerabilities"] = True
                        row["xss"] = False
                else:
                    row["known_vulnerabilities"] = False
                    row["xss"] = False
                writer.writerow(row)
                counter += 1
