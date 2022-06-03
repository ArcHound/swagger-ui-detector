#!/usr/bin/python3

from bs4 import BeautifulSoup
from packaging import version
import requests
import urllib.parse

import logging

log = logging.getLogger(__name__)


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
        log.info(f"Load vulnerabilities from {self.vuln_url} ...")
        self.vulnerabilities = []
        try:
            resp = requests.get(self.vuln_url)
        except requests.exceptions.RequestException as e:
            log.error(
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
                tr.find_all("td")[1].find("span", class_="semver").text.strip()
            )
            self.vulnerabilities.append(new_vuln)
        log.info(f"Loaded {len(self.vulnerabilities)} vulnerabilities.")

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


if __name__ == "__main__":
    snyk_url = "https://snyk.io/vuln/npm:swagger-ui"
    p = SnykParser(snyk_url)
    p.load_vulnerabilities()
    print(p.get_vulnerabilities_of_version("v2.2.2"))
