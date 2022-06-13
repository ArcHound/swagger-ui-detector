#!/usr/bin/python3

from bs4 import BeautifulSoup
import re
import requests
import urllib.parse

import logging

log = logging.getLogger(__name__)


class SwaggerClassifier:
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
            log.info(f"Unable to detect major swagger-ui version.")
            return 0

    def detect_minor_3(self, url, srcs):
        """Attempts to detect minor version of a v3+ swagger-ui

        Parameters:
        srcs (list(string)): links to javascripts in main swagger-ui page
        url (string): Swagger-ui URL

        Returns:
        version (string): exact semver version of swagger-ui used (or v3 if failed)
        """
        log.debug(srcs)
        result = None
        bundle = [x for x in srcs if "swagger-ui-bundle.js" in str(x)][0]
        swag_bundle_url = ""
        if urllib.parse.urlparse(bundle).scheme != "":
            swag_bundle_url = bundle
        else:
            swag_bundle_url = urllib.parse.urljoin(url, bundle)
        log.debug(swag_bundle_url)
        try:
            # The main idea - there is only one string satisfying the regex below
            # this string without g is a short hash of a commit that is deployed
            response = requests.get(swag_bundle_url, timeout=5)
            matches = re.search(r'"g[a-f0-9]{5,20}"', response.text)
            log.debug(matches[0][2:-1])
            result = self.SGS.get_version_from_shorthash(matches[0][2:-1])
        except requests.exceptions.RequestException as e:
            log.error(f"Failed to get swagger-ui bundle - {str(e)}")
            result = "v3"
        except (IndexError, TypeError) as e:
            log.info(f"Unable to detect minor swagger-ui version.")
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
        log.debug(f"bundle: {bundle}")
        swag_bundle_url = ""
        if urllib.parse.urlparse(bundle).scheme != "":
            swag_bundle_url = bundle
        else:
            swag_bundle_url = urllib.parse.urljoin(
                "https://" + urllib.parse.urlparse(url).netloc, bundle
            )
        log.debug(f"swag_bundle url: {swag_bundle_url}")
        try:
            # The main idea - version is mentioned at the start of swagger-ui.js file
            # go regex that version, it's the first occurence
            response = requests.get(swag_bundle_url, timeout=5)
            matches = re.search(r" * @version v[0-9a-z.]*", response.text)
            result = matches[0].split(" ")[2]
        except requests.exceptions.RequestException as e:
            log.error(f"Failed to get swagger-ui bundle - {str(e)}")
            result = "v2"
        except (IndexError, TypeError) as e:
            log.info(f"Unable to detect minor swagger-ui version.")
            result = "v2"
        return result

    def get_swagger_ui_version(self, url):
        """Attempts to get the swagger-ui version

        Parameters:
        url (string): url to the swagger-ui app

        Returns:
        version (string): semver version of swagger-ui used (hopefully exact) or None
        """
        log.debug(url)
        srcs = []
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, features="html.parser")
            srcs = [x.get("src") for x in soup.find_all("script")]
        except requests.exceptions.RequestException as e:
            log.error(f"Failed to get swagger-ui - {str(e)}")
            return None
        major_version = self.detect_major(srcs)
        if major_version == 3:
            return self.detect_minor_3(url, srcs)
        elif major_version == 2:
            return self.detect_minor_2(url, srcs)
        else:
            return None
