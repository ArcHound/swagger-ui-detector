import unittest
from src.snyk_parser import SnykParser
import responses

SNYK_URL = "https://snyk.io/vuln/npm:swagger-ui"
SNYK_RESPONSE_FILE = "tests/snyk_response.html"


class TestSnykParser(unittest.TestCase):
    def test_base_url(self):
        sp = SnykParser(SNYK_URL)
        self.assertEqual(sp.base_url, "https://snyk.io/")

    def test_is_version_vulnerable(self):
        scenarios = {
            "simple_positive": {
                "in_version": "v1",
                "vuln_version": "v2",
                "result": True,
            },
            "simple_negative": {
                "in_version": "v2",
                "vuln_version": "v1",
                "result": False,
            },
            "interval_positive": {
                "in_version": "v2",
                "vuln_version": "v1 v3",
                "result": True,
            },
            "interval_negative_less": {
                "in_version": "v1",
                "vuln_version": ">=v2 <v3",
                "result": False,
            },
            "interval_negative_more": {
                "in_version": "v4",
                "vuln_version": ">=v2 <v3",
                "result": False,
            },
            "interval_too_many": {
                "in_version": "v4",
                "vuln_version": ">=v2 <v3 <v5",
                "result": None,
            },
            "no versions": {"in_version": "v4", "vuln_version": "", "result": None},
        }
        for sc_name, scenario in scenarios.items():
            sp = SnykParser(SNYK_URL)
            self.assertEqual(
                sp.is_version_vulnerable(
                    scenario["in_version"], scenario["vuln_version"]
                ),
                scenario["result"],
                msg=sc_name,
            )

    @responses.activate
    def test_load_vulnerabilities_error(self):
        vulnerabilities = []
        responses.add(responses.GET, SNYK_URL, body="error", status=404)
        sp = SnykParser(SNYK_URL)
        sp.load_vulnerabilities()
        self.assertEqual(sp.vulnerabilities, [], msg="load_vulns error")

    @responses.activate
    def test_load_vulnerabilities(self):
        with open(SNYK_RESPONSE_FILE, "r") as f:
            response = f.read()
        responses.add(responses.GET, SNYK_URL, body=response, status=200)
        vulnerabilities = [
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-2314885",
                "name": "User Interface (UI) Misrepresentation of Critical Information",
                "version": "<4.1.3",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-572012",
                "name": "Insecure Defaults",
                "version": "<3.26.1",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-472935",
                "name": "Relative Path Overwrite (RPO)",
                "version": "<3.23.11",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449942",
                "name": "Cross-site Scripting (XSS)",
                "version": ">=2.0.3 <2.0.24",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449941",
                "name": "Cross-site Scripting (XSS)",
                "version": ">=3.0.0 <3.0.13",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449940",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449921",
                "name": "Cross-site Scripting (XSS)",
                "version": "<3.20.9",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449808",
                "name": "Reverse Tabnabbing",
                "version": "<3.18.0",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20171031",
                "name": "Cross-site Scripting (XSS)",
                "version": "<3.4.2",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160901",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.3",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160815",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.1.0",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160725",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160721",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160720",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
        ]
        sp = SnykParser(SNYK_URL)
        sp.load_vulnerabilities()
        self.assertEqual(
            sp.vulnerabilities, vulnerabilities, msg="load vulnerabilities"
        )

    def test_get_vulnerabilities_of_version(self):
        vulnerabilities = [
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-2314885",
                "name": "User Interface (UI) Misrepresentation of Critical Information",
                "version": "<4.1.3",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-572012",
                "name": "Insecure Defaults",
                "version": "<3.26.1",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-472935",
                "name": "Relative Path Overwrite (RPO)",
                "version": "<3.23.11",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449942",
                "name": "Cross-site Scripting (XSS)",
                "version": ">=2.0.3 <2.0.24",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449941",
                "name": "Cross-site Scripting (XSS)",
                "version": ">=3.0.0 <3.0.13",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449940",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449921",
                "name": "Cross-site Scripting (XSS)",
                "version": "<3.20.9",
            },
            {
                "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449808",
                "name": "Reverse Tabnabbing",
                "version": "<3.18.0",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20171031",
                "name": "Cross-site Scripting (XSS)",
                "version": "<3.4.2",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160901",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.3",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160815",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.1.0",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160725",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160721",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
            {
                "link": "https://snyk.io/vuln/npm:swagger-ui:20160720",
                "name": "Cross-site Scripting (XSS)",
                "version": "<2.2.1",
            },
        ]
        scenarios = {
            "ok": {"version": "4.11.1", "vulnerabilities": []},
            "v4": {
                "version": "v4.0",
                "vulnerabilities": [
                    {
                        "link": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-2314885",
                        "name": "User Interface (UI) Misrepresentation of Critical Information",
                        "version": "<4.1.3",
                    }
                ],
            },
        }
        sp = SnykParser(SNYK_URL)
        sp.vulnerabilities = vulnerabilities
        for sc_name, scenario in scenarios.items():
            self.assertEqual(
                set(
                    [
                        v["name"]
                        for v in sp.get_vulnerabilities_of_version(scenario["version"])
                    ]
                ),
                set([v["name"] for v in scenario["vulnerabilities"]]),
            )
