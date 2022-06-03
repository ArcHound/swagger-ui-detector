import unittest
from src.swagger_classifier import SwaggerClassifier
import responses
import requests

SWAGGER_V2 = "tests/swagger-ui.js"
SWAGGER_V3 = "tests/swagger-ui-bundle.js"
SWAGGER_URL = "https://swagger-test-not-a-real-url-for-sure.com"


class GitMock:
    versions = {"fdef4ea": "v3.52.1"}

    def get_version_from_shorthash(self, sh):
        return self.versions[sh]


class TestSwaggerClassifier(unittest.TestCase):
    def test_detect_major(self):
        scenarios = {
            "v2": {"srcs": ["swagger-ui.js"], "version": 2},
            "v3": {"srcs": ["swagger-ui-bundle.js"], "version": 3},
            "unknown": {"srcs": ["whatever.js"], "version": 0},
            "empty": {"srcs": [], "version": 0},
        }
        for sc_name, scenario in scenarios.items():
            sc = SwaggerClassifier(None)
            self.assertEqual(
                sc.detect_major(scenario["srcs"]), scenario["version"], msg=sc_name
            )

    @responses.activate
    def test_detect_minor_2(self):
        with open(SWAGGER_V2, "r") as f:
            swagger = f.read()
        responses.add(
            responses.GET, f"{SWAGGER_URL}/swagger-ui.js", body=swagger, status=200
        )
        responses.add(
            responses.GET,
            f"https://error.com/swagger-ui.js",
            body=requests.exceptions.RequestException("timeout"),
        )
        responses.add(
            responses.GET,
            f"https://invalid.com/swagger-ui.js",
            body="error",
            status=200,
        )
        scenarios = {
            "valid": {
                "url": SWAGGER_URL,
                "srcs": ["swagger-ui.js"],
                "github_obj": None,
                "result": "v2.2.9",
            },
            "valid_full_url": {
                "url": SWAGGER_URL,
                "srcs": [f"{SWAGGER_URL}/swagger-ui.js"],
                "github_obj": None,
                "result": "v2.2.9",
            },
            "invalid_bundle": {
                "url": "https://invalid.com",
                "srcs": [f"swagger-ui.js"],
                "github_obj": None,
                "result": "v2",
            },
            "error_bundle": {
                "url": "https://error.com",
                "srcs": [f"swagger-ui.js"],
                "github_obj": None,
                "result": "v2",
            },
        }
        for sc_name, scenario in scenarios.items():
            srcs = scenario["srcs"]
            url = scenario["url"]
            sc = SwaggerClassifier(scenario["github_obj"])
            self.assertEqual(
                sc.detect_minor_2(url, srcs),
                scenario["result"],
                msg=f"detect_minor_2: {sc_name}",
            )

    @responses.activate
    def test_detect_minor_3(self):
        with open(SWAGGER_V3, "r") as f:
            swagger = f.read()
        responses.add(
            responses.GET,
            f"{SWAGGER_URL}/swagger-ui-bundle.js",
            body=swagger,
            status=200,
        )
        responses.add(
            responses.GET,
            f"https://error.com/swagger-ui-bundle.js",
            body=requests.exceptions.RequestException("timeout"),
        )
        responses.add(
            responses.GET,
            f"https://invalid.com/swagger-ui-bundle.js",
            body="error",
            status=200,
        )
        scenarios = {
            "valid": {
                "url": SWAGGER_URL,
                "srcs": ["swagger-ui-bundle.js"],
                "github_obj": GitMock(),
                "result": "v3.52.1",
            },
            "valid_full_url": {
                "url": SWAGGER_URL,
                "srcs": [f"{SWAGGER_URL}/swagger-ui-bundle.js"],
                "github_obj": GitMock(),
                "result": "v3.52.1",
            },
            "invalid_bundle": {
                "url": "https://invalid.com",
                "srcs": [f"swagger-ui-bundle.js"],
                "github_obj": None,
                "result": "v3",
            },
            "error_bundle": {
                "url": "https://error.com",
                "srcs": [f"swagger-ui-bundle.js"],
                "github_obj": None,
                "result": "v3",
            },
        }
        for sc_name, scenario in scenarios.items():
            srcs = scenario["srcs"]
            url = scenario["url"]
            sc = SwaggerClassifier(scenario["github_obj"])
            self.assertEqual(
                sc.detect_minor_3(url, srcs),
                scenario["result"],
                msg=f"detect_minor_3: {sc_name}",
            )

    @responses.activate
    def test_get_swagger_ui_version(self):
        with open(SWAGGER_V2, "r") as f:
            swagger = f.read()
        responses.add(
            responses.GET, f"{SWAGGER_URL}_v2/swagger-ui.js", body=swagger, status=200
        )
        with open(SWAGGER_V3, "r") as f:
            swagger = f.read()
        responses.add(
            responses.GET,
            f"{SWAGGER_URL}_v3/swagger-ui-bundle.js",
            body=swagger,
            status=200,
        )
        responses.add(
            responses.GET,
            f"{SWAGGER_URL}_v2",
            body='<script src="swagger-ui.js"/>',
            status=200,
        )
        responses.add(
            responses.GET,
            f"{SWAGGER_URL}_v3",
            body='<script src="swagger-ui-bundle.js"/>',
            status=200,
        )
        responses.add(
            responses.GET,
            f"https://error.com",
            body=requests.exceptions.RequestException("timeout"),
        )
        responses.add(responses.GET, f"https://invalid.com", body="error")
        scenarios = {
            "valid v2": {
                "url": f"{SWAGGER_URL}_v2",
                "github_obj": None,
                "result": "v2.2.9",
            },
            "valid v3": {
                "url": f"{SWAGGER_URL}_v3",
                "github_obj": GitMock(),
                "result": "v3.52.1",
            },
            "invalid_bundle": {
                "url": "https://invalid.com",
                "github_obj": None,
                "result": None,
            },
            "error_bundle": {
                "url": "https://error.com",
                "github_obj": None,
                "result": None,
            },
        }

        for sc_name, scenario in scenarios.items():
            url = scenario["url"]
            sc = SwaggerClassifier(scenario["github_obj"])
            self.assertEqual(
                sc.get_swagger_ui_version(url),
                scenario["result"],
                msg=f"detect: {sc_name}",
            )
