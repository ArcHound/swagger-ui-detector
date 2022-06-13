Swagger-UI Detector
===================

![GitHub](https://img.shields.io/github/license/ArcHound/swagger-ui-detector)


Description
-----------

Get versions of many Swagger-UIs specified in a URL list.

But first, ensure access to a local [swagger-ui](https://github.com/swagger-api/swagger-ui) github repository (either point to a path or let the script clone it).

For each URL, the script attempts to detect a version:
  - for major version 2 or less, try searching `swagger-ui.js` file
  - for major version 3 or more, search `swagger-ui-bundle.js` for a git reference and get version from local swagger-ui github repository.

Once the version is detected, report vulnerabilities associated with that version (source of data: [SNYK](https://security.snyk.io/vuln/npm/?search=swagger-ui)).

Outputs to stdout, logs to stderr.

Installation
------------

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install swagger-ui-detector.

```bash
pip install swagger-ui-detector 
```

Usage
-----

```
Usage: swagger-ui-detector [OPTIONS]

Options:
  --swagger-ui-repo TEXT        Local repository containing swagger-ui
                                [default: ./swagger-ui]
  --swagger-ui-git-source TEXT  GIT URL of swagger-ui  
				[default: https://github.com/swagger-api/swagger-ui]
  --url-list TEXT               File containing URLs pointing to swagger-uis
  --snyk-url TEXT               Snyk URL containing swagger-ui vulnerabilities
				[default: https://snyk.io/vuln/npm:swagger-ui]
  --get-repo                    Boolean, specifies whether to get the swagger-ui repo from github  
				[default: True]
  --one-line                    Boolean, whether to print one line of output per URL.  
				[default: False]
  --help                        Show this message and exit.

```

### Examples:

Simple example:
```
> swagger-ui-detector --url-list http4kswag.txt

2022-06-13 15:25:23,523 [INFO] Directory for swagger-ui repo already exists.
2022-06-13 15:25:23,523 [INFO] Directory is not empty.
2022-06-13 15:25:23,525 [INFO] Directory is a valid swagger-ui dir with remote https://github.com/swagger-api/swagger-ui
2022-06-13 15:25:23,525 [INFO] Using local swagger-ui repository at ./swagger-ui
2022-06-13 15:25:23,525 [INFO] Load vulnerabilities from https://snyk.io/vuln/npm:swagger-ui ...
2022-06-13 15:25:23,903 [INFO] Loaded 14 vulnerabilities.
2022-06-13 15:25:23,903 [INFO] Got 2 URLs to try...

URL https://www.http4k.org/openapi3/ - [OK] Version v4.11.1
---------
This swagger-ui is not vulnerable.

2022-06-13 15:25:24,475 [INFO] Status: 95%, estimated 0s left.

URL https://demo.thingsboard.io/swagger-ui/ - [VULNERABLE] Version v3.52.5
---------

This swagger-ui is vulnerable to:
  - [User Interface (UI) Misrepresentation of Critical Information](https://snyk.io/vuln/SNYK-JS-SWAGGERUI-2314885)

2022-06-13 15:25:26,028 [INFO] Done.
```

Redirect logs:
```
> swagger-ui-detector --url-list http4kswag.txt 2>/dev/null

URL https://www.http4k.org/openapi3/ - [OK] Version v4.11.1
---------
This swagger-ui is not vulnerable.


URL https://demo.thingsboard.io/swagger-ui/ - [VULNERABLE] Version v3.52.5
---------

This swagger-ui is vulnerable to:
  - [User Interface (UI) Misrepresentation of Critical Information](https://snyk.io/vuln/SNYK-JS-SWAGGERUI-2314885)

```

One-line output:
```
> swagger-ui-detector --url-list http4kswag.txt --one-line 2>/dev/null

URL https://www.http4k.org/openapi3/ - [OK] Version v4.11.1
URL https://demo.thingsboard.io/swagger-ui/ - [VULNERABLE] Version v3.52.5
```

Redirect output:
```
> swagger-ui-detector --url-list http4kswag.txt 1>swagger-detected.log

2022-06-13 15:27:36,267 [INFO] Directory for swagger-ui repo already exists.
2022-06-13 15:27:36,267 [INFO] Directory is not empty.
2022-06-13 15:27:36,269 [INFO] Directory is a valid swagger-ui dir with remote https://github.com/swagger-api/swagger-ui
2022-06-13 15:27:36,270 [INFO] Using local swagger-ui repository at ./swagger-ui
2022-06-13 15:27:36,270 [INFO] Load vulnerabilities from https://snyk.io/vuln/npm:swagger-ui ...
2022-06-13 15:27:36,682 [INFO] Loaded 14 vulnerabilities.
2022-06-13 15:27:36,682 [INFO] Got 2 URLs to try...
2022-06-13 15:27:37,085 [INFO] Status: 95%, estimated 0s left.
2022-06-13 15:27:39,424 [INFO] Done.
```


