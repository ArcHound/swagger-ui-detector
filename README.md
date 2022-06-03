Swagger-UI Detector
===================

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

Redirect logs:
```
```

Redirect output:
```
```

