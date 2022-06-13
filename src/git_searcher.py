#!/usr/bin/python3

import git
from packaging import version

import logging

log = logging.getLogger(__name__)


class GitSearcher:
    """Object to search the repository for a hash, returns version of software that has it

    Parameters:
    repo (string): Path to the git repository containing swagger-ui
    """

    def __init__(self, repo, special_cases):
        """Constructor

        Parameters:
        repo (string): Path to the git repository containing swagger-ui
        special_casess (dict:string->string): Dictionary of hashes and versions that are not in the repo
        """
        self.g = git.cmd.Git(repo)
        self.special_cases = special_cases

    def get_version_from_shorthash(self, shorthash):
        """Searches for the shorthash in the repo attempting to return the version containing the commit

        Parameters:
        shorthash (string): hash of the commit identified in the swagger

        Returns:
        version (string): version containing commit specified by shorthash
        """
        if shorthash in self.special_cases:
            return self.special_cases[shorthash]
        try:
            versions = self.g.tag(contains=shorthash).split("\n")
            if "$GIT_TAG" in versions:
                versions.remove("$GIT_TAG")
            if len(versions) > 0 and versions != [""]:
                versions.sort(key=version.parse)
                return versions[0]
            else:
                log.info(f'Unable to find version for tag "{shorthash}".')
                return None
        except git.exc.GitCommandError as e:
            err = " ".join(str(e).split("\n"))
            log.error(f"Git tag lookup error, {err}")
