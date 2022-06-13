import git
import unittest
from unittest.mock import patch, MagicMock, Mock
from src.git_searcher import GitSearcher
import responses

class TestGitSearcher(unittest.TestCase):
    
    def test_git_search(self):
        repo = "test"
        scenarios = {"special_case": {"special_cases":{"aaaaaa":"v1.2"},"mock_response":"","query":"aaaaaa", "result":"v1.2"},
                "simple_git":{"special_cases":{}, "mock_response":"v1.2", "query":"aaaaaa", "result":"v1.2"},
                "two_git":{"special_cases":{}, "mock_response":"v1.2\nv1.3", "query":"aaaaaa", "result":"v1.2"},
                "three_git":{"special_cases":{}, "mock_response":"v1.2\nv1.3\nv1.4", "query":"aaaaaa", "result":"v1.2"},
                "git_tag_git":{"special_cases":{}, "mock_response":"v1.2\n$GIT_TAG\nv1.3", "query":"aaaaaa", "result":"v1.2"},
        "missing_tag_git":{"special_cases":{'bbbbbb':"v1.0"}, "mock_response":"", "query":"aaaaaa", "result":None}}
        for sc_name, scenario in scenarios.items():
            with patch('git.cmd.Git') as MockGit:
                gs = GitSearcher(repo=repo, special_cases=scenario["special_cases"])
                gs.g.tag = Mock(return_value=scenario["mock_response"])
                ver = gs.get_version_from_shorthash(scenario["query"])
                self.assertEqual(ver, scenario["result"], msg=sc_name)

    def test_git_search_exc(self):
        repo = "test"
        scenarios = {"missing_tag_git":{"special_cases":{'bbbbbb':"v1.0"}, "mock_response":"", "query":"aaaaaa", "result":None}}
        for sc_name, scenario in scenarios.items():
            with patch('git.cmd.Git') as MockGit:
                gs = GitSearcher(repo=repo, special_cases=scenario["special_cases"])
                gs.g.tag = Mock(return_value=scenario["mock_response"])
                gs.g.tag.side_effect = git.exc.GitCommandError('tag mishap')
                ver = gs.get_version_from_shorthash(scenario["query"])
                self.assertEqual(ver, scenario["result"], msg=sc_name)
