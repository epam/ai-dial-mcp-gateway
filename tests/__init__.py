"""The gateway's test package.

Present so tests import each other by their full path (`tests.conftest`), which keeps
mypy resolving one module per file rather than seeing `conftest` twice under two names.
"""
