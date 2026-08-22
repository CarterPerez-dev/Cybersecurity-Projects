"""
©AngelaMos | 2026
test_smoke.py
"""

import not_sandboxed


def test_package_imports() -> None:
    assert not_sandboxed.__version__
