"""Guards on the test suite itself (they keep it runnable on every supported platform)."""

from types import SimpleNamespace

import pytest
from conftest import MAX_NODE_ID_CHARS, oversized_node_ids, pytest_collection_modifyitems


def test_node_ids_longer_than_the_limit_stop_collection():
    long_id = "tests/test_x.py::test_y[" + "x" * 48_001 + "]"  # what an unnamed large parameter produced
    assert oversized_node_ids([long_id, "tests/test_x.py::test_y[oversized-48001-chars]"]) == [long_id]
    items = [SimpleNamespace(nodeid=long_id)]
    with pytest.raises(pytest.UsageError, match=f"under {MAX_NODE_ID_CHARS} characters"):
        pytest_collection_modifyitems(None, items)


def test_the_limit_is_far_below_the_windows_environment_variable_limit():
    assert MAX_NODE_ID_CHARS * 10 < 32_767  # PYTEST_CURRENT_TEST holds the node id plus a phase suffix
