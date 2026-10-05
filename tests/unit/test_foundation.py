"""Foundation unit test verifying environment and package layout."""

import password_analyzer


def test_package_metadata() -> None:
    """Verify package version is defined."""
    assert password_analyzer.__version__ == "0.1.0"
