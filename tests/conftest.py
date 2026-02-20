"""Shared test fixtures."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def terraform_fixtures():
    return FIXTURES_DIR / "terraform"


@pytest.fixture
def aws_fixtures():
    return FIXTURES_DIR / "aws"


@pytest.fixture
def iam_fixtures():
    return FIXTURES_DIR / "iam"
