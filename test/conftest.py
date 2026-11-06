"""
Shared test setup for 3RD EYE.

1. Lets the tests import the checks from the scanner folder.
2. Gives every test a brand-new, empty FAKE AWS account (moto).
   Fake keys guarantee the tests can never touch a real AWS account.
"""

import os
import sys

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))


@pytest.fixture
def aws(monkeypatch):
    """A fresh fake AWS account for one test."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")