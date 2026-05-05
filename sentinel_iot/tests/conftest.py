"""Shared pytest fixtures for SentinelIoT tests."""

import sys
import os
import pytest

# Add project root (v3) to path so that 'sentinel_iot' package is found
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
