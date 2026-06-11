"""Framework-specific integration adapters for raucle.

Each integration is optional and lazy-imports its host framework so that
installing ``raucle`` without the integration's extra does not raise
ImportError at top-level import time. See the integration module docstrings
and ``docs/proposals/`` for design notes.
"""
