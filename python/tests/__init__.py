"""Tests for the PolicyVault Python reference client.

Layers (docs/test-plan.md vocabulary):
  UNIT        test_amounts.py, test_schemas.py, test_secret_redaction.py
  INTEGRATION test_live_server.py — real HTTP against the real Node server
              spawned from this worktree by _server_boot.js. No mocks.

Run from ``python/``::

    python3 -m unittest discover -s tests -t . -v
"""
