"""
The `scanner` package -- Week 1 of VulnScan Lite.

Importing the package exposes the two functions the rest of the app needs,
so callers can write:

    from scanner import run_scan, ScanError

instead of reaching into individual files.
"""

from .engine import run_scan          # the orchestrator
from .models import ScanError, ScanResult, ModuleResult, CheckResult   # shared types

__all__ = ["run_scan", "ScanError", "ScanResult", "ModuleResult", "CheckResult"]   # public API
__version__ = "1.0.0"                 # shown by the CLI and the API health endpoint
