#!/usr/bin/env python3
"""
Automated E2E Test Runner for ESP32-S3 DNS Ad Blocker.
Supports dual execution modes:
  - 'mock': High-fidelity in-process host firmware emulator (default)
  - 'live': Network execution against physical ESP32-S3 hardware
"""

import sys
import os
import argparse
import unittest
import time
import json
from typing import List, Dict, Any, Optional

# Ensure test directory and project root are in sys.path
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_DIR)

if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from common.dns_client import DnsClient
    from common.http_client import HttpClient
    from common.base_test import BaseE2ETest
    from mock_firmware_server import MockFirmwareServer
    from test_cases.test_tier1_features import TestTier1Features
    from test_cases.test_tier2_boundaries import TestTier2Boundaries
    from test_cases.test_tier3_pairwise import TestTier3Pairwise
    from test_cases.test_tier4_workloads import TestTier4Workloads
except ImportError:
    from test.common.dns_client import DnsClient
    from test.common.http_client import HttpClient
    from test.common.base_test import BaseE2ETest
    from test.mock_firmware_server import MockFirmwareServer
    from test.test_cases.test_tier1_features import TestTier1Features
    from test.test_cases.test_tier2_boundaries import TestTier2Boundaries
    from test.test_cases.test_tier3_pairwise import TestTier3Pairwise
    from test.test_cases.test_tier4_workloads import TestTier4Workloads


class E2ETestResult(unittest.TestResult):
    """Custom TestResult tracking detailed per-test metrics."""
    def __init__(self, verbose: bool = False):
        super().__init__()
        self.verbose = verbose
        self.test_records: List[Dict[str, Any]] = []
        self._start_time: float = 0.0

    def startTest(self, test):
        super().startTest(test)
        self._start_time = time.perf_counter()

    def addSuccess(self, test):
        super().addSuccess(test)
        duration = time.perf_counter() - self._start_time
        record = {
            "test": test.id(),
            "status": "PASS",
            "duration": round(duration, 4),
            "error": None
        }
        self.test_records.append(record)
        if self.verbose:
            print(f"  [PASS] {test.id()} ({duration*1000:.1f}ms)")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        duration = time.perf_counter() - self._start_time
        err_msg = self._exc_info_to_string(err, test)
        record = {
            "test": test.id(),
            "status": "FAIL",
            "duration": round(duration, 4),
            "error": err_msg
        }
        self.test_records.append(record)
        print(f"  [FAIL] {test.id()}: {err[1]}")

    def addError(self, test, err):
        super().addError(test, err)
        duration = time.perf_counter() - self._start_time
        err_msg = self._exc_info_to_string(err, test)
        record = {
            "test": test.id(),
            "status": "ERROR",
            "duration": round(duration, 4),
            "error": err_msg
        }
        self.test_records.append(record)
        print(f"  [ERROR] {test.id()}: {err[1]}")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        record = {
            "test": test.id(),
            "status": "SKIP",
            "duration": 0.0,
            "error": reason
        }
        self.test_records.append(record)
        if self.verbose:
            print(f"  [SKIP] {test.id()} ({reason})")


def run_e2e_suite(mode: str = "mock",
                  host: str = "127.0.0.1",
                  dns_port: int = 53,
                  http_port: int = 80,
                  tier: str = "all",
                  verbose: bool = False,
                  output_json: Optional[str] = None) -> int:
    """Execute the specified E2E test suite."""
    server: Optional[MockFirmwareServer] = None

    if mode == "mock":
        # Start high-fidelity firmware emulator
        # Use dynamic ephemeral ports if default 53/80 require elevated privileges on host
        req_dns = dns_port if dns_port != 53 else 0
        req_http = http_port if http_port != 80 else 0
        server = MockFirmwareServer(host=host, dns_port=req_dns, http_port=req_http)
        server.start()
        dns_port = server.dns_port
        http_port = server.http_port

    print("=" * 72)
    print("       ESP32-S3 DNS AD BLOCKER — E2E TEST RUNNER")
    print("=" * 72)
    print(f" Execution Mode: {mode.upper()}")
    print(f" Target Host:    {host}")
    print(f" DNS Port:       {dns_port} (UDP)")
    print(f" HTTP Port:      {http_port} (TCP)")
    print(f" Selected Tier:  {tier.upper()}")
    print("=" * 72)

    try:
        # Initialize clients
        dns_client = DnsClient(host=host, port=dns_port, timeout=3.0)
        http_client = HttpClient(host=host, port=http_port, timeout=3.0)
        BaseE2ETest.set_clients(dns_client, http_client)

        loader = unittest.TestLoader()
        master_suite = unittest.TestSuite()

        tier_classes = {
            "1": [("Tier 1: Feature Coverage", TestTier1Features)],
            "2": [("Tier 2: Boundary & Corner Cases", TestTier2Boundaries)],
            "3": [("Tier 3: Cross-Feature Interactions", TestTier3Pairwise)],
            "4": [("Tier 4: Real-World Workloads", TestTier4Workloads)],
        }

        active_tiers = []
        if tier.lower() in ["all", "full"]:
            active_tiers = ["1", "2", "3", "4"]
        elif tier in tier_classes:
            active_tiers = [tier]
        else:
            print(f"Error: Unknown tier '{tier}'. Must be 'all', '1', '2', '3', or '4'.")
            return 1

        for t in active_tiers:
            for tier_name, cls in tier_classes[t]:
                sub_suite = loader.loadTestsFromTestCase(cls)
                master_suite.addTests(sub_suite)

        total_tests = master_suite.countTestCases()
        print(f"\nRunning {total_tests} test cases across {len(active_tiers)} tier(s)...\n")

        runner_result = E2ETestResult(verbose=verbose)
        t_start = time.perf_counter()
        master_suite.run(runner_result)
        total_duration = time.perf_counter() - t_start

        # Compute tier breakdown
        tier_counts: Dict[str, Dict[str, int]] = {
            "Tier 1": {"pass": 0, "fail": 0, "total": 0},
            "Tier 2": {"pass": 0, "fail": 0, "total": 0},
            "Tier 3": {"pass": 0, "fail": 0, "total": 0},
            "Tier 4": {"pass": 0, "fail": 0, "total": 0}
        }

        for record in runner_result.test_records:
            test_id = record["test"]
            tier_key = None
            if "Tier1" in test_id or "t1_" in test_id:
                tier_key = "Tier 1"
            elif "Tier2" in test_id or "t2_" in test_id:
                tier_key = "Tier 2"
            elif "Tier3" in test_id or "t3_" in test_id:
                tier_key = "Tier 3"
            elif "Tier4" in test_id or "t4_" in test_id:
                tier_key = "Tier 4"

            if tier_key:
                tier_counts[tier_key]["total"] += 1
                if record["status"] == "PASS":
                    tier_counts[tier_key]["pass"] += 1
                else:
                    tier_counts[tier_key]["fail"] += 1

        passed = len(runner_result.test_records) - len(runner_result.failures) - len(runner_result.errors)
        failed = len(runner_result.failures)
        errors = len(runner_result.errors)
        pass_rate = (passed / total_tests * 100.0) if total_tests > 0 else 0.0

        print("\n" + "=" * 72)
        print("                     TEST SUMMARY REPORT")
        print("=" * 72)
        for t_name, counts in tier_counts.items():
            if counts["total"] > 0:
                t_pct = (counts["pass"] / counts["total"] * 100.0) if counts["total"] > 0 else 0.0
                status_str = "PASSED" if counts["fail"] == 0 else "FAILED"
                print(f" {t_name:8}: {counts['pass']:3}/{counts['total']:3} passed ({t_pct:5.1f}%) [{status_str}]")

        print("-" * 72)
        print(f" Total Tests Executed: {total_tests}")
        print(f" Passed:               {passed}")
        print(f" Failed:               {failed}")
        print(f" Errors:               {errors}")
        print(f" Overall Pass Rate:    {pass_rate:.1f}%")
        print(f" Total Duration:       {total_duration:.2f} seconds")
        print("=" * 72)

        if output_json:
            report_data = {
                "mode": mode,
                "host": host,
                "dns_port": dns_port,
                "http_port": http_port,
                "total_tests": total_tests,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "pass_rate": round(pass_rate, 2),
                "duration_seconds": round(total_duration, 4),
                "tier_breakdown": tier_counts,
                "tests": runner_result.test_records
            }
            with open(output_json, "w", encoding="utf-8") as jf:
                json.dump(report_data, jf, indent=2)
            print(f"\nJSON test report saved to: {output_json}")

        if failed == 0 and errors == 0:
            print("\n>>> ALL TESTS PASSED SUCCESSFULLY! <<<\n")
            return 0
        else:
            print(f"\n>>> TEST SUITE FAILED with {failed} failure(s) and {errors} error(s)! <<<\n")
            return 1

    finally:
        if server:
            server.stop()


def main():
    parser = argparse.ArgumentParser(description="ESP32-S3 DNS Ad Blocker E2E Test Suite Runner")
    parser.add_argument("--mode", choices=["mock", "live"], default="mock",
                        help="Execution mode: 'mock' (host emulator) or 'live' (physical hardware)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Target IP/hostname (default: 127.0.0.1)")
    parser.add_argument("--dns-port", type=int, default=53,
                        help="Target DNS UDP port (default: 53, or dynamic in mock mode)")
    parser.add_argument("--http-port", type=int, default=80,
                        help="Target HTTP TCP port (default: 80, or dynamic in mock mode)")
    parser.add_argument("--tier", choices=["all", "1", "2", "3", "4"], default="all",
                        help="Select test tier to execute (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose per-test reporting")
    parser.add_argument("--output-json", default=None,
                        help="Path to export JSON test execution report")

    args = parser.parse_args()
    exit_code = run_e2e_suite(
        mode=args.mode,
        host=args.host,
        dns_port=args.dns_port,
        http_port=args.http_port,
        tier=args.tier,
        verbose=args.verbose,
        output_json=args.output_json
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
