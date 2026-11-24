#!/usr/bin/env python3
"""Exercise the login endpoint with repeated failed attempts.

This is a defensive test script for systems you own or are authorized to test.
It measures whether the login page stays available under repeated bad-password
submissions and checks the health endpoint before and after the run.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import secrets
import statistics
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


DEFAULT_BASE_URL = "https://localhost:8443"
DEFAULT_USERNAME = "alice"


@dataclass
class AttemptResult:
    attempt: int
    status_code: int | None
    elapsed_ms: float | None
    error: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send repeated failed login attempts and report whether the web "
            "application remains available."
        )
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of the web app (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--username",
        default=DEFAULT_USERNAME,
        help=f"Username to target with the failed attempts (default: {DEFAULT_USERNAME})",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=10,
        help="Number of failed login attempts to send (default: 10)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="How many login requests to send in parallel (default: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Optional delay in seconds between sequential attempts (default: 0)",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="Optional file with one candidate password per line",
    )
    parser.add_argument(
        "--health-path",
        default="/health",
        help="Health endpoint path to check before and after the run (default: /health)",
    )
    return parser.parse_args()


def build_url(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def load_passwords(password_file: Path | None, attempts: int) -> list[str]:
    if password_file:
        passwords = [line.strip() for line in password_file.read_text(encoding="utf-8").splitlines()]
        passwords = [password for password in passwords if password]
        if not passwords:
            raise ValueError(f"Password file {password_file} is empty")
        return passwords[:attempts]

    alphabet = string.ascii_letters + string.digits + string.punctuation
    return [
        "".join(secrets.choice(alphabet) for _ in range(18))
        for _ in range(attempts)
    ]


def check_health(base_url: str, health_path: str, timeout: float) -> tuple[int, str]:
    response = requests.get(build_url(base_url, health_path), timeout=timeout, verify=False)
    return response.status_code, response.text[:200]


def attempt_login(
    base_url: str,
    username: str,
    password: str,
    attempt_number: int,
    timeout: float,
) -> AttemptResult:
    started = time.perf_counter()
    try:
        response = requests.post(
            build_url(base_url, "/login"),
            data={"username": username, "password": password},
            allow_redirects=False,
            timeout=timeout,
            verify=False,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return AttemptResult(
            attempt=attempt_number,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
        )
    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return AttemptResult(
            attempt=attempt_number,
            status_code=None,
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )


def run_attempts(
    base_url: str,
    username: str,
    passwords: Iterable[str],
    concurrency: int,
    timeout: float,
    delay: float,
) -> list[AttemptResult]:
    passwords = list(passwords)
    results: list[AttemptResult] = []

    if concurrency <= 1:
        for index, password in enumerate(passwords, start=1):
            results.append(attempt_login(base_url, username, password, index, timeout))
            if delay > 0 and index != len(passwords):
                time.sleep(delay)
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_map = {
            executor.submit(attempt_login, base_url, username, password, index, timeout): index
            for index, password in enumerate(passwords, start=1)
        }
        for future in concurrent.futures.as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda item: item.attempt)
    return results


def main() -> int:
    args = parse_args()
    passwords = load_passwords(args.password_file, args.attempts)

    print(f"Base URL: {args.base_url}")
    print(f"Target username: {args.username}")
    print(f"Attempts: {len(passwords)}")
    print(f"Concurrency: {args.concurrency}")

    try:
        health_status_before, health_body_before = check_health(args.base_url, args.health_path, args.timeout)
    except requests.RequestException as exc:
        print(f"Pre-check health request failed: {exc}", file=sys.stderr)
        return 1

    print(f"Health before: {health_status_before} {health_body_before!r}")
    if health_status_before != 200:
        print("Health endpoint was not healthy before the test.", file=sys.stderr)
        return 1

    results = run_attempts(
        base_url=args.base_url,
        username=args.username,
        passwords=passwords,
        concurrency=args.concurrency,
        timeout=args.timeout,
        delay=args.delay,
    )

    try:
        health_status_after, health_body_after = check_health(args.base_url, args.health_path, args.timeout)
    except requests.RequestException as exc:
        print(f"Post-check health request failed: {exc}", file=sys.stderr)
        return 1

    print(f"Health after: {health_status_after} {health_body_after!r}")

    status_counts: dict[str, int] = {}
    latencies: list[float] = []
    failures: list[AttemptResult] = []

    for result in results:
        key = str(result.status_code) if result.status_code is not None else "error"
        status_counts[key] = status_counts.get(key, 0) + 1
        if result.elapsed_ms is not None:
            latencies.append(result.elapsed_ms)

        if result.error is not None or result.status_code is None or result.status_code >= 500:
            failures.append(result)

    print("\nStatus summary:")
    for status_code, count in sorted(status_counts.items(), key=lambda item: item[0]):
        print(f"  {status_code}: {count}")

    if latencies:
        print(
            "Latency ms: "
            f"min={min(latencies):.1f} "
            f"avg={statistics.fmean(latencies):.1f} "
            f"max={max(latencies):.1f}"
        )

    if failures:
        print("\nFailures:", file=sys.stderr)
        for failure in failures:
            print(
                f"  attempt {failure.attempt}: status={failure.status_code} error={failure.error}",
                file=sys.stderr,
            )
        return 1

    if health_status_after != 200:
        print("Health endpoint degraded after the test.", file=sys.stderr)
        return 1

    print("\nLogin endpoint remained available during repeated failed attempts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())