#!/usr/bin/env python3
"""Shared status vocabulary for perf governance scripts."""

from __future__ import annotations


RETRY_CLASS_PASS = "pass"
RETRY_CLASS_RETRYABLE = "retryable"
RETRY_CLASS_HARD = "hard"
RETRY_CLASSES = (
    RETRY_CLASS_PASS,
    RETRY_CLASS_RETRYABLE,
    RETRY_CLASS_HARD,
)

STABILITY_STATUS_MISSING_TREND = "missing_trend"
STABILITY_STATUS_FAIL = "fail"
STABILITY_STATUS_WARMING_UP = "warming_up"
STABILITY_STATUS_PASS = "pass"
STABILITY_STATUSES = (
    STABILITY_STATUS_MISSING_TREND,
    STABILITY_STATUS_FAIL,
    STABILITY_STATUS_WARMING_UP,
    STABILITY_STATUS_PASS,
)


def normalize_retry_class(raw: object, any_fail: bool = False) -> str:
    value = str(raw or "").strip().lower()
    if value in RETRY_CLASSES:
        return value
    return RETRY_CLASS_HARD if any_fail else RETRY_CLASS_PASS


def normalize_stability_status(raw: object, default: str = STABILITY_STATUS_FAIL) -> str:
    value = str(raw or "").strip().lower()
    if value in STABILITY_STATUSES:
        return value
    return default
