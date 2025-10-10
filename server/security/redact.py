#!/usr/bin/env python3
"""Redact sensitive fields in logs and configuration files.

This script mirrors the rules used on the iOS client so operators can sanitise
server-side artifacts before sharing. Usage:

    python3 redact.py --in input.log --out output.log
"""

from __future__ import annotations

import argparse
import json
import os
import re
from typing import Iterable

KEY_REGEX = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,64}(?![A-Za-z0-9+/=])")
TOKEN_REGEX = re.compile(r"(?i)(bearer|token|authorization)\s+([A-Za-z0-9._\-]+)")
DOMAIN_REGEX = re.compile(r"(?<!@)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}")
IP_REGEX = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
PATH_REGEX = re.compile(r"(?<![A-Za-z0-9])(/[^\s:]+)")


def redact_domain(value: str) -> str:
    parts = value.split('.')
    if len(parts) < 2:
        return value
    masked = []
    for index, part in enumerate(parts):
        if index == len(parts) - 1:
            masked.append(part)
        elif index == 0:
            masked.append(part[:2] + '*' * max(0, len(part) - 2))
        else:
            masked.append('*' * len(part))
    return '.'.join(masked)


def redact_ipv4(value: str) -> str:
    parts = value.split('.')
    if len(parts) != 4:
        return value
    return f"***.***.{parts[2]}.{parts[3]}"


def redact_text(text: str) -> str:
    result = text
    result = KEY_REGEX.sub('***KEY_REDACTED***', result)

    def token_replacer(match: re.Match[str]) -> str:
        prefix = match.group(1).upper()
        return f"{prefix} ***TOKEN***"

    result = TOKEN_REGEX.sub(token_replacer, result)
    result = DOMAIN_REGEX.sub(lambda m: redact_domain(m.group(0)), result)
    result = IP_REGEX.sub(lambda m: redact_ipv4(m.group(1)), result)

    def path_replacer(match: re.Match[str]) -> str:
        value = match.group(1)
        if '//' in value:
            return value
        return '/' + os.path.basename(value)

    result = PATH_REGEX.sub(path_replacer, result)
    return result


def process_stream(lines: Iterable[str]) -> Iterable[str]:
    for line in lines:
        yield redact_text(line)


def main() -> None:
    parser = argparse.ArgumentParser(description="Redact sensitive fields in log/config files.")
    parser.add_argument('--in', dest='input_path', required=True, help='Path to input file')
    parser.add_argument('--out', dest='output_path', required=True, help='Path for redacted output file')
    parser.add_argument('--json', action='store_true', help='Treat input as JSON and redact all string values')
    args = parser.parse_args()

    if args.json:
        with open(args.input_path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)

        def sanitize(obj):
            if isinstance(obj, str):
                return redact_text(obj)
            if isinstance(obj, list):
                return [sanitize(item) for item in obj]
            if isinstance(obj, dict):
                return {key: sanitize(value) for key, value in obj.items()}
            return obj

        redacted = sanitize(payload)
        with open(args.output_path, 'w', encoding='utf-8') as handle:
            json.dump(redacted, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
    else:
        with open(args.input_path, 'r', encoding='utf-8') as input_handle:
            lines = list(process_stream(input_handle))
        with open(args.output_path, 'w', encoding='utf-8') as output_handle:
            output_handle.writelines(lines)


if __name__ == '__main__':
    main()
