#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
from datetime import datetime

HASH_RE = re.compile(
    r"\[(?P<protocol>[^\]]+)\]\s+"
    r"(?P<hash_type>NTLMv2|NTLMv2-SSP|NTLM|NTLM-SSP)\s+Hash\s+:\s+"
    r"(?P<hash>[^:\s]+::.+)"
)

DATE_RE = re.compile(r"(\d{2}/\d{2}/\d{4})")


def parse_date(value):
    return datetime.strptime(value, "%m/%d/%Y")


def line_in_date_range(line, start, end):
    match = DATE_RE.search(line)
    if not match:
        return True

    line_date = parse_date(match.group(1))

    if start and line_date < start:
        return False
    if end and line_date > end:
        return False

    return True


def clean_line(line):
    ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", line).strip()


def extract_hashes(args):
    input_path = Path(args.input)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    seen_users = set()
    results = []
    usernames = set()

    start = parse_date(args.start) if args.start else None
    end = parse_date(args.end) if args.end else None

    protocol_filter = re.compile(args.protocols, re.I) if args.protocols else None
    hash_filter = re.compile(args.hash_type, re.I) if args.hash_type else None

    with input_path.open("r", errors="ignore") as f:
        for raw_line in f:
            line = clean_line(raw_line)

            if not line_in_date_range(line, start, end):
                continue

            match = HASH_RE.search(line)
            if not match:
                continue

            protocol = match.group("protocol")
            hash_type = match.group("hash_type")
            captured_hash = match.group("hash")

            if protocol_filter and not protocol_filter.search(protocol):
                continue

            if hash_filter and not hash_filter.search(hash_type):
                continue

            username = captured_hash.split("::", 1)[0]
            domain_part = captured_hash.split("::", 1)[1].split(":", 1)[0]

            if args.user and args.user.lower() not in username.lower():
                continue

            if args.domain and args.domain.lower() not in domain_part.lower():
                continue

            usernames.add(username)

            if not args.all:
                if username.lower() in seen_users:
                    continue
                seen_users.add(username.lower())

            if args.show_ip:
                results.append(line)
            else:
                results.append(captured_hash)

    return results, sorted(usernames)


def main():
    parser = argparse.ArgumentParser(
        description="Extract and filter hashes from Responder-Session.log files"
    )

    parser.add_argument("-i", "--input", required=True, help="Responder log file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-A", "--all", action="store_true", help="Extract all hashes, not just first per user")
    parser.add_argument("-P", "--protocols", help='Protocol filter, e.g. "SMB|HTTP|FTP"')
    parser.add_argument("-H", "--hash-type", help='Hash type filter, e.g. "NTLMv2|NTLMv2-SSP"')
    parser.add_argument("-U", "--user", help="Filter by username")
    parser.add_argument("-D", "--domain", help="Filter by domain")
    parser.add_argument("-u", "--usernames", action="store_true", help="Also extract usernames")
    parser.add_argument("-I", "--show-ip", action="store_true", help="Show full matching log lines")
    parser.add_argument("--start", help="Start date mm/dd/yyyy")
    parser.add_argument("--end", help="End date mm/dd/yyyy")

    args = parser.parse_args()

    results, usernames = extract_hashes(args)

    output = "\n".join(results)

    if args.output:
        Path(args.output).write_text(output + "\n")
        if args.usernames:
            Path(args.output + ".usernames").write_text("\n".join(usernames) + "\n")
    else:
        print("\n=== LIST OF HASHES ===\n")
        print(output)

        if args.usernames:
            print("\n=== LIST OF USERNAMES ===\n")
            print("\n".join(usernames))


if __name__ == "__main__":
    main()