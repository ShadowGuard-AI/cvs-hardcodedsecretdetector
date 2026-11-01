#!/usr/bin/env python3

import argparse
import difflib
import math
from collections import Counter
import logging
import os
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Regular expressions for common secrets. The length based shapes are
# anchored to an assignment or label: a bare run of 32 to 45 letters or
# digits, or of exactly 40 word characters, matches ordinary prose and
# identifiers, and the old unanchored pair reported one plain string
# twice, as an API Key and as an AWS Secret Access Key. Where a pattern
# captures the secret itself, the group is named "value" so the report
# code can mask it: matched values are never printed or written out in
# clear, in the console output or in the -o file. Reports carry the
# file, line, type, and surrounding context with the value redacted.
PATTERNS = {
    "Private Key Block": r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----",
    "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Password": r"(?:password|pwd|secret)\s*[:=]\s*['\"]?(?P<value>[^'\"\s]+)['\"]?",
    "Token Assignment": r"(?:api_token|auth_token|access_token|session_token|bearer_token)\s*[:=]\s*['\"]?(?P<value>[^'\"\s]+)['\"]?",
    "API Key": r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?(?P<value>[A-Za-z0-9_\-]{16,})['\"]?",
    "AWS Secret Access Key": r"aws_secret_access_key\s*[:=]\s*['\"]?(?P<value>[\w+=/]{40})['\"]?",
    "SQL Connection String": r"Server=.*?Database=.*?User Id=.*?Password=.*?",
    "Database Credentials": r"jdbc:.*?://.*?:.*?",  # Broad JDBC pattern for initial detection
}


def mask_values(text, values):
    """Replace every detected secret value in text with a redaction marker.

    Fragments count too: if a long piece of a detected value (12 or
    more characters) appears in the text on its own, for example the
    body of a token quoted on a neighboring line without its prefix,
    that piece is redacted as well, because it is most of the secret.
    """
    for value in sorted(values, key=len, reverse=True):
        if value:
            text = text.replace(value, "[redacted]")
    for value in values:
        if not value or len(value) < 12:
            continue
        while True:
            matcher = difflib.SequenceMatcher(None, text, value, autojunk=False)
            block = matcher.find_longest_match(0, len(text), 0, len(value))
            if block.size < 12:
                break
            text = text[:block.a] + "[redacted]" + text[block.a + block.size:]
    return text


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans source code for hardcoded secrets.")
    parser.add_argument("path", help="Path to the file or directory to scan.")
    parser.add_argument("-e", "--entropy", action="store_true", help="Enable entropy analysis for additional checks.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Path to output file to save results.", default=None)
    return parser.parse_args()


def scan_file(file_path, enable_entropy=False, output_file=None):
    """
    Scans a single file for hardcoded secrets.

    Args:
        file_path (str): The path to the file to scan.
        enable_entropy (bool): Whether to enable entropy analysis.
        output_file (str): Path to the output file to save results.
    """
    try:
        # The whole file is read as UTF-8 text. A binary file, or one
        # in another encoding, fails that read and is reported as
        # unreadable rather than scanned in part, which is why the
        # directory scan counts skipped files instead of hiding them.
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return

    # Collect hits first, with the span of the secret value itself, so
    # one string is reported once, under the first matching type in
    # table order, instead of once per pattern that happens to match it.
    hits = []
    accepted_spans = []
    for name, pattern in PATTERNS.items():
        matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            if "value" in match.re.groupindex and match.group("value") is not None:
                value = match.group("value")
                span = match.span("value")
            else:
                value = match.group(0)
                span = match.span(0)
            if any(span[0] < end and start < span[1] for start, end in accepted_spans):
                continue
            accepted_spans.append(span)
            hits.append((span[0], name, value, span))

    if enable_entropy:
        for string, position in find_high_entropy_strings(content):
            span = (position, position + len(string))
            if any(span[0] < end and start < span[1] for start, end in accepted_spans):
                continue
            accepted_spans.append(span)
            hits.append((position, "High Entropy String", string, span))

    hits.sort(key=lambda hit: hit[0])
    # Masking uses every value found in the whole file, not only the
    # value on this line, because a secret can be quoted again in the
    # context window of a different hit. The line numbers are also
    # computed from the hit position here, after sorting, so the
    # report reads in file order whatever order the patterns ran in.
    all_values = [value for _, _, value, _ in hits]

    found_secrets = []
    for position, name, value, span in hits:
        line_number = content[:position].count('\n') + 1
        context = content[max(0, position - 50):min(len(content), span[1] + 50)]
        masked_context = mask_values(context, all_values)
        found_secrets.append(
            f"File: {file_path}, Line: {line_number}, Type: {name}, Secret: [redacted], Context: {masked_context}"
        )
        logging.warning(f"Potential secret found in {file_path} (Line {line_number}): {name}")

    if output_file:
        try:
            # Append mode, per file, and nothing truncates the output
            # first. Running a scan twice against the same -o path, or
            # scanning a directory file by file, accumulates entries,
            # so an old report and a new one can sit in the same file.
            with open(output_file, "a") as outfile:
                for secret_info in found_secrets:
                    outfile.write(secret_info + "\n")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")

    return found_secrets


def shannon_entropy(data):
    """Shannon entropy of a bytes object, in bits per byte (0.0 to 8.0).

    Local implementation: the PyPI distribution named "entropy" does not
    provide this function, so the tool cannot rely on it.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def find_high_entropy_strings(text, min_length=16, threshold=3.5):
    """
    Finds high entropy strings within the given text.

    Args:
        text (str): The text to analyze.
        min_length (int): Minimum length of the string to consider.
        threshold (float): Entropy threshold above which a string is considered high entropy.

    Returns:
        list: A list of tuples containing the high entropy string and its starting position.
    """
    # Scan whole token shaped runs once each. Sliding a fixed window one
    # character at a time reported a single long string a dozen times, once
    # per offset, and the overlaps told the reader nothing extra.
    high_entropy_strings = []
    for match in re.finditer(r"[A-Za-z0-9+/=_-]{%d,}" % min_length, text):
        token = match.group(0)
        if shannon_entropy(token.encode('utf-8')) > threshold:
            high_entropy_strings.append((token, match.start()))
    return high_entropy_strings


def scan_directory(dir_path, enable_entropy=False, output_file=None):
    """
    Recursively scans a directory for hardcoded secrets.

    Args:
        dir_path (str): The path to the directory to scan.
        enable_entropy (bool): Whether to enable entropy analysis.
        output_file (str): Path to the output file to save results.
    """
    all_secrets = []
    scanned = 0
    skipped = 0
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            secrets = scan_file(file_path, enable_entropy, output_file)
            if secrets is None:
                # scan_file returns None only when the file could not
                # be read. Count it as skipped instead of letting a
                # directory where nothing was read report a clean scan.
                skipped += 1
                continue
            scanned += 1
            if secrets:
                all_secrets.extend(secrets)
    return all_secrets, scanned, skipped


def validate_input(path):
    """
    Validates the input path.

    Args:
        path (str): The path to validate.

    Returns:
        bool: True if the path is valid, False otherwise.
    """
    if not os.path.exists(path):
        logging.error(f"Path does not exist: {path}")
        return False
    return True


def main():
    """
    Main function to run the hardcoded secret detector.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    if not validate_input(args.path):
        sys.exit(1)

    if os.path.isfile(args.path):
        secrets = scan_file(args.path, args.entropy, args.output)
        # scan_file returns None when the file could not be read (for
        # example a binary file that is not valid UTF-8). Treating that
        # as an empty result printed "No secrets found" for a file that
        # was never scanned, so a failed read is a failed run here. In
        # directory mode unreadable files are counted as skipped, since
        # one bad file should not void a whole tree scan.
        if secrets is None:
            logging.error(f"Could not read {args.path}; nothing was scanned.")
            sys.exit(1)
        if secrets:
            print("\n".join(secrets))  # Print results to console
        elif not args.output:
            print("No secrets found.")
    elif os.path.isdir(args.path):
        secrets, scanned, skipped = scan_directory(args.path, args.entropy, args.output)
        print(f"Scanned {scanned} file(s); skipped {skipped} unreadable file(s).")
        if scanned == 0:
            print("No files could be scanned, so no scan was performed and no clean result is reported.")
            sys.exit(1)
        if secrets:
            print("\n".join(secrets)) # Print results to console
        elif not args.output:
            print("No secrets found.")
    else:
        logging.error(f"Invalid path type: {args.path}")
        sys.exit(1)


if __name__ == "__main__":
    main()