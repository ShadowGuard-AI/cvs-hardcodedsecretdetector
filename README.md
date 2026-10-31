![Banner](banner.png)

# cvs-HardcodedSecretDetector
A command-line tool that scans source code for hardcoded secrets, API keys, passwords, and other sensitive information using regular expressions, and, only when -e is passed, entropy analysis. It detects hardcoded secrets only; it does not check for SQL injection, XSS, or other vulnerability classes. Patterns cover private key block headers, GitHub tokens including the full ghp_ prefix, AWS access key IDs, password and token named assignments (password, pwd, secret, api_token, auth_token, access_token, and similar names), api_key assignments, aws_secret_access_key assignments, SQL connection strings, and JDBC credential URLs. Length based patterns are anchored to an assignment or label, so a plain run of letters is not reported, and one string is reported once, under a single type. Matched secret values are never printed or saved in clear: the console output and the -o output file carry the file, line, type, and context with the value replaced by [redacted], so a scan report is not itself a list of usable secrets. In directory mode the run prints how many files were scanned and how many were skipped as unreadable; if no file could be scanned, it says no scan was performed and exits 1 instead of reporting a clean result, matching single file mode, where an unreadable file also exits 1.

## Install
`git clone https://github.com/ShadowGuard-AI/cvs-hardcodedsecretdetector`

## Usage
`python3 main.py [-h] [-e] [-v] [-o OUTPUT] path`, run from the cloned directory. There is no executable or package by the repo name.

## Parameters
- `path`: Path to the file or directory to scan. Required.
- `-h`: Show help message and exit
- `-e`: Enable entropy analysis for additional checks. Entropy analysis is off unless this flag is passed.
- `-v`: Enable verbose output (debug logging).
- `-o`: Path to output file to save results. Results are appended to the file, with secret values redacted the same way as the console output.

## License
Copyright (c) ShadowStrikeHQ
