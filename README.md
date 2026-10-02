# secret-glance

Find likely secrets in local text files without printing the matched values. It reports only file paths, line numbers, and detector names. It makes no network requests and does not modify files.

## Use

Requires Python 3.8+; no packages to install.

```sh
python secret_glance.py .
python secret_glance.py src config/.env
```

Exit status is `0` when no likely matches are found, `1` when matches are found, and `2` when a requested path is missing or a file/directory cannot be read. Files larger than 1 MiB, binary files, and symlinks are skipped. `.git`, virtual environment, dependency, and Python cache directories are skipped. UTF-8 text is scanned line by line.

Detectors look for common private-key headers, AWS access-key IDs, GitHub and Slack token shapes, JWT-like strings, and non-placeholder values assigned to secret-like names. This is a small heuristic helper: it can miss secrets and can report examples or unrelated strings. It does not inspect Git history, decode files, validate credentials, or replace a maintained secret scanner. No matched value is written to stdout or stderr.

## License

MIT
