# AWS Mig Welder

[![CI](https://github.com/skyscrapr/awsmigwelder/actions/workflows/test.yml/badge.svg)](https://github.com/skyscrapr/awsmigwelder/actions/workflows/test.yml)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/github/license/skyscrapr/awsmigwelder)
![Black](https://img.shields.io/badge/code%20style-black-000000.svg)
![Ruff](https://img.shields.io/badge/linter-ruff-orange)
![Mypy](https://img.shields.io/badge/type%20checking-mypy-blueviolet)

A command-line tool to **export** and **consolidate** AWS security group rules to support migrations, especially those involving AWS Migration Hub and EC2 environments.

## 🚀 Features

- Export security group rules for:
  - AWS EC2 security groups
  - AWS Migration Hub discovered servers
- Consolidate overlapping or duplicate rules intelligently
- Output results as clean CSV files for audit or further processing

## 📦 Requirements

- Python 3.8+
- AWS credentials configured (e.g., via `~/.aws/credentials` or environment variables)
- `boto3`, `requests`, and other dependencies listed in `setup.py`

## 🛠️ Installation

Install the package locally:

```bash
pip install .
```

Or install in editable/development mode with dev tools:

```bash
pip install -e .[dev]
```

## 🧰 Usage

Run the CLI tool via:

```bash
python migwelder.py <command> [options]
```

### Available Commands

| Command                    | Description                                       |
|---------------------------|---------------------------------------------------|
| `export-sg-rules`         | Export rules from a given EC2 security group     |
| `export-server-sg-rules`  | Export rules for a server via Migration Hub      |
| `consolidate-sg-rules`    | Consolidate duplicate or covered rules from CSV  |

### Examples

Export rules for a specific security group:

```bash
python migwelder.py export-sg-rules --id "sg-0123456789abcdef0" --output "sg-0123456789abcdef0.csv"
```

Export security group rules for a Migration Hub server:

```bash
python migwelder.py export-server-sg-rules --id "d-server-0123456789abcdef0" --output "d-server-0123456789abcdef0.csv"
```

Consolidate security group rules from an exported CSV:

```bash
python migwelder.py consolidate-sg-rules --input d-server-0123456789abcdef0.csv --default default-rules.csv --output d-server-0123456789abcdef0_new.csv
```

## 🧪 Running Tests

Run all unit tests with:

```bash
pytest
```

Test files are located in the `tests/` directory.

## ✨ Linting and Type Checking

Lint your code using [Ruff](https://docs.astral.sh/ruff/):

```bash
ruff aws/ tests/ migwelder.py
```

Check formatting using [Black](https://black.readthedocs.io/):

```bash
black --check aws/ tests/ migwelder.py
```

Run static type checks with [mypy](http://mypy-lang.org/):

```bash
mypy aws/ migwelder.py
```

## 🤖 Continuous Integration

This project includes a GitHub Actions workflow:

- Triggers on push and pull requests to `main`
- Runs:
  - `pytest`
  - `ruff` (linting)
  - `black --check` (formatting)
  - `mypy` (type checking)

You’ll find the config in:

```text
.github/workflows/test.yml
```

## 📁 Project Structure

```
aws-mig-welder/
├── aws/
│   ├── __init__.py
│   ├── discovery.py         # Export rules from Migration Hub
│   └── ec2.py               # Export rules from EC2 security groups
├── migwelder.py             # Main CLI tool
├── tests/
│   ├── __init__.py
│   ├── test_discovery.py
│   ├── test_ec2.py
|   └── test_migwelder.py
├── setup.py
├── requirements.txt
├── README.md
└── .github/
    └── workflows/
        └── test.yml         # GitHub Actions CI config
```

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
