# Python Security & OOP Practice

An educational repository for practicing Python object-oriented programming (OOP) through small defensive-security and auditing utilities. The modules explore classes, attributes, encapsulation, inheritance, polymorphism, hashing, and logging.

## Learning modules

- **Port scanner** (`port_scanner.py`, `port_scanner_2.py`) — practice with network sockets and class-based organization.
- **File integrity / hash vault** (`hash_vault.py`, `file_vault.py` references may differ by revision) — explore SHA-256 hashing and file-integrity concepts. Check the actual filename in the current checkout before running examples.
- **Reconnaissance suite** (`recon_suite.py`) — practice inheritance and polymorphism across DNS, HTTP-header, and TLS-related checks.
- **Logging and exceptions** (`logger_config.py`, `custom_exceptions.py`) — reusable logging configuration and custom exception patterns.
- **Tests** (`test_module4.py`) — an example of testing a module.

## Requirements

- Python 3.10 or newer recommended.
- Some network-related modules may use Python's standard library; inspect imports in each script before running it.

## Run safely

Use a local lab or systems you own or have explicit permission to test. Do not scan public hosts or networks without authorization.

From Windows PowerShell, create an isolated environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version
```

Review the script's arguments and default targets before executing a network utility. The README does not assume that every script is safe to run without configuration.

## Educational scope and limitations

This repository is an academic/practice lab, not a production security toolkit. The presence of a scanner or hashing utility does not establish complete coverage, validated detection accuracy, or operational readiness. Verify behavior in a controlled environment and add tests before relying on outputs.

## Validation status

The repository includes a test module, but no test execution is claimed by this documentation update. Run the tests in your local environment after reviewing their imports and expected behavior.

## License

Check the repository's license file or GitHub license metadata before redistributing or reusing this code.
