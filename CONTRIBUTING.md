# Contributing Guide - VulnLab

Thank you for considering contributing to VulnLab! This document provides guidelines and best practices for contributions.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Code Standards](#code-standards)
- [Project Structure](#project-structure)
- [Adding New Containers](#adding-new-containers)
- [Testing](#testing)
- [Review Process](#review-process)

---

## Code of Conduct

This project adheres to principles of mutual respect and constructive collaboration. We expect all contributors to:

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what is best for the community
- Maintain professional communication

---

## How to Contribute

### 1. Reporting Bugs

Before reporting a bug:

1. Check if an open issue already exists.
2. Try to reproduce the problem in a clean installation.
3. Collect relevant information (Docker version, OS, logs).

When creating the issue, include:

- A clear description of the problem.
- Steps to reproduce.
- Expected vs. actual behavior.
- Relevant logs.
- Environment (OS, versions).

### 2. Suggesting Enhancements

For enhancement suggestions:

1. Check if a similar issue already exists.
2. Clearly describe the proposed enhancement.
3. Explain the benefit to the project.
4. If possible, suggest an implementation.

### 3. Pull Requests

#### Process

1. Fork the repository.
2. Create a branch for your feature: `git checkout -b feature/new-feature`
3. Make atomic and descriptive commits.
4. Update the documentation if necessary.
5. Test your changes.
6. Open a Pull Request.

#### Commit Conventions

Use clear and descriptive commit messages:

```
type(scope): short description

Optional body with more details.

Refs: #123
```

**Types:**
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Formatting (does not affect code)
- `refactor`: Code refactoring
- `test`: Adding or correcting tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(scanner): add support for multiple report formats
fix(lab): correct IP parsing in the ips command
docs(readme): update installation section
```

---

## Code Standards

### Bash Scripts

- Use `#!/bin/bash` as the shebang.
- Include `set -e` to fail on errors.
- Use the common library `lib/common.sh`.
- Prefer uppercase variable names.
- Document functions with comments.
- Use `shellcheck` for validation.

```bash
#!/bin/bash
set -e

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Description of the function
# Args:
#   $1 - First argument
my_function() {
    local arg1="$1"
    # implementation
}
```

### Python

- Follow PEP 8.
- Use type hints.
- Document functions with docstrings (Google style).
- Keep functions small and focused.
- Use logging instead of print.

```python
def my_function(param: str) -> bool:
    """
    Brief description of the function.

    Args:
        param: Description of the parameter.

    Returns:
        Description of the return value.

    Raises:
        ValueError: When param is invalid.
    """
    pass
```

### Docker Compose

- Use version 3.8 or higher.
- Keep binding to `127.0.0.1` for all ports.
- Use descriptive names for services.
- Document known CVEs in comments.
- Organize services by category.

---

## Project Structure

```
trabalho/
├── lab.sh                 # Main orchestration script
├── docker-compose.yml     # Container definitions
├── lib/
│   └── common.sh          # Common functions library
├── scanner/
│   ├── openvas_scanner.py # Main scanner
│   ├── run.sh             # Scanner wrapper
│   └── config.yaml        # Configuration
├── scripts/
│   └── generate_compose.py # Utilities
├── docs/
│   └── ...                # Additional documentation
└── README.md              # Main documentation
```

---

## Adding New Containers

### Checklist

Before adding a new vulnerable container:

- [ ] Verify it doesn't duplicate an existing one.
- [ ] Confirm the image is available on Docker Hub.
- [ ] Document the known vulnerabilities.
- [ ] Test locally.
- [ ] Update the documentation.

### Template

Add to `docker-compose.yml`:

```yaml
  # CATEGORY: Service Name
  # Vulnerabilities: CVE-XXXX-YYYY, CVE-ZZZZ-WWWW
  service-name:
    image: image:version
    container_name: service-name
    networks:
      vulnnet:
        ipv4_address: 172.30.X.Y
    ports:
      - "127.0.0.1:HOST_PORT:CONTAINER_PORT"
    environment:
      - VARIABLE=value
```

### Update the README

Add an entry in the appropriate section of the catalog:

| Service      | Image          | IP           | Port      | Vulnerabilities |
|--------------|----------------|--------------|-----------|-----------------|
| `service-name` | `image:version`| `172.30.X.Y` | `PORT:PORT` | CVE-XXXX-YYYY   |

---

## Testing

### Manual Tests

Before submitting a PR:

1.  **Compose Syntax:**
    ```bash
    docker-compose config
    ```

2.  **Initialization:**
    ```bash
    ./lab.sh start service-name
    ./lab.sh status
    ```

3.  **Connectivity:**
    ```bash
    ./lab.sh ips | grep service-name
    curl http://127.0.0.1:PORT
    ```

4.  **Bash Scripts:**
    ```bash
    shellcheck lab.sh scanner/*.sh
    ```

5.  **Python Scripts:**
    ```bash
    python -m py_compile scanner/openvas_scanner.py
    ```

---

## Review Process

### What reviewers check for

1.  **Functionality:** Does the code do what it should?
2.  **Security:** Does it follow security best practices (localhost binding, etc.)?
3.  **Quality:** Is the code clean, documented, and without duplication?
4.  **Tests:** Was it tested locally?
5.  **Documentation:** Is the README updated if necessary?

### Review Time

-   Simple PRs: 1-3 days
-   Complex PRs: 3-7 days

---

## Questions?

If you have questions about contributing, open an issue with the `question` tag or contact the maintainers.

We appreciate your contribution!