from pathlib import Path
import re

ignored_directories = {".git", "node_modules", "__pycache__"}

dependency_files = {
    "requirements.txt",
    "package.json",
    "pom.xml",
    "build.gradle"
}

project_types = {
    "package.json": "JavaScript / Node.js",
    "requirements.txt": "Python",
    "pom.xml": "Java / Maven",
    "build.gradle": "Java / Gradle"
}

security_sensitive_files = {
    ".env",
    ".env.local",
    "config.py",
    "settings.py",
    "application.properties"
}

scannable_extensions = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".html",
    ".css",
    ".json",
    ".xml",
    ".txt"
}


def detect_hardcoded_secrets(content):
    findings = []

    pattern = re.compile(
        r"""(?i)\b(password|api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*(['"])(.*?)\2"""
    )

    placeholders = {
        "",
        "your_password",
        "your_api_key",
        "your_secret",
        "your_token",
        "placeholder",
        "example",
        "changeme",
        "change_me",
        "none",
        "null",
        "your-secret-here"
    }

    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped_line = line.strip()

        if stripped_line.startswith(("#", "//", "*")):
            continue

        for match in pattern.finditer(line):
            keyword = match.group(1).lower()
            value = match.group(3).strip()

            if value.lower() in placeholders:
                continue

            findings.append({
                "type": "Potential Hardcoded Secret",
                "severity": "Medium",
                "keyword": keyword,
                "line": line_no,
                "description": (
                    "A quoted value assigned to a credential-related "
                    "field needs review."
                )
            })

    return findings


def scan_repository(project_path):
    file_count = 0
    file_types = {}
    readme_files = []
    dependency_files_found = []
    project_types_found = set()
    security_files_found = []
    security_findings = []

    for file in project_path.rglob("*"):
        if (
            file.is_file()
            and not any(
                part in ignored_directories
                for part in file.parts
            )
        ):
            file_count += 1
            extension = file.suffix

            if extension == "":
                extension = "No extension"

            if extension in file_types:
                file_types[extension] += 1
            else:
                file_types[extension] = 1

            if file.name.lower() == "readme.md":
                readme_files.append(file)

            if file.name in dependency_files:
                dependency_files_found.append(file)
                project_types_found.add(project_types[file.name])

            if file.name in security_sensitive_files:
                security_files_found.append(file)

            if file.suffix.lower() in scannable_extensions:
                try:
                    with open(
                        file, "r", encoding="utf-8"
                    ) as current_file:
                        content = current_file.read()

                except (OSError, UnicodeDecodeError):
                    continue

                findings = detect_hardcoded_secrets(content)

                for finding in findings:
                    finding["file"] = str(
                        file.relative_to(project_path)
                    )
                    security_findings.append(finding)

    return {
        "project": project_path.name,
        "total_files": file_count,
        "file_types": file_types,
        "readme_files": readme_files,
        "dependency_files": dependency_files_found,
        "project_types": project_types_found,
        "security_files": security_files_found,
        "security_findings": security_findings
    }


def main():
    repository_path = input("Enter repository path: ").strip()
    project_path = Path(repository_path)

    if not project_path.exists():
        print("Repository path does not exist.")

    elif not project_path.is_dir():
        print("The given path is not a directory.")

    else:
        results = scan_repository(project_path)

        print("Project:", results["project"])
        print("Total files:", results["total_files"])

        print("\nSecurity Findings:")

        for finding in results["security_findings"]:
            print(finding)


if __name__ == "__main__":
    main()