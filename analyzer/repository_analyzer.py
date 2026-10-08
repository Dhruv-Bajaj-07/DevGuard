from pathlib import Path

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

sensitive_keywords = {
    "password",
    "api_key",
    "secret_key",
    "token"
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


def scan_repository(project_path):

    file_count = 0
    file_types = {}
    readme_files = []
    dependency_files_found = []
    project_types_found = set()
    security_files_found = []
    security_findings = []

    for file in project_path.rglob("*"):

        if file.is_file() and not any(part in ignored_directories for part in file.parts):
            file_count = file_count + 1
            extension = file.suffix
            
            if extension == "":
                extension = "No extension"

            if extension in file_types:
                file_types[extension] = file_types[extension] + 1
            else:
                file_types[extension] = 1

            if file.name.lower() == "readme.md":
                readme_files.append(file)

            if file.name in dependency_files:
                dependency_files_found.append(file)

                project_type = project_types[file.name]
                project_types_found.add(project_type)

            if file.name in security_sensitive_files:
                security_files_found.append(file)

            if file.suffix in scannable_extensions:
                with open(file, "r") as current_file:
                    content = current_file.read()
                    for line_no, line in enumerate(content.splitlines(),start=1):
                        for keyword in sensitive_keywords:
                            if keyword in line and "=" in line:
                                value = line.split("=")[1].strip()
                                if value.startswith('"') or value.startswith("'"):

                                    security_findings.append({
                                        "type": "Hardcoded Secret",
                                        "severity": "High",
                                        "keyword": keyword,
                                        "file": str(file.relative_to(project_path)),
                                        "line": line_no,
                                        "description": "A possible hardcoded credential was found in the source code."
                                    })

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


repository_path = input("Enter repository path: ")

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