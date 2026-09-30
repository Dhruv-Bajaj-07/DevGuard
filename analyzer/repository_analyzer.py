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
content = """Hello DevGuard
password = "abc123"
This is another line
api_key = "XYZ123"
"""
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
project_path = Path(r"C:\Users\govin\OneDrive\Desktop\Full Stack")

file_count = 0
file_types = {}
readme_files = []
dependency_files_found = []
project_types_found = set()
security_files_found = []



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
                for line in content.splitlines():
                    for keyword in sensitive_keywords:
                        if keyword in line:
                                print("Sensitive keyword found:", keyword)
                                print("Scannable:", file.relative_to(project_path))
            
    
print("Project:", project_path.name)
print("Total files:", file_count)
print("\nFile Types:")
for extension, count in file_types.items():
    print(extension, ":", count)

print("\nREADME files:", len(readme_files))
for readme in readme_files:
    print("-", readme.relative_to(project_path))
    
print("\nDependency files:", len(dependency_files_found))
for dependency_file in dependency_files_found:
    print("-", dependency_file.relative_to(project_path))
    
print("\nProject Types:")
for project_type in project_types_found:
    print("-", project_type)
    
print("\nSecurity-sensitive files:", len(security_files_found))
for security_file in security_files_found:
    print("-", security_file.relative_to(project_path))
    
