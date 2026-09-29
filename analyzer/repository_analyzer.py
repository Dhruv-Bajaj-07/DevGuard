from pathlib import Path

ignored_directories = {".git", "node_modules", "__pycache__"}
project_path = Path(r"C:\Users\govin\OneDrive\Desktop\Full Stack")

file_count = 0
file_types = {}
readme_files = []

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
     
print("Project:", project_path.name)
print("Total files:", file_count)
print("\nFile Types:")
for extension, count in file_types.items():
    print(extension, ":", count)

print("\nREADME files:", len(readme_files))
for readme in readme_files:
    print("-", readme.relative_to(project_path))