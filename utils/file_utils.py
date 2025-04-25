# Purpose: File management helpers like reading, writing, checking, or deleting files.
import os

def read_file(file_path):
    with open(file_path, 'r', errors='ignore') as f:
        return f.read()

def write_file(file_path, content):
    with open(file_path, 'w') as f:
        f.write(content)

def file_exists(file_path):
    return os.path.isfile(file_path)

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
