#!/usr/bin/python3
import os
import subprocess

def search_files(root_paths, extensions, search_lines):
    searched_directories = set()

    for root_path in root_paths:
        for root, _, files in os.walk(root_path):
            searched_directories.add(root)  # Add the directory path to the set
            for file in files:
                if file.endswith(extensions):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r") as f:
                        for line in f:
                            for search_line in search_lines:
                                if search_line in line:
                                    print("Found in file: " + file)
                                    print("Absolute path: " + file_path)
                                    print("----------")

    return searched_directories

def check_sudoers_manipulation():
    sudoers_path = "/etc/sudoers"

    try:
        with open(sudoers_path, "r") as f:
            sudoers_content = f.read()
            if "NOPASSWD" in sudoers_content:
                print("Potential manipulation detected in sudoers file: " + sudoers_path)
                print("----------")
    except FileNotFoundError:
        print("sudoers file not found: " + sudoers_path)

def main():
    plist_paths = [
        "/System/Library/LaunchDaemons",
        "/Library/Apple/System/Library/LaunchDaemons",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/Library/LaunchAgents",
        "/Library/Apple/System/Library/LaunchAgents",
        os.path.expanduser("~/Library/LaunchAgents"),
        "/Users/laithrafid/Library/LaunchAgents"
    ]

    extensions = (".plist",)
    search_lines = ["socksport", "socksport=", "localhost", "127.0.0.1"]

    print("Searching for .plist files...")
    searched_directories = search_files(plist_paths, extensions, search_lines)

    print("Checking for potential manipulation in sudoers file...")
    check_sudoers_manipulation()

    print("\nSearched directories:")
    for directory in searched_directories:
        print(directory)

if __name__ == "__main__":
    main()
