#!/usr/bin/python3
'''
Type             Location                       Run on behalf of
User Agents     ~/Library/LaunchAgents          Currently logged in user
Global Agents   /Library/LaunchAgents           Currently logged in user
Global Daemons  /Library/LaunchDaemons          root or the user specified with the key UserName
System Agents   /System/Library/LaunchAgents    Currently logged in user
System Daemons  /System/Library/LaunchDaemons   root or the user specified with the key UserName
'''
import os
import plistlib
import psutil
import subprocess
from tabulate import tabulate
from termcolor import colored

def get_launchctl_manager_info():
    try:
        result = subprocess.run(['launchctl', 'managerpid'], capture_output=True, text=True)
        managerpid = result.stdout.strip()

        result = subprocess.run(['launchctl', 'manageruid'], capture_output=True, text=True)
        manageruid = result.stdout.strip()

        result = subprocess.run(['launchctl', 'managername'], capture_output=True, text=True)
        managername = result.stdout.strip()

        return managerpid, manageruid, managername

    except subprocess.CalledProcessError:
        return None


def get_process_info(process):
    try:
        managerpid, manageruid, _ = get_launchctl_manager_info()
        gui_command = ['launchctl', 'print', f'gui/{manageruid}/{process}']
        system_command = ['launchctl', 'print', f'system/{process}']

        # Run the GUI command and get the result
        gui_result = subprocess.run(gui_command, capture_output=True, text=True)
        gui_output_lines = gui_result.stdout.strip().split('\n')

        pid = ""
        state = ""
        domain = ""

        for line in gui_output_lines:
            if 'pid =' in line or 'PID =' in line:
                pid = line.split('=', 1)[1].strip()
            elif 'state =' in line:
                state = line.split('=', 1)[1].strip()
            elif 'domain =' in line:
                domain = line.split('=', 1)[1].strip()

        # If PID is found from the GUI command, return the result
        if state:
            return pid, state, domain

        # Run the system command and get the result
        system_result = subprocess.run(system_command, capture_output=True, text=True)
        system_output_lines = system_result.stdout.strip().split('\n')

        pid = ""
        state = ""
        domain = ""

        for line in system_output_lines:
            if 'pid =' in line or 'PID =' in line:
                pid = line.split('=', 1)[1].strip()
            elif 'state =' in line:
                state = line.split('=', 1)[1].strip()
            elif 'domain =' in line:
                domain = line.split('=', 1)[1].strip()

        return pid, state, domain

    except subprocess.CalledProcessError as e:
        print(f"Error running launchctl print for process {process}: {e.stderr}")
        return "", "", ""


def list_config_files(directory):
    config_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.plist') and not file.endswith('.swp'):
                plist_path = os.path.join(root, file)
                config_files.append(plist_path)
    return config_files



def get_plist_info(plist_path):
    try:
        with open(plist_path, 'rb') as plist_file:
            plist_data = plist_file.read()
            plist = plistlib.loads(plist_data)
            return plist
    except Exception as e:
        print(f"Error parsing plist file: {plist_path}")
        print(f"Error message: {str(e)}")
        return None

def generate_table():
    headers = ["#", "Level", "Directory of Plist", "PID", "Process", "State", "Domain", "Open files by Process"]
    table_data = []

    directories = [
        ("User Agents", os.path.expanduser("~/Library/LaunchAgents")),
        ("Global Agents", "/Library/LaunchAgents"),
        ("Global Daemons", "/Library/LaunchDaemons"),
        ("System Agents", "/System/Library/LaunchAgents"),
        ("System Daemons", "/System/Library/LaunchDaemons")
    ]

    row_number = 1

    for level, directory in directories:
        config_files = list_config_files(directory)
        for plist_path in config_files:
            plist_info = get_plist_info(plist_path)
            if plist_info is None:
                print(f"problematic Skipping plist file: {plist_path}")
                print("Genertating table with other plists")
                continue  # Skip this plist file if parsing fails
            if plist_info is not None:
                process_name = plist_info.get("Label", "")
                process_pid, state, domain = get_process_info(process_name)
                process_open_files = ""

                level_colored = colored(level, "yellow")
                plist_path_colored = colored(plist_path, "cyan")
                process_pid_colored = colored(process_pid, "green") if process_pid else ""
                process_name_colored = colored(process_name, "magenta")
                state_colored = colored(state, "blue") if state else ""
                domain_colored = colored(domain, "blue") if domain else ""
                process_open_files_colored = colored(process_open_files, "blue")

                table_data.append([
                    str(row_number),
                    level_colored,
                    plist_path_colored,
                    process_pid_colored,
                    process_name_colored,
                    state_colored,
                    domain_colored,
                    process_open_files_colored
                ])

                row_number += 1

    return tabulate(table_data, headers=headers, tablefmt="psql")


# Print the colored table
colored_table = generate_table()
print(colored_table)
