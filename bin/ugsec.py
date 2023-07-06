#!/usr/bin/python3
'''
pyhton3 script to do these functions : 

Utility Functions:

print_help()
colorize_column()
truncate_text()
list_config_files()

Information Retrieval Functions:

get_user_info()
get_admin_accounts()
get_group_info()
get_user_groups()
get_user_pid()
get_last_used()
get_network_services_udp()
get_network_services_tcp()
get_open_files()
get_group_members()
get_launchctl_manager_info()
get_process_info()
get_plist_info()

Display Functions:

display_user_table()
display_group_table()
display_network_services()
print_horizontal_user_table()
print_user_table()
print_group_table()
print_group_info()
print_open_files()
print_password_policy()
print_plist_table()
User and Group Management Functions:

add_user()
add_group()
delete_user_memberships()
delete_users()
delete_groups()

User and Group Information Functions:

get_user_info_by_username()
get_group_info_by_groupname()

Main Function:

main()

##################################### Plists Locations##########################################
Type             Location                       Run on behalf of
User Agents     ~/Library/LaunchAgents          Currently logged in user
Global Agents   /Library/LaunchAgents           Currently logged in user
Global Daemons  /Library/LaunchDaemons          root or the user specified with the key UserName
System Agents   /System/Library/LaunchAgents    Currently logged in user
System Daemons  /System/Library/LaunchDaemons   root or the user specified with the key UserName
################################################################################################

'''
import os
import re
import pwd
import grp
import platform
import sys
#import winreg check why error installing
import subprocess
import readline
import datetime
import getpass
import psutil
import plistlib
import colorama
from prettytable import PrettyTable
from colorama import init, Fore, Style
from tabulate import tabulate
from termcolor import colored

#################### Utility Functions:

def print_help():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py "+ Fore.CYAN + "[Option]" + Style.RESET_ALL + Fore.RED + " [Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Options:"+ Style.RESET_ALL +"\n")
    print("  -i, --interactive      Run the script in interactive mode")
    print("  -ut, --users-table      Print the table of all users")
    print("  -gt, --group-table      Print the table of all groups")
    print("  -du, --delete-users     Delete user(s) specified by username(s)")
    print("  -dg, --delete-groups    Delete group(s) specified by group name(s)")
    print("  -gu, --get-user-info    Get detailed information about a specific user")
    print("  -gs, --get-startups       Get all plists in osx ")
    print("  -gg, --get-group-info   Get detailed information about a specific group")
    print("  -au, --add-user         Add a new user with the specified username")
    print("  -ag, --add-group        Add a new group with the specified group name")
    print("  -dum, --delete-user-memberships    Delete user memberships from a group")
    print("  -h, --help             Show help")
    print_message("error", f"Arguments:")
    print("for option specific arguments use options -h")
    print("example: ugsec.py -ut -h")

def colorize_column(value, condition, color):
    if condition:
        return f"{color}{value}{Style.RESET_ALL}"
    else:
        return value

def truncate_text(text, max_length):
    text = str(text)
    if len(text) > max_length:
        return text[:max_length - 3] + "..."
    return text

def list_config_files(directory):
    config_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.plist') and not file.endswith('.swp'):
                plist_path = os.path.join(root, file)
                config_files.append(plist_path)
    return config_files

#################### Information Retrieval Functions:

def get_user_info(usernames=None):
    operating_system = platform.system()

    user_info = []
    processed_users = set()

    if operating_system == "Windows":
        # Windows logic
        for user in pwd.getpwall():
            if user.pw_name in processed_users:
                continue
            if usernames and user.pw_name not in usernames:
                continue
            user_entry = {
                "Name": user.pw_name,
                "PID": get_user_pid(user.pw_name),  # Add the PID field
                "Password": user.pw_passwd,
                "UID": user.pw_uid,
                "GID": user.pw_gid,
                "Directory": user.pw_dir,
                "Shell": user.pw_shell,
                "GECOS": user.pw_gecos,
                "Groups": get_user_groups(user.pw_name),
                "Last Used": get_last_used(user.pw_name)
            }
            user_info.append(user_entry)
            processed_users.add(user.pw_name)

    elif operating_system == "Linux":
        # Linux logic
        for user in pwd.getpwall():
            if user.pw_name in processed_users:
                continue
            if usernames and user.pw_name not in usernames:
                continue
            try:
                spwd_entry = spwd.getspnam(user.pw_name)
                last_used_timestamp = spwd_entry.sp_lstchg * 86400  # Convert to seconds
                last_used_datetime = datetime.datetime.fromtimestamp(last_used_timestamp)
                last_used_str = last_used_datetime.strftime("%Y-%m-%d %H:%M:%S")
            except KeyError:
                last_used_str = "N/A"

            user_entry = {
                "Name": user.pw_name,
                "PID": get_user_pid(user.pw_name),  # Add the PID field
                "Password": user.pw_passwd,
                "UID": user.pw_uid,
                "GID": user.pw_gid,
                "Directory": user.pw_dir,
                "Shell": user.pw_shell,
                "GECOS": user.pw_gecos,
                "Groups": get_user_groups(user.pw_name),
                "Last Used": last_used_str
            }
            user_info.append(user_entry)
            processed_users.add(user.pw_name)

    elif operating_system == "Darwin":
        # macOS (Darwin) logic
        for user in pwd.getpwall():
            if user.pw_name in processed_users:
                continue
            if usernames and user.pw_name not in usernames:
                continue
            user_entry = {
                "Name": user.pw_name,
                "PID": get_user_pid(user.pw_name),  # Add the PID field
                "Password": user.pw_passwd,
                "UID": user.pw_uid,
                "GID": user.pw_gid,
                "Directory": user.pw_dir,
                "Shell": user.pw_shell,
                "GECOS": user.pw_gecos,
                "Groups": get_user_groups(user.pw_name),
                "Last Used": get_last_used(user.pw_name)
            }
            user_info.append(user_entry)
            processed_users.add(user.pw_name)

    return user_info

def get_admin_accounts():
    admins = []
    if platform.system() == "Windows":
        import wmi
        w = wmi.WMI()
        for group in w.Win32_Group():
            if group.Name == "Administrators":
                admins = [a.Name for a in group.associators(wmi_result_class="Win32_UserAccount")]
    elif platform.system() == "Linux":
        with open('/etc/group', 'r') as file:
            for line in file:
                if line.startswith('sudo:'):
                    admins = line.split(':')[1].strip().split(',')
    elif platform.system() == "Darwin":
        admins = subprocess.check_output(['dscl', '.', 'read', '/Groups/admin', 'GroupMembership']).decode().split()[1:]

    return admins

def get_group_info(group_names=None):
    operating_system = platform.system()

    if operating_system == "Windows":
        # Windows logic placeholder
        try:
            command = "net localgroup"
            output = subprocess.check_output(command, shell=True, text=True)
            lines = output.strip().split("\n")

            group_info = []
            for line in lines:
                if line.startswith("-------------------------------------------------------------------------------"):
                    continue
                if line.startswith("The command completed"):
                    break
                group_entry = {
                    "Group Name": line.strip(),
                    "Users": "",
                    "Comment": ""
                }
                group_info.append(group_entry)

            return group_info
        except subprocess.CalledProcessError:
            return []
    elif operating_system == "Linux":
        # Linux logic
        try:
            command = "cat /etc/group"
            output = subprocess.check_output(command, shell=True, text=True)
            lines = output.strip().split("\n")

            group_info = []
            for line in lines:
                parts = line.split(":")
                group_name = parts[0]
                users = parts[3].split(",") if len(parts) >= 4 else []
                comment = parts[4] if len(parts) >= 5 else ""

                if group_names and group_name not in group_names:
                    continue

                group_entry = {
                    "Group Name": group_name,
                    "Users": users,
                    "Comment": comment
                }
                group_info.append(group_entry)

            return group_info
        except subprocess.CalledProcessError:
            return []
    elif operating_system == "Darwin":
        # macOS (Darwin) logic
        try:
            command = "dscl . -list /Groups"
            output = subprocess.check_output(command, shell=True, text=True)
            groups = output.strip().split("\n")

            group_info = []
            for group in groups:
                if group_names and group not in group_names:
                    continue

                group_entry = {
                    "Group Name": group,
                    "Users": "",
                    "Comment": ""
                }

                group_info_output = subprocess.check_output(f"dscl . -read /Groups/{group}", shell=True, text=True)
                lines = group_info_output.split("\n")
                for line in lines:
                    if "GroupMembership:" in line:
                        group_entry["Users"] = line.split(":")[1].strip()
                    elif "Comment:" in line:
                        comment_index = lines.index(line) + 1
                        if comment_index < len(lines):
                            group_entry["Comment"] = lines[comment_index].strip()
                        break

                group_info.append(group_entry)

            return group_info

        except subprocess.CalledProcessError:
            return []
    else:
        return []  # Unsupported operating system

def get_user_groups(username):
    groups = []
    for group in grp.getgrall():
        if username in group.gr_mem:
            groups.append(group.gr_name)
    return ", ".join(groups)

def get_user_pid(username):
    operating_system = platform.system()

    if operating_system == "Windows":
        # Windows logic
        try:
            command = f"tasklist /FI \"USERNAME eq {username}\" /NH /FO CSV"
            output = subprocess.check_output(command, shell=True, text=True)
            lines = output.strip().split("\n")
            pids = []
            for line in lines:
                pid = line.split(",")[1].strip('"')
                pids.append(pid)
            return ", ".join(pids)
        except subprocess.CalledProcessError:
            return "N/A"
    elif operating_system == "Linux":
        # Linux logic
        try:
            command = f"pgrep -u {username}"
            output = subprocess.check_output(command, shell=True, text=True)
            pids = output.strip().split("\n")
            return ", ".join(pids)
        except subprocess.CalledProcessError:
            return "N/A"
    elif operating_system == "Darwin":
        # macOS (Darwin) logic
        try:
            command = f"pgrep -U {username}"
            output = subprocess.check_output(command, shell=True, text=True)
            pids = output.strip().split("\n")
            return ", ".join(pids)
        except subprocess.CalledProcessError:
            return "N/A"
    else:
        return "N/A"  # Unsupported operating system

def get_last_used(username):
    operating_system = platform.system()

    if operating_system == "Windows":
        try:
            command = f"net user {username}"
            output = subprocess.check_output(command, shell=True, text=True)
            lines = output.strip().split("\n")
            for line in lines:
                if line.startswith("Last logon"):
                    last_login_str = line.split(":")[1].strip()
                    return last_login_str
            return "N/A"  # Last logon information not found
        except subprocess.CalledProcessError:
            return "N/A"
    elif operating_system == "Linux":
        try:
            spwd_entry = pwd.getspnam(username)
            last_used_timestamp = spwd_entry.sp_lstchg * 86400  # Convert to seconds
            last_used_datetime = datetime.datetime.fromtimestamp(last_used_timestamp)
            return last_used_datetime.strftime("%Y-%m-%d %H:%M:%S")
        except KeyError:
            return "N/A"
    elif operating_system == "Darwin":
        try:
            command = f"last | grep {username} | head -n 1"
            output = subprocess.check_output(command, shell=True, text=True)
            last_line = output.strip()
            last_login_time = last_line.split()[4:9]
            last_login_str = " ".join(last_login_time)
            return last_login_str
        except subprocess.CalledProcessError:
            return "N/A"
    else:
        return "N/A"  # Unsupported operating system

def get_network_services_udp(username):
    operating_system = platform.system()

    if operating_system == "Windows":
        # Windows logic
        command = f"netstat -ano -p udp -n | findstr LISTENING | findstr {username}"
    elif operating_system == "Linux":
        # Linux logic
        command = f"sudo lsof -iUDP +c0 -a -nP -u {username}"
    elif operating_system == "Darwin":
        # macOS (Darwin) logic
        command = f"sudo lsof -iUDP +c0 -a -nP -u {username}"
    else:
        return []  # Unsupported operating system

    try:
        output = subprocess.check_output(command, shell=True, text=True)
        lines = output.strip().split("\n")
        services = []
        for line in lines:
            if line.startswith("COMMAND"):
                headers = line.split()
            else:
                values = line.split()
                service = {
                    "Command": values[0],
                    "PID": values[1],
                    "Type": values[3],
                    "Name": values[8]
                }
                services.append(service)
        return services
    except subprocess.CalledProcessError:
        return []

def get_network_services_tcp(username):
    operating_system = platform.system()

    if operating_system == "Windows":
        # Windows logic
        command = f"netstat -ano -p tcp -n | findstr LISTENING | findstr {username}"
    elif operating_system == "Linux":
        # Linux logic
        command = f"sudo lsof -iTCP +c0 -a -nP -u {username}"
    elif operating_system == "Darwin":
        # macOS (Darwin) logic
        command = f"sudo lsof -iTCP +c0 -a -nP -u {username}"
    else:
        return []  # Unsupported operating system

    try:
        output = subprocess.check_output(command, shell=True, text=True)
        lines = output.strip().split("\n")
        services = []
        for line in lines:
            if line.startswith("COMMAND"):
                headers = line.split()
            else:
                values = line.split()
                service = {
                    "Command": values[0],
                    "PID": values[1],
                    "Type": values[3],
                    "Name": values[8]
                }
                services.append(service)
        return services
    except subprocess.CalledProcessError:
        return []

def get_open_files(username, pid_filter=None):
    operating_system = platform.system()

    if operating_system == "Windows":
        # Windows logic
        command = f"lsof -a -l -n -u {username}"
    elif operating_system == "Linux":
        # Linux logic
        command = f"sudo lsof -a -l -n +c0 -u {username}"
    elif operating_system == "Darwin":
        # macOS (Darwin) logic
        command = f"sudo lsof -a -l -n -u {username}"
    else:
        return []  # Unsupported operating system

    if pid_filter:
        command += f" -p {pid_filter}"
    
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        lines = output.strip().split("\n")
        if len(lines) <= 1:
            return []  # No open files found
        else:
            open_files = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    file_info = {
                        "Command": parts[0],
                        "PID": parts[1],
                        "User": parts[2],
                        "FD": parts[3],
                        "Type": parts[4],
                        "Size": parts[6],
                        "Name": parts[8]
                    }
                    open_files.append(file_info)
            return open_files
    except subprocess.CalledProcessError:
        return []  # Command execution failed, return empty list

def get_group_members(groupname):
    system = platform.system()
    
    if system == "Darwin":
        try:
            output = subprocess.check_output(["dscl", ".", "-read", f"/Groups/{groupname}", "GroupMembership"])
            members_line = output.decode().strip()
            if members_line.startswith("GroupMembership:"):
                members = members_line.replace("GroupMembership:", "").strip().split()
                return members
        except subprocess.CalledProcessError:
            pass
    
    elif system == "Windows":
        try:
            output = subprocess.check_output(["net", "localgroup", groupname])
            members_line = output.decode().strip()
            members_start = members_line.find("----------") + len("----------")
            members_end = members_line.find("The command completed successfully.")
            if members_start != -1 and members_end != -1:
                members = members_line[members_start:members_end].strip().split()
                return members
        except subprocess.CalledProcessError:
            pass
    
    elif system == "Linux":
        try:
            output = subprocess.check_output(["getent", "group", groupname])
            members_line = output.decode().strip()
            members_start = members_line.find(":") + 1
            if members_start != -1:
                members = members_line[members_start:].strip().split(",")
                return members
        except subprocess.CalledProcessError:
            pass
    
    return []

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
    system = platform.system().lower()
    
    if system == "darwin":
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
            print_message("error", f"Error running launchctl print for process {process}: {e.stderr}")
            return "", "", ""
    
    elif system == "linux":
        try:
            command = ['ps', '-C', process, '-o', 'pid=', '-o', 'state=']
            result = subprocess.run(command, capture_output=True, text=True)
            output_lines = result.stdout.strip().split('\n')

            pid = ""
            state = ""
            domain = ""

            if len(output_lines) >= 1:
                pid = output_lines[0].strip().split()[0]
                state = output_lines[0].strip().split()[1]

            return pid, statem, domain

        except subprocess.CalledProcessError as e:
            print_message("error", f"Error running ps command for process {process}: {e.stderr}")
            return "", ""
    
    elif system == "windows":
        try:
            command = ['tasklist', '/fi', f'imagename eq {process}']
            result = subprocess.run(command, capture_output=True, text=True)
            output_lines = result.stdout.strip().split('\n')

            pid = ""
            state = ""
            domain = ""
            
            if len(output_lines) >= 2:
                # Skip the header line
                process_info = output_lines[1]

                # Split the process info into columns
                columns = process_info.split()
                if len(columns) >= 2:
                    pid = columns[1]
                    state = "Running"  # Windows tasklist only shows running processes

            return pid, statem, domain

        except subprocess.CalledProcessError as e:
            print_message("error", f"Error running tasklist for process {process}: {e.stderr}")
            return "", ""
    
    else:
        print_message("error", f"Unsupported platform: {system}")
        return "", "", ""

def get_plist_info(plist_path):
    try:
        with open(plist_path, 'rb') as plist_file:
            plist_data = plist_file.read()
            plist = plistlib.loads(plist_data)
            return plist
    except Exception as e:
        print_message("error", f"Error parsing plist file: {plist_path}")
        print_message("error", f"Error message: {str(e)}")
        return None


def get_cron_tab(filter):
    startup_programs = []
    try:
        if "system" in filter:
            output = subprocess.run("cut -f1 -d: /etc/passwd | grep -v '^[#]' | grep '[^_]' ", shell=True, capture_output=True, text=True)
            users = output.stdout.strip().split("\n")
            for user in users:
                try:
                    output = subprocess.run(f"sudo crontab -u {user} -l", shell=True, capture_output=True, text=True)
                    if output.stdout.strip() == "" or output.stdout.strip() == f"crontab: no crontab for {user}":
                        print_message("info", f"No crontab for {user}")
                    else:
                        lines = output.stdout.strip().split("\n")
                        for line in lines:
                            if not line.startswith("#"):
                                cron_job = line.split(" ", maxsplit=5)
                                program_name = cron_job[-1]
                                startup_programs.append({"Name": "Cron Job", "Path": program_name})
                except subprocess.CalledProcessError:
                    pass
        elif "admins" in filter:
            admins = get_admin_accounts()
            for user in admins:
                try:  
                    output = subprocess.run(f"sudo crontab -u {user} -l", shell=True, capture_output=True, text=True)
                    if output.stdout.strip() == "" or output.stdout.strip() == f"crontab: no crontab for {user}":
                        print_message("info", f"No crontab for {user}")
                    else:
                        lines = output.stdout.strip().split("\n")
                        for line in lines:
                            if not line.startswith("#"):
                                cron_job = line.split(" ", maxsplit=5)
                                program_name = cron_job[-1]
                                startup_programs.append({"Name": "Cron Job", "Path": program_name})
                except subprocess.CalledProcessError:
                    pass
        elif "user" in filter:
            output = subprocess.run("cut -f1 -d: /etc/passwd | grep -v '^[#_]'", shell=True, capture_output=True, text=True)
            users = output.stdout.strip().split("\n")
            for user in users:
                try:
                    output = subprocess.run(f"sudo crontab -u {user} -l", shell=True, capture_output=True, text=True)
                    if output.stdout.strip() == "" or output.stdout.strip() == f"crontab: no crontab for {user}":
                        print_message("info", f"No crontab for {user}")
                    else:
                        lines = output.stdout.strip().split("\n")
                        for line in lines:
                            if not line.startswith("#"):
                                cron_job = line.split(" ", maxsplit=5)
                                program_name = cron_job[-1]
                                startup_programs.append({"Name": "Cron Job", "Path": program_name})
                except subprocess.CalledProcessError:
                    pass
        elif "all" in filter:
            output = subprocess.run("cut -f1 -d: /etc/passwd | grep -v '^#'", shell=True, capture_output=True, text=True)
            users = output.stdout.strip().split("\n")
            admins = get_admin_accounts()
            all_users = admins + users
            for user in all_users:
                try:
                    output = subprocess.run(f"sudo crontab -l -u {user}", shell=True, capture_output=True, text=True)
                    if output.stdout.strip() == "" or output.stdout.strip() == f"crontab: no crontab for {user}":
                        print_message("info", f"No crontab for {user}")
                    else:
                        lines = output.stdout.strip().split("\n")
                        for line in lines:
                            if not line.startswith("#"):
                                cron_job = line.split(" ", maxsplit=5)
                                program_name = cron_job[-1]
                                startup_programs.append({"Name": "Cron Job", "Path": program_name})
                except subprocess.CalledProcessError:
                    pass
    except subprocess.CalledProcessError:
        pass

    return startup_programs


def get_windows_startups_services():
    startup_programs = []
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as reg_key:
            num_entries = winreg.QueryInfoKey(reg_key)[0]
            for i in range(num_entries):
                value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                startup_programs.append({"Name": value_name, "Path": value_data})
        return startup_programs
    except ImportError:
        pass
    return startup_programs

def get_linux_startups_services():
    startup_programs = []
    autostart_dirs = [
        os.path.expanduser("~/.config/autostart"),
        "/etc/xdg/autostart"
    ]

    for autostart_dir in autostart_dirs:
        if os.path.isdir(autostart_dir):
            for file_name in os.listdir(autostart_dir):
                file_path = os.path.join(autostart_dir, file_name)
                if os.path.isfile(file_path) and file_name.endswith(".desktop"):
                    with open(file_path, "r") as file:
                        for line in file:
                            if line.startswith("Exec="):
                                program_name = line[5:].strip()
                                startup_programs.append({"Name": file_name, "Path": program_name})
                                break
    try:
        output = subprocess.check_output("sudo systemctl list-units --type=service --all", shell=True, text=True)
        lines = output.strip().split("\n")
        for line in lines[1:]:  # Skip the header line
            service_info = line.split()
            service_name = service_info[0]
            startup_programs.append({"Name": service_name, "Path": "Systemd Service"})
    except subprocess.CalledProcessError:
        pass

        # Check sysvinit services (if available)
    try:
        output = subprocess.check_output("sudo service --status-all", shell=True, text=True)
        lines = output.strip().split("\n")
        for line in lines:
            if line.strip().endswith("running"):
                service_name = line.strip().split()[3]
                startup_programs.append({"Name": service_name, "Path": "SysVinit Service"})
    except subprocess.CalledProcessError:
        pass
    return startup_programs

def get_startup_programs(filter):
    
    system = platform.system()

    if system == "Windows":
        get_windows_startups_services()
    elif system == "Linux":
        # Check autostart directories
        get_linux_startups_services()
        # Check cron jobs
        get_cron_tab(filter)
    elif system == "Darwin":
        # Check autostart directories
        colored_table = print_plist_table(filter)
        print(colored_table)
        # Check cron jobs
        get_cron_tab(filter)
        
#################### Display Functions:

def display_user_table(data, condition_func=None , truncate=True):
    headers = list(data[0].keys())
    headers.insert(0, "#")  # Add "#" column header

    # Remove duplicate "#" field name
    if "#" in headers[1:]:
        headers.remove("#")

    table = PrettyTable(headers)
    sorted_data = sorted(data, key=lambda x: x['UID'])
    color_list = [
        Fore.YELLOW,
        Fore.CYAN,
        Fore.GREEN,
        Fore.MAGENTA,
        Fore.BLUE,
        Fore.RED,
        Fore.WHITE,
        Fore.WHITE,
        Fore.WHITE,
        Fore.WHITE
    ]
    for i, entry in enumerate(sorted_data, start=1):
        colored_entry = [
            colorize_column(i, True, Fore.RED),
            *[
                colorize_column(
                    truncate_text(entry.get(key, ""), 30) if truncate else entry.get(key, ""),
                    condition_func(entry.get(key, "")) if condition_func else False,
                    color
                )
                for key, color in zip(headers[1:], color_list)
            ]
        ]
        table.add_row(colored_entry)
    table.align = "l"
    table.max_width = 100
    return table

def display_network_services(services, protocol):
    if not services:
        print_message("error", f"No network services ({protocol}) found.")
        return
    
    table = PrettyTable()
    table.field_names = ["Command", "PID", "Type", "Name"]
    for service in services:
        command = service["Command"]
        pid = service["PID"]
        service_type = service["Type"]
        name = service["Name"]
        colored_command = f"{Fore.YELLOW}{command}{Style.RESET_ALL}"
        colored_pid = f"{Fore.CYAN}{pid}{Style.RESET_ALL}"
        colored_service_type = f"{Fore.GREEN}{service_type}{Style.RESET_ALL}"
        colored_name = f"{Fore.MAGENTA}{name}{Style.RESET_ALL}"
        table.add_row([colored_command, colored_pid, colored_service_type, colored_name])

    print_message("info", f"Network Services ({protocol}):")
    print(table)

def print_horizontal_user_table(user_info):
    color_list = [
        Fore.RED,
        Fore.CYAN,
        Fore.GREEN,
        Fore.MAGENTA,
        Fore.BLUE,
        Fore.RED,
        Fore.CYAN,
        Fore.MAGENTA,
        Fore.CYAN,
        Fore.MAGENTA,
    ]
    for key, value in user_info.items():
        colored_key = colorize_column(key, True, Fore.WHITE)
        colored_value = colorize_column(value, True, color_list.pop(0))
        print_message("error", f"{colored_key}: {colored_value}")

def print_user_table(arguments):
    if "all" in arguments or not arguments: 
        data = get_user_info([])
    elif "system" in arguments:
        pattern = r'^_.*'  # Regular expression pattern to match user names starting with underscore
        matching_usernames = [user.pw_name for user in pwd.getpwall() if re.match(pattern, user.pw_name)]
        data = get_user_info(matching_usernames)
    elif "other" in arguments:
        pattern = r'^[^_].*'  # Regular expression pattern to match user names starting with underscore
        matching_usernames = [user.pw_name for user in pwd.getpwall() if re.match(pattern, user.pw_name)]
        data = get_user_info(matching_usernames)
    table = display_user_table(data, condition_func=lambda shell: shell != "/usr/bin/false", truncate=True)
    total_users = len(data)
    print(table)
    print_message("info", f"Total number of users: {total_users}")    

def print_group_table(arguments):
    if "all" in arguments or not arguments:
        group_info = get_group_info()
    elif "system" in arguments:
        pattern = r'^_.*'
        matching_groups = [group["Group Name"] for group in get_group_info() if re.match(pattern, group["Group Name"])]
        group_info = get_group_info(group_names=matching_groups)
    elif "other" in arguments:
        pattern = r'^[^_].*'
        matching_groups = [group["Group Name"] for group in get_group_info() if re.match(pattern, group["Group Name"])]
        group_info = get_group_info(group_names=matching_groups)
    else:
        print("Invalid argument.")
        return

    if group_info:
        group_table = PrettyTable(["#", "Group Name", "Users", "Comment"])
        group_table.align = "l"

        for i, group_entry in enumerate(group_info, start=1):
            colored_group = f"{Fore.YELLOW}{group_entry['Group Name']}{Fore.RESET}"
            colored_users = f"{Fore.GREEN}{group_entry['Users']}{Fore.RESET}"
            colored_comment = f"{Fore.CYAN}{group_entry['Comment']}{Fore.RESET}"
            colored_index = f"{Fore.RED}{i}{Fore.RESET}"
            group_table.add_row([colored_index, colored_group, colored_users, colored_comment])

        print("Group Information:")
        print(group_table)

        total_groups = len(group_info)
        print_message("info",f"Total number of groups: {total_groups}")

def print_group_info(group_info):
    if not group_info:
        print_message("info", f"No group information available.")
        return

    table = PrettyTable(["Field", "Value"])
    table.align = "l"

    colors = [Fore.YELLOW, Fore.CYAN, Fore.GREEN, Fore.MAGENTA]  # Define a list of colors

    for i, (key, value) in enumerate(group_info.items()):
        color_index = i % len(colors)  # Determine the color index based on the current iteration
        colored_key = f"{Fore.WHITE}{key}:{Style.RESET_ALL}"  # Set key color to white and append ":"
        colored_value = colorize_column(str(value), True, colors[color_index])  # Add the color argument for values
        table.add_row([colored_key, colored_value])

    print(table)

def print_admin_accounts():
    admins = get_admin_accounts()
    colored_admins = colorize_column(", ".join(admins), True, Fore.RED)
    print("administrators accounts:", colored_admins)
    prompt = "Do you want more information about the administrators? (y/n) (Press Enter to skip): "
    more_info = input(Fore.MAGENTA +  prompt + Style.RESET_ALL)
    if more_info.lower() == 'y':
        # Prompt for usernames
        get_user_info_by_username(admins)
        print_password_policy()
    elif more_info.lower() == 'n' or more_info.lower() == '':
        print_message("info", "No more information about the administrators needed")
    else: 
        print_message("error", "Invalid answer")

def print_open_files(open_files):
    if not open_files:
        print_message("info", f"No open files found.")
    else:
        table = PrettyTable(["Command", "PID", "User", "FD", "Type", "Size", "Name"])
        color_list = [
            Fore.RED,
            Fore.CYAN,
            Fore.GREEN,
            Fore.MAGENTA,
            Fore.BLUE,
            Fore.MAGENTA,
            Fore.YELLOW,
        ]
        for file in open_files:
            colored_entries = [
                colorize_column(file.get(key, ""), True, color)
                for key, color in zip(
                    ["Command", "PID", "User", "FD", "Type", "Size", "Name"],
                    color_list,
                )
            ]
            table.add_row(colored_entries)
        print_message("info", f"Open Files:")
        print(table)

def print_password_policy():
    prompt = "do you want to know Password Policy? (y/n) (Press Enter to skip):"
    more_info = input(Fore.MAGENTA +  prompt + Style.RESET_ALL )
    if more_info.lower() == 'y':
        print_message("info", f"Password Policy:")
        if platform.system() == "Windows":
            os.system("net accounts")
        elif platform.system() == "Linux":
            os.system("sudo grep '^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE' /etc/login.defs")
        elif platform.system() == "Darwin":
            os.system("pwpolicy getaccountpolicies")
    elif more_info.lower() == 'n' or more_info.lower() == '':
        print_message("info", "No more information about Password Policy needed")
    else:
        print_message("error", "Invalid answer")

def print_plist_table(filter):
    headers = ["#", "Level", "Directory of Plist", "PID", "Process", "State", "Domain", "Open files by Process"]
    table_data = []
    row_number = 1
    if filter == "user":
        directories = [
        ("User Agents", os.path.expanduser("~/Library/LaunchAgents")),
        ("Global Agents", "/Library/LaunchAgents"),
        ]
    elif filter == "system":
        directories = [
        ("Global Daemons", os.path.expanduser("/Library/LaunchDaemons")),
        ("System Agents", "/System/Library/LaunchAgents"),
        ("System Daemons", "/System/Library/LaunchDaemons")
        ]
    elif filter == "all" or filter == "admins" or not filter: 
        directories = [
        ("User Agents", os.path.expanduser("~/Library/LaunchAgents")),
        ("Global Agents", "/Library/LaunchAgents"),
        ("Global Daemons", "/Library/LaunchDaemons"),
        ("System Agents", "/System/Library/LaunchAgents"),
        ("System Daemons", "/System/Library/LaunchDaemons")
    ]
    for level, directory in directories:
        config_files = list_config_files(directory)
        for plist_path in config_files:
            plist_info = get_plist_info(plist_path)
            if plist_info is None:
                print_message("info", f"problematic Skipping plist file: {plist_path}")
                print_message("info", f"Genertating table with other plists")
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

def print_message(message_type,message):
    # Define color codes
    color_codes = {
        'error': Fore.RED,
        'info': Fore.CYAN,
        'warning': Fore.YELLOW
    }
    color_code = color_codes[message_type]
    # Check if the message type is valid
    if message_type not in color_codes:
        print_message("error", f"Invalid message type: {message_type}")
        return

    # Print the message with the corresponding color
    print(f"{color_code}{message}{Style.RESET_ALL}")

def print_help_ut():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -ut, --users-table " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print(" all    : for all Users in OS")
    print(" system : for all System users in OS ")
    print(" other  : for all non system users in os")
    print(" admins : for all administrators in os")
    pass

def print_help_gt():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -gt, --group-table " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print(" all    : for all groups in OS")
    print(" system : for all System groups in OS ")
    print(" other  : for all non system groups in os")
    pass

def print_help_gu():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -gu, --get-user-info " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("username : for one username")
    print("username1 username2 username3 : for multi users separated by spaces")
    pass

def print_help_gg():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -gg, --get-group-info " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("groupname : for one groupname")
    print("groupname1 groupname1 groupname3 : for multi groups separated by spaces")
    pass

def print_help_au():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -au, --add-user " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("username : for one username")
    print("username1 username2 username3 : for multi users separated by spaces")
    pass

def print_help_ag():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -ag, --add-group " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("groupname : for one groupname")
    print("groupname1 groupname1 groupname3 : for multi groups separated by spaces")
    pass

def print_help_dum():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -dum, --delete-user-memberships " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("groupname : for one groupname to delete users memberships")
    print("groupname1 groupname1 groupname3 : for multi groups separated by spaces delete users memberships")
    pass

def print_help_dg():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -dg, --delete-groups " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("groupname : to delete groupname")
    print("groupname1 groupname1 groupname3 : for multi groups separated by spaces delete groups")
    pass

def print_help_du():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -du, --delete-users " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print("username : to delete username")
    print("username1 username2 username3 : to delete for multi users separated by spaces")
    pass

def print_help_gs():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python ugsec.py -gs, --get-startups " + Fore.CYAN + "[Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Arguments:" + Style.RESET_ALL)
    print(" all    : for all startups scripts in OS")
    print(" system : for all System startups scripts in OS ")
    print(" user  : for all non system startups scripts in os")
    print(" admins : for all administrators startups scripts in os")
    pass

#################### User and Group Management Functions:

def add_user(username):
    additional_options = []

    # Prompt for additional options
    while True:
        option = input(Fore.MAGENTA + "Enter additional option (e.g., -c comment, -s shell) or press Enter to skip: " + Style.RESET_ALL)
        if option:
            additional_options.append(option)
        else:
            break

    # Prompt for the group to add the user to
    groupname = input(Fore.MAGENTA + "Enter the group to add the user to: " + Style.RESET_ALL)

    # Prompt for the home directory (optional)
    homedir = input(Fore.MAGENTA + "Enter the home directory for the user (press Enter to skip): " + Style.RESET_ALL)
    homedir_option = ["NFSHomeDirectory", homedir] if homedir else []

    # Prompt for the password (optional)
    password = getpass.getpass(input(Fore.MAGENTA + "Enter the password for the user (press Enter to skip): " + Style.RESET_ALL))
    password_option = ["Password", password] if password else []

    try:
        command = ["sudo", "dscl", ".", "-create", "/Users/" + username]
        command.extend(additional_options)
        subprocess.check_call(command)

        # Set the home directory if provided
        if homedir_option:
            subprocess.check_call(["sudo", "dscl", ".", "-create", "/Users/" + username] + homedir_option)

        # Set the password if provided
        if password_option:
            subprocess.check_call(["sudo", "dscl", ".", "-passwd", "/Users/" + username] + password_option)

        # Add the user to the group
        subprocess.check_call(["sudo", "dscl", ".", "-append", "/Groups/" + groupname, "GroupMembership", username])

        print_message("error", f"User '{username}' added successfully to the group '{groupname}' with additional options.")
    except subprocess.CalledProcessError:
        print_message("error", f"Failed to add user '{username}' to the group '{groupname}' with additional options.")

        if platform.system() == "Linux":
            # Linux-specific user creation logic
            subprocess.check_call(["sudo", "useradd", username, "-G", groupname] + additional_options)
            print_message("info", f"User '{username}' added successfully to the group '{groupname}' on Linux.")
        elif platform.system() == "Windows":
            # Windows-specific user creation logic
            subprocess.check_call(["net", "user", username, password, "/add"])
            subprocess.check_call(["net", "localgroup", groupname, username, "/add"])
            print_message("info", f"User '{username}' added successfully to the group '{groupname}' on Windows.")

def add_group(groupname):
    try:
        subprocess.check_call(["sudo", "dscl", ".", "-create", f"/Groups/{groupname}"])
        print_message("info", f"Group '{groupname}' added successfully.")

        # Prompt for comment option
        comment = input(Fore.MAGENTA + "Enter the comment for the group (press Enter to skip): " + Style.RESET_ALL)
        if comment:
            subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "Comment", comment])

        # Prompt for password option
        password = input(Fore.MAGENTA + "Enter the password for the group (press Enter to skip): " + Style.RESET_ALL)
        if password:
            subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "Password", password])

        # Prompt for realname option
        realname = input(Fore.MAGENTA + "Enter the real name for the group (press Enter to skip): " + Style.RESET_ALL)
        if realname:
            subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "RealName", realname])

        # Prompt for users to add to membership
        users = input(Fore.MAGENTA + "Enter the username(s) to add to the group membership (separated by spaces), or press Enter to skip: " + Style.RESET_ALL)
        if users:
            users = users.split()
            for user in users:
                subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "GroupMembership", user])

        print_message("info", f"Additional options added successfully.")
    except subprocess.CalledProcessError:
        print_message("error", f"Failed to add group '{groupname}' with additional options.")

        if platform.system() == "Linux":
            # Linux-specific group creation logic
            subprocess.check_call(["groupadd", groupname])
            print_message("info", f"Group '{groupname}' added successfully on Linux.")
        elif platform.system() == "Windows":
            # Windows-specific group creation logic
            subprocess.check_call(["net", "localgroup", groupname, "/add"])
            print_message("info", f"Group '{groupname}' added successfully on Windows.")

def delete_user_memberships(groupname):
    group_members = get_group_members(groupname)
    if not group_members:
        print_message("info", f"No user memberships found in group '{groupname}'.")
        return

    print_message("error", f"User Memberships in Group '{groupname}':")
    for i, member in enumerate(group_members, start=1):
        print_message("error", f"{i}. {member}")

    prompt = "Enter the number(s) of the user(s) to delete from the group '{groupname}' (separated by spaces), or enter 'all' to delete all users: "
    choice = input(Fore.MAGENTA + prompt + Style.RESET_ALL)
    if choice.lower() == 'all':
        users_to_delete = group_members
    else:
        selected_indexes = choice.split()
        users_to_delete = [group_members[int(index)-1] for index in selected_indexes if index.isdigit() and 1 <= int(index) <= len(group_members)]

    if not users_to_delete:
        print_message("info", f"No valid users selected for deletion.")
        return

    for user in users_to_delete:
        try:
            if platform.system() == "Darwin":
                subprocess.check_call(["dseditgroup", "-o", "edit", "-d", user, "-t", "user", groupname])
            elif platform.system() == "Linux":
                subprocess.check_call(["sudo", "deluser", user, groupname])
            elif platform.system() == "Windows":
                subprocess.check_call(["net", "localgroup", groupname, user, "/delete"])
            print_message("info", f"User '{user}' deleted from group '{groupname}' successfully.")
        except subprocess.CalledProcessError:
            print_message("error", f"Failed to delete user '{user}' from group '{groupname}'.")

def delete_users(usernames):
    deleted_users = []
    for name in usernames:
        deleted_users.append(name)
        try:
            if platform.system() == "Darwin":
                subprocess.check_call(["sudo", "dscl", ".", "-delete", f"/Users/{name}"])
                message = f"User '{name}' deleted successfully."
                print_message("info", message)
            elif platform.system() == "Linux":
                subprocess.check_call(["sudo", "userdel", name])
                message = f"User '{name}' deleted successfully."
                print_message("info", message)
            elif platform.system() == "Windows":
                # Add Windows-specific deletion logic here
                subprocess.check_call(["net", "user", name, "/delete"])
                message = f"User '{name}' deleted successfully."
                print_message("info", message)
        except subprocess.CalledProcessError:
            print_message("error", f"Failed to delete user: {name}")

        prompt = f"Do you want to delete the home directory of user '{name}' as well? (y/n): "
        choice = input(Fore.MAGENTA + prompt + Style.RESET_ALL)
        if choice.lower() == 'y':
            try:
                if platform.system() == "Darwin":
                    subprocess.check_call(["sudo", "rm", "-rf", f"/Users/{name}"])
                    print_message("info", f"Home directory of user '{name}' deleted successfully.")
                elif platform.system() == "Linux":
                    subprocess.check_call(["sudo", "rm", "-rf", f"/home/{name}"])
                    print_message("info", f"Home directory of user '{name}' deleted successfully.")
                elif platform.system() == "Windows":
                    # Add Windows-specific home directory deletion logic here
                    subprocess.check_call(["rmdir", f"C:\\Users\\{name}", "/s", "/q"])
                    print_message("info", f"Home directory of user '{name}' deleted successfully.")
            except subprocess.CalledProcessError:
                print_message("error", f"Failed to delete home directory of user '{name}' or user '{name}' has no directory")

    print_message("error", f"Deleted user(s): {', '.join(deleted_users)}")

def delete_groups(groupnames):
    deleted_groups = []
    deleted_users = []
    for name in groupnames:
        deleted_groups.append(name)
        try:
            if platform.system() == "Darwin":
                subprocess.check_call(["sudo", "dscl", ".", "-delete", "/Groups/" + name])
            elif platform.system() == "Linux":
                subprocess.check_call(["sudo", "groupdel", name])
            elif platform.system() == "Windows":
                subprocess.check_call(["net", "localgroup", name, "/delete"])
        except subprocess.CalledProcessError:
            print_message("error", f"Failed to delete group: {name}")

        # Check if the group has any users as members
        group_members = get_group_members(name)
        if group_members:
            prompt = f"The group '{name}' has {len(group_members)} user(s) as members. Do you want to delete these users as well? (y/n): "
            choice = input(Fore.MAGENTA + prompt + Style.RESET_ALL)
            if choice.lower() == 'y':
                try:
                    delete_users(group_members)  # Call the existing delete_users function
                    deleted_users.extend(group_members)
                except subprocess.CalledProcessError:
                    print_message("error", f"Failed to delete users: {', '.join(group_members)}")

    print_message("info", f"Deleted group(s): {', '.join(deleted_groups)}")
    if deleted_users:
        print_message("error", f"Deleted user(s): {', '.join(deleted_users)}")

#################### User and Group Information Functions:

def get_user_info_by_username(usernames):
    if isinstance(usernames, str):
        usernames = [usernames]  # Convert single username to a list

    user_info = []
    for username in usernames:
        try:
            user_entry = pwd.getpwnam(username)
            user_info.append(get_user_info([username])[0])
        except KeyError:
            print_message("error", f"User '{username}' not found.")

    if not user_info:
        return

    for user_entry in user_info:
        username = user_entry["Name"]
        print_message("error", f"User: {username}")
        print_horizontal_user_table(user_entry)

        # Print network services (UDP)
        udp_services = get_network_services_udp(username)
        display_network_services(udp_services, "UDP")

        # Print network services (TCP)
        tcp_services = get_network_services_tcp(username)
        display_network_services(tcp_services, "TCP")

        open_files = get_open_files(username)
        if len(open_files) > 20:
            pid_filter = input(Fore.MAGENTA +"There are more than 20 open files. Enter a specific PID to filter the open files, or enter 'all' to print all open files (press Enter to skip): ")
            if pid_filter.lower() == "all":
                print_message("info", f"Open Files for User '{username}':")
                print_open_files(open_files)
            elif pid_filter:  # Check if the user entered a specific PID
                filtered_files = get_open_files(username, pid_filter)
                print_message("info", f"Open Files for User '{username}' (Filtered by PID {pid_filter}):")
                print_open_files(filtered_files)
            else:
                print_message("info", f"You skipped the open file listing.")
        else:
            if open_files:
                print_message("info", f"Open Files for User '{username}':")
                print_open_files(open_files)
            else:
                print_message("info", f"No open files found for User '{username}'.")

def get_group_info_by_groupname(groupname):
    system = platform.system()
    if system == "Darwin":
        try:
            group_info_output = subprocess.check_output(f"dscl . -read /Groups/{groupname}", shell=True, text=True)
            print_message("info", f"Group Information:")
            print(colorize_column(group_info_output, False, Fore.WHITE))  # Set 'False' as the second argument for keys
        except subprocess.CalledProcessError:
            print(colorize_column(f"Group '{groupname}' not found.", True, Fore.RED))  # Add 'True' as the second argument
    elif system == "Windows":
        try:
            group_info_output = subprocess.check_output(f"net localgroup {groupname}", shell=True, text=True)
            print_message("info", f"Group Information:")
            print(colorize_column(group_info_output, False, Fore.WHITE))  # Set 'False' as the second argument for keys
        except subprocess.CalledProcessError:
            print(colorize_column(f"Group '{groupname}' not found.", True, Fore.RED))  # Add 'True' as the second argument
    elif system == "Linux":
        try:
            group_info_output = subprocess.check_output(f"getent group {groupname}", shell=True, text=True)
            print_message("info", f"Group Information:")
            print(colorize_column(group_info_output, False, Fore.WHITE))  # Set 'False' as the second argument for keys
        except subprocess.CalledProcessError:
            print(colorize_column(f"Group '{groupname}' not found.", True, Fore.RED))  # Add 'True' as the second argument
    else:
        print(f"Unsupported system: {system}.")

#################### Main Function:

def main():
    colorama.init(autoreset=True)
    readline.parse_and_bind('"\e[A": previous-history')
    readline.parse_and_bind('"\e[B": next-history')
    readline.parse_and_bind('"\e[C": forward-char')
    readline.parse_and_bind('"\e[D": backward-char')
    init()
    if len(sys.argv) < 2:
        print_message("error", f"No option provided.")
        print_help()
        return

    if len(sys.argv) > 1 and (sys.argv[1] == "-i" or sys.argv[1] == "--interactive"):
        while True:
            print_message("info", f"\n======================================================")
            print_message("info", f"=================User and Group Management==============")
            print_message("info", f"========================================================")
            print("Select an option:")
            print("  1. Display Users Table")
            print("  2. Display Groups Table")
            print("  3. Delete User(s)")
            print("  4. Delete Group(s)")
            print("  5. Get User Information by Username")
            print("  6. Get Group Information by GroupName")
            print("  7. Add User")
            print("  8. Add Group")
            print("  9. startup programs and scripts")
            print("  10. Help")
            print("  0. Quit")
            pass
            choice = input(Fore.MAGENTA + "Enter your choice:" + Style.RESET_ALL)
            if choice == "1":
                while True:
                    print("1. all    : for all Users in OS")
                    print("2. system : for all System users in OS ")
                    print("3. admins  : for all non system users in os")
                    print("4. other  : for all non system users in os")
                    print("0. quit   : go back to main menu")
                    users_choice = input(Fore.MAGENTA + "enter your choice (enter to skip for all users):" + Style.RESET_ALL)
                    if users_choice  == "1" or  users_choice == "all" or users_choice == "":
                        print_user_table("all")
                    elif users_choice == "2" or users_choice == "system":
                        print_user_table("system")
                    elif users_choice == "3" or users_choice == "admins":
                        print_admin_accounts()

                    elif users_choice == "4" or users_choice == "other":
                        print_user_table("other")
                    elif users_choice == "0" or users_choice == "Quit":
                        break
                    else:
                        print_message("error", "please enter a valid argument")
                        break                    

            elif choice == "2":
                while True:
                    print("1. all    : for all groups in OS")
                    print("2. system : for all System groups in OS ")
                    print("3. other  : for all non system groups in os")
                    print("0. quit   : go back to main menu")
                    group_choice = input(Fore.MAGENTA + "enter your choice (enter to skip for all groups):" + Style.RESET_ALL)
                    if group_choice  == "1" or  group_choice == "all" or group_choice == "":
                        print_group_table("all")
                    elif group_choice == "2" or group_choice == "system":
                        print_group_table("system")
                    elif group_choice == "3" or group_choice == "other":
                        print_group_table("other")
                    elif group_choice == "0" or group_choice == "Quit":
                        break
                    else:
                        print_message("error", "please enter a valid argument")
                        break 

            elif choice == "3":
                usernames = input(Fore.MAGENTA + "Enter the username(s) to delete (separated by spaces): " + Style.RESET_ALL).split()
                delete_users(usernames)

            elif choice == "4":
                groupnames = input(Fore.MAGENTA + "Enter the group name(s) to delete (separated by spaces): " + Style.RESET_ALL).split()
                delete_groups(groupnames)

            elif choice == "5":
                username = input(Fore.MAGENTA + "Enter the username: " + Style.RESET_ALL).strip(" ")
                get_user_info_by_username(username)

            elif choice == "6":
                groupname = input(Fore.MAGENTA + "Enter the group name: " + Style.RESET_ALL).strip(" ")
                get_group_info_by_groupname(groupname)

            elif choice == "7":
                username = input(Fore.MAGENTA + "Enter the username to add: " + Style.RESET_ALL)
                add_user(username)

            elif choice == "8":
                groupname = input(Fore.MAGENTA + "Enter the group name to add: " + Style.RESET_ALL)
                add_group(groupname)

            elif choice == "9":
                while True:
                    print("1. all    : for all startups scripts and programs in OS")
                    print("2. system : for all System startups scripts and programs in OS ")
                    print("3. admins : for all administrators startups scripts and programs in os")
                    print("4. user   : for all non system users startups scripts and programs in os")
                    print("0. quit   : go back to main menu")
                    arguments = input(Fore.MAGENTA + "Enter group of users to get startups scripts and programs(Press Enter for All):" + Style.RESET_ALL).strip("")
                    if "all" in arguments or not arguments or "1" in arguments:
                        get_startup_programs("all") 
                    elif "system" in arguments or "2" in arguments:
                        get_startup_programs("system") 
                    elif "admins" in arguments or "3" in arguments:
                        get_startup_programs("admins")
                    elif "user" in arguments or "4" in arguments:
                        get_startup_programs("user") 
                    elif "quit" in arguments or "0" in arguments:
                        break
                    else:
                        print_message("error", "Invalid argument")
                        print_help_gs()
                        break
            elif choice == "10":
                print_help()

            elif choice == "0":
                print_message("info", f"Goodbye!")
                break

            else:
                print_message("error", f"Invalid choice. Please try again.")

    elif len(sys.argv) >= 2:
        option = sys.argv[1]
        arguments = sys.argv[2:]
        if option in ['-ut', '--users-table']:
            if "-h" in arguments:
                print_help_ut()
            elif "all" in arguments or "system" in arguments or "other" in arguments or not arguments:
                print_user_table(arguments)
            elif "admins" in arguments: 
                print_admin_accounts()
            else:
                print_message("error", "please enter a valid argument")
                print_help_ut()
                return
            
        elif option in ['-gt', '--groups-table']:
            if "-h" in arguments:
                print_help_gt()
            elif "all" in arguments or "system" in arguments or "other" in arguments or not arguments:
                print_group_table(arguments)
            else:
                print_message("error", "please enter a valid argument")
                print_help_gt()
                return

        elif option in ['-du', '--delete-users']:
            if len(sys.argv) < 3:
                print_help_du("error", f"Error: username not provided.")
                print_help()
                return
            elif len(sys.argv) >= 3:
                if "-h" in arguments:
                    print_help_du()
                for argument in arguments:
                    delete_users(argument)
            else:
                print_message("error", "Invalid argument")
                print_help_du()
                return

        elif option in ['-dg', '--delete-groups']:
            if len(sys.argv) < 3:
                print_message("error", f"Error: groupname not provided.")
                print_help_dg()
                return
            elif len(sys.argv) >= 3:
                if "-h" in arguments:
                    print_help_dg()
                for argument in arguments:
                    delete_groups(argument)
            else:
                print_message("error", "Invalid argument")
                print_help_dg()
                return

        elif option in ['-dum', '--delete-user-memberships']:
            if len(sys.argv) < 3:
                print_message("error", f"Error: groupname not provided.")
                print_help_dum()
                return
            elif len(sys.argv) >= 3:
                if "-h" in arguments:
                    print_help_dum()
                for argument in arguments:
                    delete_user_memberships(argument)
            else:
                print_message("error", "Invalid argument")
                print_help_dum()
                return

        elif option in ['-gu', '--get-user-info']:
            if len(sys.argv) < 3:
                print_message("error", f"Error: username not provided.")
                print_help_gu()
                return
            elif len(sys.argv) >= 3:
                if "-h" in arguments:
                    print_help_gu()
                for argument in arguments:
                    get_user_info_by_username(argument)
            else:
                print_message("error", "Invalid argument")
                print_help_gu()
                return

        elif option in ['-gs', '--get-startups']:
            if "-h" in arguments:
                print_help_gs()
            elif "all" in arguments or not arguments:
                get_startup_programs("all") 
            elif "system" in arguments:
                get_startup_programs("system") 
            elif "admins" in arguments:
                get_startup_programs("admins")
            elif "user" in arguments:
                get_startup_programs("user") 
            else:
                print_message("error", "Invalid argument")
                print_help_gs()
                return

        elif option in ['-gg', '--get-group-info']:
            if len(sys.argv) < 3:
                print_message("error", f"Error: groupname not provided.")
                print_help_gg()
                return
            elif len(sys.argv) >= 3:
                if "-h" in arguments:
                    print_help_gg()
                for argument in arguments:
                    get_group_info_by_groupname(argument)
            else:
                print_message("error", "Invalid argument")
                print_help_gg()
                return
            
        elif option in ['-au', '--add-user']:
            if len(sys.argv) < 3:
                print_message("error", f"Error: username not provided.")
                print_help_au()
                return
            elif len(sys.argv) >= 3:
                if "-h" in arguments:
                    print_help_au()
                for argument in arguments:
                    add_user(argument)
            else:
                print_message("error", "Invalid argument")
                print_help_au()
                return

        elif option in ['-ag', '--add-group']:
            if len(sys.argv) < 3:
                print_message("error", f"Error: groupname not provided.")
                print_help_ag()
                return
            elif len(sys.argv) >= 3:
                if "-h" in arguments:
                    print_help_ag()
                for argument in arguments:
                    add_group(argument)
            else:
                print_message("error", "Invalid argument")
                print_help_ag()
                return
            
        elif option in ['-h', '--help']:
            print_help()

        else:
            print_message("error", f"Invalid option.")
            print_help()
            
    else:
        print_message("error", f"Invalid option, please check below")
        print_help()       

if __name__ == "__main__":
    main()
