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
import pwd
import grp
import platform
import sys
import subprocess
import datetime
import psutil
import plistlib
from prettytable import PrettyTable
from colorama import init, Fore, Style
from tabulate import tabulate
from termcolor import colored

#################### Utility Functions:

def print_help():
    print("Usage: python ugsec.py [option] [arguments]\n")
    print("Options:")
    print("  -i, --interactive      Run the script in interactive mode")
    print("  -ut, --users-table      Print the table of all users")
    print("  -ud, --users_discovery  print users who are Administrators and more")
    print("  -gt, --group-table      Print the table of all groups")
    print("  -du, --delete-users     Delete user(s) specified by username(s)")
    print("  -dg, --delete-groups    Delete group(s) specified by group name(s)")
    print("  -gu, --get-user-info    Get detailed information about a specific user")
    print("  -gp, --get-plists       Get all plists in osx ")
    print("  -gg, --get-group-info   Get detailed information about a specific group")
    print("  -au, --add-user         Add a new user with the specified username")
    print("  -ag, --add-group        Add a new group with the specified group name")
    print("  -dum, --delete-user-memberships    Delete user memberships from a group")
    print("  -h, --help             Show help")

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
    user_info = []
    processed_users = set()
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

def get_group_info():
    try:
        command = "dscl . -list /Groups"
        output = subprocess.check_output(command, shell=True, text=True)
        groups = output.strip().split("\n")

        group_info = []
        for i, group in enumerate(groups, start=1):
            group_entry = {
                "Group Name": group,
                "Users": "",
                "Comment": ""
            }
            group_info.append(group_entry)
        
        for group_entry in group_info:
            group = group_entry["Group Name"]
            group_info_output = subprocess.check_output(f"dscl . -read /Groups/{group}", shell=True, text=True)
            lines = group_info_output.split("\n")
            for j, line in enumerate(lines):
                if "GroupMembership:" in line:
                    group_entry["Users"] = line.split(":")[1].strip()
                elif "Comment:" in line and j < len(lines) - 1:
                    group_entry["Comment"] = lines[j + 1].strip()

        return group_info

    except subprocess.CalledProcessError:
        print("Failed to retrieve group information.")
        return []

def get_user_groups(username):
    groups = []
    for group in grp.getgrall():
        if username in group.gr_mem:
            groups.append(group.gr_name)
    return ", ".join(groups)

def get_user_pid(username):
    try:
        command = f"pgrep -u {username}"
        output = subprocess.check_output(command, shell=True, text=True)
        pids = output.strip().split("\n")
        return ", ".join(pids)
    except subprocess.CalledProcessError:
        return "N/A"

def get_last_used(username):
    if platform.system() == "Darwin":  # macOS
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
        try:
            spwd_entry = pwd.getspnam(username)
            last_used_timestamp = spwd_entry.sp_lstchg * 86400  # Convert to seconds
            last_used_datetime = datetime.datetime.fromtimestamp(last_used_timestamp)
            return last_used_datetime.strftime("%Y-%m-%d %H:%M:%S")
        except KeyError:
            return "N/A"

def get_network_services_udp(username):
    try:
        command = f"sudo lsof -iUDP +c0 -a  -nP -u {username}"
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
    try:
        command = f"sudo lsof -iTCP +c0 -a  -nP -u {username}"
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
    command = f"sudo lsof -a -l -n +c0 -u{username}"
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
    try:
        output = subprocess.check_output(["dscl", ".", "-read", f"/Groups/{groupname}", "GroupMembership"])
        members_line = output.decode().strip()
        if members_line.startswith("GroupMembership:"):
            members = members_line.replace("GroupMembership:", "").strip().split()
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

def display_group_table(group_info):
    group_table = PrettyTable(["#", "Group Name", "Users","Comment"])
    group_table.align = "l"

    for i, group_entry in enumerate(group_info, start=1):
        colored_group = colorize_column(group_entry["Group Name"], True, Fore.YELLOW)
        colored_users = colorize_column(group_entry["Users"], True, Fore.GREEN)
        colored_comment = colorize_column(group_entry["Comment"], True, Fore.CYAN)
        colored_raw = colorize_column(i, True, Fore.RED)
        group_table.add_row([colored_raw, colored_group, colored_users, colored_comment])

    print("Group Information:")
    print(group_table)

    total_groups = len(group_info)
    print(f"Total number of groups: {total_groups}")

def display_network_services(services, protocol):
    if not services:
        print(f"No network services ({protocol}) found.")
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

    print(f"Network Services ({protocol}):")
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
        print(f"{colored_key}: {colored_value}")

def print_user_table(data, condition_func=None, truncate=True):
    table = display_user_table(data, condition_func, truncate)
    print(table)

def print_group_table():
    group_info = get_group_info()
    display_group_table(group_info)

def print_group_info(group_info):
    if not group_info:
        print("No group information available.")
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

def print_open_files(open_files):
    if not open_files:
        print("No open files found.")
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
        print("Open Files:")
        print(table)

def print_password_policy():
    if platform.system() == "Windows":
        os.system("net accounts")
    elif platform.system() == "Linux":
        os.system("sudo grep '^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE' /etc/login.defs")
    elif platform.system() == "Darwin":
        os.system("pwpolicy getaccountpolicies")

def print_plist_table():
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


#################### User and Group Management Functions:

def add_user(username):
    additional_options = []

    # Prompt for additional options
    while True:
        option = input("Enter additional option (e.g., -c comment, -s shell) or press Enter to skip: ")
        if option:
            additional_options.append(option)
        else:
            break

    # Prompt for the group to add the user to
    groupname = input("Enter the group to add the user to: ")

    # Prompt for the home directory (optional)
    homedir = input("Enter the home directory for the user (press Enter to skip): ")
    homedir_option = ["NFSHomeDirectory", homedir] if homedir else []

    # Prompt for the password (optional)
    password = getpass.getpass("Enter the password for the user (press Enter to skip): ")
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

        print(f"User '{username}' added successfully to the group '{groupname}' with additional options.")
    except subprocess.CalledProcessError:
        print(f"Failed to add user '{username}' to the group '{groupname}' with additional options.")

def add_group(groupname):
    try:
        subprocess.check_call(["sudo", "dscl", ".", "-create", f"/Groups/{groupname}"])
        print(f"Group '{groupname}' added successfully.")

        # Prompt for comment option
        comment = input("Enter the comment for the group (press Enter to skip): ")
        if comment:
            subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "Comment", comment])

        # Prompt for password option
        password = input("Enter the password for the group (press Enter to skip): ")
        if password:
            subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "Password", password])

        # Prompt for realname option
        realname = input("Enter the real name for the group (press Enter to skip): ")
        if realname:
            subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "RealName", realname])

        # Prompt for users to add to membership
        users = input("Enter the username(s) to add to the group membership (separated by spaces), or press Enter to skip: ")
        if users:
            users = users.split()
            for user in users:
                subprocess.check_call(["sudo", "dscl", ".", "-append", f"/Groups/{groupname}", "GroupMembership", user])

        print("Additional options added successfully.")
    except subprocess.CalledProcessError:
        print(f"Failed to add group '{groupname}' with additional options.")

def delete_user_memberships(groupname):
    group_members = get_group_members(groupname)
    if not group_members:
        print(f"No user memberships found in group '{groupname}'.")
        return

    print(f"User Memberships in Group '{groupname}':")
    for i, member in enumerate(group_members, start=1):
        print(f"{i}. {member}")

    prompt = f"Enter the number(s) of the user(s) to delete from the group '{groupname}' (separated by spaces), or enter 'all' to delete all users: "
    choice = input(prompt)
    if choice.lower() == 'all':
        users_to_delete = group_members
    else:
        selected_indexes = choice.split()
        users_to_delete = [group_members[int(index)-1] for index in selected_indexes if index.isdigit() and 1 <= int(index) <= len(group_members)]

    if not users_to_delete:
        print("No valid users selected for deletion.")
        return

    for user in users_to_delete:
        try:
            subprocess.check_call(["dseditgroup", "-o", "edit", "-d", user, "-t", "user", groupname])
            print(f"User '{user}' deleted from group '{groupname}' successfully.")
        except subprocess.CalledProcessError:
            print(f"Failed to delete user '{user}' from group '{groupname}'.")

def delete_users(usernames):
    deleted_users = []
    for name in usernames:
        deleted_users.append(name)
        try:
            subprocess.check_call(["sudo", "dscl", ".", "-delete", f"/Users/{name}"])
            print(f"User '{name}' deleted successfully.")
        except subprocess.CalledProcessError:
            print(f"Failed to delete user: {name}")

        prompt = f"Do you want to delete the home directory of user '{name}' as well? (y/n): "
        choice = input(prompt)
        if choice.lower() == 'y':
            try:
                subprocess.check_call(["sudo", "rm", "-rf", f"/Users/{name}"])
                print(f"Home directory of user '{name}' deleted successfully.")
            except subprocess.CalledProcessError:
                print(f"Failed to delete home directory of user '{name}'. or user '{name}' has no directory")
    
    print(f"Deleted user(s): {', '.join(deleted_users)}")

def delete_groups(groupnames):
    deleted_groups = []
    deleted_users = []
    for name in groupnames:
        deleted_groups.append(name)
        try:
            subprocess.check_call(["sudo", "dscl", ".", "-delete", "/Groups/" + name])
        except subprocess.CalledProcessError:
            print(f"Failed to delete group: {name}")

        # Check if the group has any users as members
        group_members = get_group_members(name)
        if group_members:
            prompt = f"The group '{name}' has {len(group_members)} user(s) as members. Do you want to delete these users as well? (y/n): "
            choice = input(prompt)
            if choice.lower() == 'y':
                for member in group_members:
                    try:
                        subprocess.check_call(["sudo", "dscl", ".", "-delete", f"/Users/{member}"])
                        deleted_users.append(member)
                    except subprocess.CalledProcessError:
                        print(f"Failed to delete user: {member}")

    print(f"Deleted group(s): {', '.join(deleted_groups)}")
    if deleted_users:
        print(f"Deleted user(s): {', '.join(deleted_users)}")

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
            print(f"User '{username}' not found.")

    if not user_info:
        return

    for user_entry in user_info:
        username = user_entry["Name"]
        print(f"User: {username}")
        print_horizontal_user_table(user_entry)

        # Print network services (UDP)
        udp_services = get_network_services_udp(username)
        display_network_services(udp_services, "UDP")

        # Print network services (TCP)
        tcp_services = get_network_services_tcp(username)
        display_network_services(tcp_services, "TCP")

        open_files = get_open_files(username)
        if len(open_files) > 20:
            pid_filter = input("There are more than 20 open files. Enter a specific PID to filter the open files, or enter 'all' to print all open files (press Enter to skip): ")
            if pid_filter.lower() == "all":
                print(f"Open Files for User '{username}':")
                print_open_files(open_files)
            elif pid_filter:  # Check if the user entered a specific PID
                filtered_files = get_open_files(username, pid_filter)
                print(f"Open Files for User '{username}' (Filtered by PID {pid_filter}):")
                print_open_files(filtered_files)
            else:
                print("You skipped the open file listing.")
        else:
            if open_files:
                print(f"Open Files for User '{username}':")
                print_open_files(open_files)
            else:
                print(f"No open files found for User '{username}'.")

def get_group_info_by_groupname(groupname):
    if groupname.isdigit() and 0 < int(groupname) <= len(group_info):
        index = int(groupname) - 1
        print("Group Information:")
        print_group_info(group_info[index])
    else:
        try:
            group_info_output = subprocess.check_output(f"dscl . -read /Groups/{groupname}", shell=True, text=True)
            print("Group Information:")
            print(colorize_column(group_info_output, False, Fore.WHITE))  # Set 'False' as the second argument for keys
        except subprocess.CalledProcessError:
            print(colorize_column(f"Group '{groupname}' not found.", True, Fore.RED))  # Add 'True' as the second argument

#################### Main Function:

def main():
    init()
    if len(sys.argv) < 2:
        print("No option provided.")
        print_help()
        return
    if len(sys.argv) > 1 and (sys.argv[1] == "-i" or sys.argv[1] == "--interactive"):
        while True:
            print("\n===========================")
            print("User and Group Management")
            print("===========================")
            print("Select an option:")
            print("  1. Display User Information")
            print("  2. Display Group Information")
            print("  3. Delete User(s)")
            print("  4. Delete Group(s)")
            print("  5. Get User Information by Username")
            print("  6. Get Group Information by Group Name")
            print("  7. Add User")
            print("  8. Add Group")
            print("  9. Help")
            print("  0. Quit")
            choice = input("Enter your choice: ")
            if choice == "1":
                print("User Information:")
                user_info = get_user_info([])
                print_user_table(user_info, condition_func=lambda shell: shell != "/usr/bin/false", truncate=True)
                total_users = len(user_info)
                print(f"Total number of users: {total_users}")

            elif choice == "2":
                print_group_table()

            elif choice == "3":
                usernames = input("Enter the username(s) to delete (separated by spaces): ").split()
                delete_users(usernames)

            elif choice == "4":
                groupnames = input("Enter the group name(s) to delete (separated by spaces): ").split()
                delete_groups(groupnames)

            elif choice == "5":
                username = input("Enter the username: ")
                get_user_info_by_username(username)

            elif choice == "6":
                groupname = input("Enter the group name: ")
                get_group_info_by_groupname(groupname)

            elif choice == "7":
                username = input("Enter the username to add: ")
                add_user(username)

            elif choice == "8":
                groupname = input("Enter the group name to add: ")
                add_group(groupname)

            elif choice == "9":
                print_help()

            elif choice == "10":
                groupname = input("Enter the group name to delete users memberships: ")
                delete_user_memberships(groupname)

            elif choice == "0":
                print("Goodbye!")
                break

            else:
                print("Invalid choice. Please try again.")

    elif len(sys.argv) >= 2:
        option = sys.argv[1]
        if option in ['-ut', '--users-table']:
            print("User Information:")
            user_info = get_user_info([])
            print_user_table(user_info, condition_func=lambda shell: shell != "/usr/bin/false", truncate=True)
            total_users = len(user_info)
            print(f"Total number of users: {total_users}")
        
        elif option in ['-gt', '--group-table']:
            print_group_table()
        
        elif option in ['-ud', '--users_discovery']:
            # Get list of Administrator Accounts
            admins = get_admin_accounts()
            colored_admins = colorize_column(", ".join(admins), True, Fore.RED)
            print("administrators accounts:", colored_admins)
            # Prompt for more info about administrators
            prompt = "Do you want more information about the administrators? (y/n): "
            choice = input(prompt)

            if choice.lower() == 'y':
                # Prompt for usernames
                get_user_info_by_username(admins)
            else:
                # Print Password Policy
                print("Password Policy:")
                print_password_policy()
        elif option in ['-du', '--delete-users']:
            if len(sys.argv) < 3:
                print("Error: username not provided.")
                print_help()
                return
            usernames = sys.argv[2:]
            delete_users(usernames)

        elif option in ['-dg', '--delete-groups']:
            if len(sys.argv) < 3:
                print("Error: groupname not provided.")
                print_help()
                return
            groupnames = sys.argv[2:]
            delete_groups(groupnames)

        elif option in ['-dum', '--delete-user-memberships']:
            if len(sys.argv) < 3:
                print("Error: groupname not provided.")
                print_help()
                return
            groupname = sys.argv[2]
            delete_user_memberships(groupname)

        elif option in ['-gu', '--get-user-info']:
            if len(sys.argv) < 3:
                print("Error: username not provided.")
                print_help()
                return
            username = sys.argv[2]
            get_user_info_by_username(username)

        elif option in ['-gp', '--get-plists']:
            colored_table = print_plist_table()
            print(colored_table)

        elif option in ['-gg', '--get-group-info']:
            if len(sys.argv) < 3:
                print("ERROR: groupname not provided.")
                print_help()
                return
            groupname = sys.argv[2]
            get_group_info_by_groupname(groupname)

        elif option in ['-au', '--add-user']:
            if len(sys.argv) < 3:
                print("Error: username not provided.")
                print_help()
                return
            username = sys.argv[2]
            add_user(username)

        elif option in ['-ag', '--add-group']:
            if len(sys.argv) < 3:
                print("ERROR: groupname not provided.")
                print_help()
                return
            groupname = sys.argv[2]
            add_group(groupname)
        elif option in ['-h', '--help']:
            print_help()

        else:
            print("Invalid option.")
            print_help()
            
    else:
        print("Invalid option, please check below")
        print_help()       
if __name__ == "__main__":
    main()
