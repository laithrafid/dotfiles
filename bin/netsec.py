#!/usr/bin/python3
'''
pyhton3 script to do these functions : 

Utility Functions:

validate_hostname()
validate_ipv4()
validate_ipv6()
extract_tr_options()
extract_local_options()
classify_ipv4()
classify_ipv6()

Information Retrieval and processing Functions:

tcp2color()
get_whois_info()
parse_output_ipv4()
parse_output_ipv6()

Commnads and Subprocess to Run:

run_traceroute()
run_traceroute6()
check_open_ports()
dns_scan()
scapy_traceroute()

Display Functions:

create_colored_table()

Main Function:
main()

'''
import re
import os
import sys
import subprocess
import socket
import nmap
import ipaddress
import sqlite3
import binascii
import base64
import hashlib
import shutil
import readline  # Added readline module for arrow key support
import threading
import datetime
import struct
import colorama
from colorama import init, Fore, Back, Style
from prettytable import PrettyTable
from datetime import datetime, timedelta
from termcolor import colored
import scapy.all as scapy
from tabulate import tabulate
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad,unpad
#################### Utility Functions:

'''
def create_new_user(username, password):
    # Create the new user
    subprocess.run(['sudo', 'dscl', '.', 'create', f'/Users/{username}'])
    subprocess.run(['sudo', 'dscl', '.', 'create', f'/Users/{username}', 'UserShell', '/bin/bash'])
    subprocess.run(['sudo', 'dscl', '.', 'create', f'/Users/{username}', 'RealName', username])
    subprocess.run(['sudo', 'dscl', '.', 'create', f'/Users/{username}', 'UniqueID', '1001'])
    subprocess.run(['sudo', 'dscl', '.', 'create', f'/Users/{username}', 'PrimaryGroupID', '80'])
    subprocess.run(['sudo', 'dscl', '.', 'create', f'/Users/{username}', 'NFSHomeDirectory', f'/Users/{username}'])
    
    # Set the password for the new user
    subprocess.run(['sudo', 'dscl', '.', 'passwd', f'/Users/{username}', password])
    
    # Grant administrative privileges to the new user
    subprocess.run(['sudo', 'dscl', '.', 'append', f'/Groups/admin', 'GroupMembership', username])
    
    # Enable Remote Management for the new user
    subprocess.run(['sudo', '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart', '-activate', '-configure', '-access', '-on', '-restart', '-agent', '-privs', '-all'])

def execute_script_with_admin_privileges(script_path, args):
    # Execute the script with administrator privileges
    subprocess.run(['/usr/bin/osascript' -e 'do shell script "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on -restart -agent -privs -all" with administrator privileges'])

# Create a new user
new_user = 'newuser'
new_user_password = 'newpassword'
create_new_user(new_user, new_user_password)

# Execute the commands with administrator privileges
script_path = '/path/to/myscript'
script_args = 'arguments_here'
execute_script_with_admin_privileges(script_path, script_args)
'''
''' placeholder Log_keys function order
    mkdir tls/
    touch tls/session-key.log
    export SSLKEYLOGFILE="tls/session-key.log"
    process_tcpdump_output([pcap_filter], num_threads)
    open -n /Applications/Google\ Chrome.app
    tshark -o 'tls.keylog_file:/Users/laithrafid/Desktop/code/tls/session-key.log' -r capture.pcap
'''
def Log_keys(pcap_filter, num_threads):
    # Create the 'tls' directory
    os.makedirs('tls', exist_ok=True)
    
    # Create the session-key.log file
    with open('tls/session-key.log', 'w'):
        pass
    
    # Export SSLKEYLOGFILE environment variable
    os.environ['SSLKEYLOGFILE'] = 'tls/session-key.log'
    
    # Run process_tcpdump_output function with provided arguments
    process_tcpdump_output(pcap_filter, num_threads)
    
    # Open Google Chrome
    subprocess.Popen(['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'])
    
    # Run tshark with the specified options
    tshark_command = ['tshark', '-o', 'tls.keylog_file:tls/session-key.log', '-r', 'capture.pcap']
    subprocess.run(tshark_command)

def validate_hostname(hostname):
    try:
        # Check if hostname is valid
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

def validate_ipv4(ipv4):
    try:
        # Check if IPv4 address is valid
        ipaddress.IPv4Address(ipv4)
        return True
    except ipaddress.AddressValueError:
        return False

def validate_ipv6(ipv6):
    try:
        # Check if IPv6 address is valid
        ipaddress.IPv6Address(ipv6)
        return True
    except ipaddress.AddressValueError:
        return False

def extract_tr_options(options):
    # Extract options other than -4, -6, -how, and --how
    tr_options = [opt for opt in options if opt not in ['-4', '-6']]
    return tr_options

def extract_local_options(options):
    # Extract options other than -4, -6, -how, and --how
    local_options = [opt for opt in options if opt in ['-4', '-6']]
    return local_options

def classify_ipv4(ipv4_address):
    ip = None
    try:
        ip = ipaddress.IPv4Address(ipv4_address)
    except ipaddress.AddressValueError:
        # Extract the IP address part from the string
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ipv4_address)
        if match:
            ip = ipaddress.IPv4Address(match.group(1))
    
    if ip is not None:
        if ip.is_private:
            return 'Private', ''
        else:
            first_byte = int(ip.packed[0])
            if 1 <= first_byte <= 126:
                return 'Public', 'Class A'
            elif 128 <= first_byte <= 191:
                return 'Public', 'Class B'
            elif 192 <= first_byte <= 223:
                return 'Public', 'Class C'
            elif 224 <= first_byte <= 239:
                return 'Public', 'Class D'
            elif 240 <= first_byte <= 255:
                return 'Public', 'Class E'
    
    return '', ''

def classify_ipv6(ipv6_address):
    ip = ipaddress.IPv6Address(ipv6_address)
    if ip.is_private:
        return 'Private'
    elif ip.is_reserved:
        return 'Reserved'
    elif ip.is_loopback:
        return 'Loopback'
    elif ip.is_link_local:
        return 'Link Local'
    elif ip.is_multicast:
        return 'Multicast'
    else:
        return 'Global'

#################### Information Retrieval and processing Functions:
def ping_ipv4(target, options):
    command = ["ping"] + options + [target]
    try:
        ping_process = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
        for line in iter(ping_process.stdout.readline, ''):
            print_colored_output(line)
    except subprocess.CalledProcessError as e:
        print_message("error", f"Ping failed. Check the IPv4 address or hostname. Error: {e.output}")

def ping_ipv6(target, options):
    command = ["ping6"] + options + [target]
    try:
        ping_process = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
        for line in iter(ping_process.stdout.readline, ''):
            print_colored_output(line)
    except subprocess.CalledProcessError as e:
        print_message("error", f"Ping failed. Check the IPv6 address or hostname. Error: {e.output}")

def process_line(line):
    # Define color codes
    ip_header_color = Fore.BLUE
    tcp_header_color = Fore.GREEN
    tcp_data_color = Fore.YELLOW 
    ip_address1_color = Fore.CYAN
    port1_color = Fore.MAGENTA
    ip_address2_color = Fore.YELLOW
    port2_color = Fore.RED
    filter_ok_color = Fore.GREEN
    filter_end_color = Fore.RED
    proc_color = Fore.CYAN
    # Chunk 1: Collect packet data
    if re.match(r'\t0x', line):
        hex_data = re.search(r'^[\t\s]+0x(.*)', line).group(1)
        hex_data = re.sub(r'\s+', '', hex_data)
        raw = bytes.fromhex(hex_data)
        print_message("error", f"  (found {len(raw)} bytes)\n{raw}")
        return

    # Chunk 2.0: IPv4 address format matching
    if re.match(r'^(\s*)((?:\d{1,3}\.){3}\d{1,3})\.(\d+) > ((?:\d{1,3}\.){3}\d{1,3})\.(\d+):', line):
        line = re.sub(r'^(\s*)((?:\d{1,3}\.){3}\d{1,3})\.(\d+) > ((?:\d{1,3}\.){3}\d{1,3})\.(\d+):', rf'\1{ip_address1_color}\2{Style.RESET_ALL}:{port1_color}\3{Style.RESET_ALL} > {ip_address2_color}\4{Style.RESET_ALL}:{port2_color}\5{Style.RESET_ALL}:', line)
        print(line)
        return

    # Chunk 2.1: IPv6 address format matching
    elif re.match(r'^(\s*)([\da-fA-F:]+) > ([\da-fA-F:]+):', line):
        line = re.sub(r'^(\s*)([\da-fA-F:]+) > ([\da-fA-F:]+):', rf'\1{ip_address1_color}\2{Style.RESET_ALL} > {ip_address2_color}\3{Style.RESET_ALL}:', line)
        print(line)
        return

    # Chunk 2.2: IPv6 address with port format matching
    elif re.match(r'^(\s*)([\da-fA-F:]+)\.(\d+) > ([\da-fA-F:]+)\.(\d+):', line):
        line = re.sub(r'^(\s*)([\da-fA-F:]+)\.(\d+) > ([\da-fA-F:]+)\.(\d+):', rf'\1{ip_address1_color}\2{Style.RESET_ALL}:{port1_color}\3{Style.RESET_ALL} > {ip_address2_color}\4{Style.RESET_ALL}:{port2_color}\5{Style.RESET_ALL}:', line)
        print(line)
        return

    # Chunk 2.3: Color formatting for ICMPv6 source and destination IP addresses
    elif re.search(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', line):
        source_ip = re.search(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', line).group(1)
        dest_ip = re.search(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', line).group(2)
        line = re.sub(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', rf'{ip_address1_color}\1{Style.RESET_ALL} > {ip_address2_color}\2{Style.RESET_ALL}', line)
        print(line)
        return

    # Chunk 3: Add red color to timestamp
    elif re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+) ', line):
        line = re.sub(r'^(\d{2}:\d{2}:\d{2}\.\d+) ', rf'{filter_end_color}\1{Style.RESET_ALL} ', line)
        print(line)
        return

    # Chunk 4: Add color to TCP flags
    line = re.sub(r'\b(Flags|Ack|Seq|Win)\b', rf'{tcp_header_color}\1{Style.RESET_ALL}', line)

    # Chunk 5: Add color to IP headers
    line = re.sub(r'\b(IP|ttl)\b', rf'{ip_header_color}\1{Style.RESET_ALL}', line)

    # Chunk 6: Add color to TCP data
    line = re.sub(r'\b0x[\da-fA-F]+\b', rf'{tcp_data_color}\g<0>{Style.RESET_ALL}', line)

    # Chunk 7: Add color to filter expressions
    line = re.sub(r'\b(port|src|dst)\b', rf'{filter_ok_color}\1{Style.RESET_ALL}', line)

    # Chunk 8: Add color to Protocol Details
    line = re.sub(r'\b(Ethernet|IP|TCP|UDP|ICMP|IGMP)\b', r'{tcp_header_color}\1{Style.RESET_ALL}', line)

    # Chunk 9: Add color to Packet Header Information (including ICMP and IGMP)
    line = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rf'{ip_address1_color}\1{Style.RESET_ALL}', line)
    line = re.sub(r' > (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rf' > {ip_address2_color}\1{Style.RESET_ALL}', line)

    # Print the modified line
    print(line)

def get_tcpdump_version():
    tcpdump_version = subprocess.check_output(['sudo', 'tcpdump', '--version'], universal_newlines=True)
    return tcpdump_version.strip()

def read_tcpdump_output(options, num_threads, pcap_input_filename):
    current_directory = os.getcwd()
    
    if not pcap_input_filename:     
        pcap_input_filename = input(Fore.MAGENTA + "Give me filename.pcap: " + Style.RESET_ALL)
    
    pcap_input_path = input(Fore.MAGENTA + "Enter directory of filename.pcap (Press enter if file is in  {current_directory}):" + Style.RESET_ALL)
    if not pcap_input_path: 
        pcap_input_path = current_directory + "/"

    pcap_input_path = ''.join(pcap_input_path)
    pcap_input_filename = ''.join(pcap_input_filename)
    pcap_input_filename = str(pcap_input_filename)
    pcap_input_path = str(pcap_input_path)
    pcap_input_all = str(pcap_input_path  +  pcap_input_filename)
    process_pcap_file(pcap_input_all, options, num_threads)
    
def process_pcap_file(pcap_file_path, options, num_threads):
    read_args = ['sudo', 'tcpdump', '-Knv'] + options.split() + ['-r', pcap_file_path]
    print_message("error", f"{' '.join(read_args)}  will run now:")
    
    # Run tcpdump command and capture the output
    tcpdump_process = subprocess.Popen(read_args, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
    
    # Create a list to hold the worker threads
    worker_threads = []
    
    # Start the worker threads for processing output
    for _ in range(num_threads):
        output_thread = threading.Thread(target=process_output, args=(tcpdump_process,))
        output_thread.start()
        worker_threads.append(output_thread)
    
    # Wait for all worker threads to finish
    for thread in worker_threads:
        thread.join()
    
    # Wait for the tcpdump process to finish
    tcpdump_process.wait()

def process_tcpdump_output(options, num_threads):
    save_output = input(Fore.MAGENTA + "Do you want to save the output? (yes) or (Press enter to continoue without saving): " + Style.RESET_ALL)
    print_message("error", f"Using tcpdump version: {get_tcpdump_version()}")
    if save_output.lower() == "yes":
        # Run tcpdump and save output to pcap file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
        pcap_output_filename = f"tcpdump_output_{timestamp}.pcap"
        save_args = ['sudo', 'tcpdump'] + options + ['-w', pcap_output_filename]
        print_message("error", f"{' '.join(save_args)} will run now:")
        tcpdump_process = subprocess.Popen(save_args,  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Run tcpdump without saving output
    tcpdump_args = ['sudo', 'tcpdump', '-Knv' ,'-tttt'] + options
    print_message("error", f"{' '.join(tcpdump_args)} will run now:")
    # Run tcpdump command and capture the output
    tcpdump_process = subprocess.Popen(tcpdump_args, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
            
        # Create a list to hold the worker threads
    worker_threads = []

        # Start the worker threads for processing output
    for _ in range(num_threads):
        output_thread = threading.Thread(target=process_output, args=(tcpdump_process,))
        output_thread.start()
        worker_threads.append(output_thread)

    # Wait for all worker threads to finish
    for thread in worker_threads:
        thread.join()

    # Wait for the tcpdump process to finish
    tcpdump_process.wait()

    print_message("info", f"finished processing.")

def process_output(tcpdump_process):
    for line in iter(tcpdump_process.stdout.readline, ''):
        line = line.rstrip('\n')
        process_line(line)

def get_whois_info(IP_Address):
    Organization = ''
    Netname = ''
    Country = ''
    #print('this Organization and Country before for IP_Address', IP_Address, Organization, Country)
    try:
        output = subprocess.check_output(['/usr/bin/whois', IP_Address], universal_newlines=True)
        #print('WHOIS Output for {}:'.format(IP_Address))
        #print(output)

        output_lines = output.split('\n')
        for line in output_lines:
            if 'OrgName:' in line:
                Organization = line.split(":")[1].strip()
            elif'org-name:' in line:
                Organization = line.split(":")[1].strip()
            elif 'org:' in line:
                Organization = line.split(":")[1].strip()
            elif 'netname:' in line:
                Netname = line.split(':', 1)[1].strip()
            elif 'NetName' in line:
                Netname = line.split(':', 1)[1].strip()
            elif 'country:' in line:
                Country = line.split(':', 1)[1].strip()
            elif 'Country:' in line:
                Country = line.split(':', 1)[1].strip()

        Organization = Organization if Organization else ''
        Netname = Netname if Netname else ''
        Country = Country if Country else ''
    except Exception:
        pass
    return Organization, Netname, Country

def parse_output_ipv4(output):
    # Parse the IPv4 traceroute output into a table
    table = create_colored_table()
    lines = output.splitlines()
    for line in lines:
        split_line = line.split()
        if line.startswith('*') or split_line[1] == '*':
            # Handle lines starting with stars
            Hop = split_line[0] if len(split_line) > 0 and split_line[0].isdigit() else ' '
            table.add_row([Hop] + ['*'] * 8)  # Add empty space in each column
        else:
            '''good for debuging
            print('split_line.[0]:', split_line[0])
            print('split_line.[1]:', split_line[1])
            print('split_line.[2]:', split_line[2])
            print('split_line.[3:]:', split_line[3:])
            '''
            Hop = split_line[0] if len(split_line) > 0 and split_line[0].isdigit() else ' '
            AS = ''
            Hostname = ''
            IP_Address = ''
            if len(split_line) > 1:
                if split_line[1].startswith('['):
                    AS = split_line[1]
                    Hostname = split_line[2] if len(split_line) > 2 else ''
                    IP_Address = split_line[3].strip('()') if len(split_line) > 3 else ''
                    RTT = ' '.join(split_line[4:]) if len(split_line) > 4 else ''
                    Class = classify_ipv4(split_line[3].strip('()'))
                    Organization, Netname, Country = get_whois_info(split_line[3].strip('()'))

                else:
                    AS = split_line[0] if split_line[0].startswith('[') else ''
                    Hostname = split_line[1] if len(split_line) > 1 else ''
                    IP_Address = split_line[2].strip('()') if len(split_line) > 2 else ''
                    RTT = ' '.join(split_line[3:]) if len(split_line) > 3 else ''
                    Class = classify_ipv4(split_line[2].strip('()'))
                    Organization, Netname, Country = get_whois_info(split_line[2].strip('()'))
            table.add_row([Hop, AS, Hostname, IP_Address, Class, Organization, Netname, Country, RTT])
    return table

def parse_output_ipv6(output):
    # Parse the IPv6 traceroute output into a table
    table = create_colored_table()
    lines = output.splitlines()
    for line in lines:
        split_line = line.split()
        if line.startswith('*') or split_line[1] == '*':
            # Handle lines starting with stars
            Hop = split_line[0] if len(split_line) > 0 and split_line[0].isdigit() else ' '
            table.add_row([Hop] + ['*'] * 8)   # Add empty space in each column
        else:
            '''good for debugging
            print('split_line.[0]:', split_line[0])
            print('split_line.[1]:', split_line[1])
            print('split_line.[2]:', split_line[2])
            print('split_line.[3:]:', split_line[3:])
            '''
            Hop = split_line[0] if len(split_line) > 0 and split_line[0].isdigit() else ' '
            AS = ''
            Hostname = ''
            IP_Address = ''
            if Hop == ' ':
                Hostname = split_line[0] if len(split_line) > 1 else ''
                IP_Address = split_line[1].strip('()') if len(split_line) > 2 else ''
                RTT = ' '.join(split_line[2:]) if len(split_line) > 3 else ''
                Class = classify_ipv6(split_line[1].strip('()'))
                Organization, Netname, Country = get_whois_info(split_line[1].strip('()'))
            else:
                Hostname = split_line[1] if len(split_line) > 1 else ''
                IP_Address = split_line[2].strip('()') if len(split_line) > 2 else ''
                RTT = ' '.join(split_line[3:]) if len(split_line) > 3 else ''
                Class = classify_ipv4(split_line[2].strip('()'))
                Organization, Netname, Country = get_whois_info(split_line[2].strip('()'))
            table.add_row([Hop, AS, Hostname, IP_Address, Class, Organization, Netname, Country, RTT])
    return table

def create_colored_table():
    # Create table with colored columns
    table = PrettyTable()
    table.field_names = [
        colored('Hop', 'green'),
        colored('AS', 'cyan'),
        colored('Hostname', 'magenta'),
        colored('IP Address', 'blue'),
        colored('Class', 'yellow'),
        colored('Organization', 'red'),
        colored('Netname', 'yellow'),
        colored('Country', 'green'),
        colored('RTT', 'blue')
    ]
    table.align = 'c'
    # Set color for each value in the table
    table.format = True
    return table

def get_safe_storage_key(target):
    if "chrome" in target or 'firefox' in target:
        cmd = [
            "security",
            "find-generic-password",
            "-ga",
            "{target}",
            "-w"
        ]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        safe_storage_key = output.strip()
        return safe_storage_key
    except subprocess.CalledProcessError:
        print_message("error","Error getting Chrome Safe Storage Key")
        return None

def decrypt_mac_chrome_secrets(encrypted_value, safe_storage_key):
    iv = b' ' * 16
    key = hashlib.pbkdf2_hmac('sha1', safe_storage_key, b'saltysalt', 1003)[:16]

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    decrypted_pass = cipher.decrypt(encrypted_value)
    decrypted_pass = decrypted_pass.rstrip(b"\x04").decode("utf-8", "ignore")
    decrypted_pass = decrypted_pass.replace("\x08", "")  # Remove backspace characters
    return decrypted_pass

def decrypt_mac_chrome_secrets2(encrypted_value, safe_storage_key):
    if not encrypted_value:
        return ""  # Return empty string for empty encrypted value

    iv = b' ' * 16
    key = hashlib.pbkdf2_hmac('sha1', safe_storage_key, b'saltysalt', 1003)[:16]

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    # Check and remove version tag
    if encrypted_value[:3] == b'v10':
        encrypted_payload = encrypted_value[3:]
    else:
        raise ValueError("Invalid version tag")

    decrypted_pass = cipher.decrypt(encrypted_payload)

    # Remove PKCS7 padding
    padding_length = decrypted_pass[-1]
    padding_value = decrypted_pass[-padding_length:]

    if padding_length > 0 and all(value == padding_length for value in padding_value):
        decrypted_pass = decrypted_pass[:-padding_length]
    else:
        raise ValueError("Invalid padding")

    decrypted_pass = decrypted_pass.decode("utf-8", "ignore")

    return decrypted_pass

def get_datetime(timestamp, target):
    if target == 'chrome' or target == 'edge':
        epoch_start = 11644473600000000
        delta = int(timestamp) - epoch_start
        timestamp_sec = delta // 1000000
    elif target == 'firefox':
        timestamp_sec = int(timestamp)
    elif target == 'safari':
        timestamp_sec = int(timestamp) + 978307200
    else:
        raise ValueError("Unsupported target")

    # Convert timestamp to date and time format
    timestamp_dt = datetime.fromtimestamp(timestamp_sec)

    return timestamp_dt

def process_passwords(safe_storage_key, login_data):
    decrypted_list = []
    conn = None
    try:
        conn = sqlite3.connect(login_data)
        cursor = conn.cursor()
        cursor.execute("SELECT username_value, password_value, origin_url FROM logins")
        rows = cursor.fetchall()
        for row in rows:
            user = row[0]
            encrypted_pass = row[1][3:]  # removing 'v10' prefix
            url = row[2]
            if user == "" or encrypted_pass == "":
                continue
            else:
                decrypted_pass = decrypt_mac_chrome_secrets(encrypted_pass, safe_storage_key)
                url_user_pass_decrypted = (
                    url.encode('ascii', 'ignore'),
                    user.encode('ascii', 'ignore'),
                    decrypted_pass.encode('ascii', 'ignore')
                )
                decrypted_list.append(url_user_pass_decrypted)
    except sqlite3.Error as e:
        print("SQLite error:", e)
    finally:
        if conn:
            conn.close()

    return decrypted_list

def process_cookies(db_path, target):
    cookies_dict = {}
    conn = None
    print_message("info", db_path)
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        if target == 'chrome' or target == 'firefox':
            safe_storage_key = get_safe_storage_key(target)
            if safe_storage_key is None:
                raise ValueError(f"Failed to retrieve {target} Safe Storage Key")

            cursor.execute("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, is_persistent, priority FROM cookies")
            rows = cursor.fetchall()

            for row in rows:
                cookie = {}
                host, name, encrypted_value, path, expires, is_secure, is_httponly, has_expires, is_persistent, priority = row
                expires = get_datetime(expires, target)
                #print("encrypted_value:",encrypted_value)
                decrypted_value = decrypt_mac_chrome_secrets2(encrypted_value, safe_storage_key)
                cookie['name'] = name
                cookie['encrypted_value'] = decrypted_value
                cookie['path'] = path
                cookie['expires'] = str(expires)
                cookie['is_secure'] = bool(is_secure)
                cookie['is_httponly'] = bool(is_httponly)
                cookie['has_expires'] = bool(has_expires)
                cookie['is_persistent'] = bool(is_persistent)

                if host not in cookies_dict:
                    cookies_dict[host] = []
                cookies_dict[host].append(cookie)

        elif target == 'safari':
            cookies_dict = parse_binary_cookies(db_path)
            

    except sqlite3.Error as e:
        print("SQLite error:", e)
    finally:
        if conn:
            conn.close()
    return cookies_dict

def parse_binary_cookies(db_path):
    cookies = []
    with open(db_path, "rb") as f:
        data = f.read()
        buffer_size = 11000
        while len(data) > 0:
            offset = 0
            while offset < len(data) and len(data) - offset >= buffer_size:
                version, url_offset, name_offset, path_offset, value_offset, comment_offset, comment_url_offset, flags, creation, expiration = struct.unpack_from(
                    "!iIIIIiIiII", data, offset
                )
                url = data[url_offset : url_offset + 255]
                name = data[name_offset : name_offset + 255]
                path = data[path_offset : path_offset + 255]
                value = data[value_offset : value_offset + 255]
                comment = data[comment_offset : comment_offset + 255] if comment_offset > 0 else None
                comment_url = data[comment_url_offset : comment_url_offset + 255] if comment_url_offset > 0 else None
                cookie = {
                    "version": version,
                    "url": url,
                    "name": name,
                    "path": path,
                    "value": value,
                    "comment": comment,
                    "comment_url": comment_url,
                    "flags": flags,
                    "creation": creation,
                    "expiration": expiration,
                }
                cookies.append(cookie)
                offset += buffer_size
            data = data[offset:]
    return cookies


def get_cookies(target):
    # Determine the user's operating system
    operating_system = os.name

    if operating_system == 'posix':  # macOS or Linux
        if target == 'chrome':
            profile_path = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default")
            db_path = os.path.join(profile_path, "Cookies")
            filename = "Cookies.db"
        elif target == 'firefox':
            profile_path = os.path.expanduser("~/.mozilla/firefox")
            profile_dir = None
            for directory in os.listdir(profile_path):
                if directory.endswith('.default-release') or directory.endswith('.default'):
                    profile_dir = directory
                    break
            if profile_dir is None:
                raise FileNotFoundError("Firefox profile directory not found")
            db_path = os.path.join(profile_path, profile_dir, "cookies.sqlite")
            filename = "cookies.sqlite"
        elif target == 'safari':
            profile_path = os.path.expanduser("~/Library/Containers/com.apple.Safari/Data/Library/Cookies/")
            db_path = os.path.join(profile_path, "Cookies.binarycookies")
            filename = "Cookies.binarycookies"

        elif target == 'edge':
            profile_path = os.path.expanduser("~/Library/Application Support/Microsoft Edge")
            db_path = os.path.join(profile_path, "Cookies")
            filename = "Cookies"
        else:
            raise ValueError("Unsupported target")
    elif operating_system == 'nt':  # Windows
        if target == 'chrome':
            profile_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default")
            db_path = os.path.join(profile_path, "Cookies")
            filename = "Cookies.db"
        elif target == 'firefox':
            profile_path = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
            profile_dir = None
            for directory in os.listdir(profile_path):
                if directory.endswith('.default-release') or directory.endswith('.default'):
                    profile_dir = directory
                    break
            if profile_dir is None:
                raise FileNotFoundError("Firefox profile directory not found")
            db_path = os.path.join(profile_path, profile_dir, "cookies.sqlite")
            filename = "cookies.sqlite"
        elif target == 'safari':
            raise OSError("Safari is not supported on Windows")
        elif target == 'edge':
            profile_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default")
            db_path = os.path.join(profile_path, "Cookies")
            filename = "Cookies"
        else:
            raise ValueError("Unsupported target")
    else:
        raise OSError("Unsupported operating system")

    # Copy the file to the current directory
    shutil.copyfile(db_path, filename)

    return filename

def get_login_data(target):
    # Determine the user's operating system
    operating_system = os.name

    if operating_system == 'posix':  # macOS or Linux
        if target == 'chrome':
            profile_path = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default")
            login_data = [
                os.path.join(profile_path, "Login Data"),
                os.path.join(profile_path, "Login Data For Account")
            ]
        elif target == 'firefox':
            profile_path = os.path.expanduser("~/.mozilla/firefox")
            profile_dir = None
            for directory in os.listdir(profile_path):
                if directory.endswith('.default-release') or directory.endswith('.default'):
                    profile_dir = directory
                    break
            if profile_dir is None:
                raise FileNotFoundError("Firefox profile directory not found")
            login_data = [
                os.path.join(profile_path, profile_dir, "logins.json")
            ]
        elif target == 'safari':
            profile_path = os.path.expanduser("~/Library/Safari")
            login_data = [
                os.path.join(profile_path, "AutoFillPasswords.plist")
            ]
        elif target == 'edge':
            profile_path = os.path.expanduser("~/Library/Application Support/Microsoft Edge")
            login_data = [
                os.path.join(profile_path, "Web Data")
            ]
        else:
            raise ValueError("Unsupported target")
    elif operating_system == 'nt':  # Windows
        if target == 'chrome':
            profile_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default")
            login_data = [
                os.path.join(profile_path, "Login Data"),
                os.path.join(profile_path, "Login Data For Account")
            ]
        elif target == 'firefox':
            profile_path = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
            profile_dir = None
            for directory in os.listdir(profile_path):
                if directory.endswith('.default-release') or directory.endswith('.default'):
                    profile_dir = directory
                    break
            if profile_dir is None:
                raise FileNotFoundError("Firefox profile directory not found")
            login_data = [
                os.path.join(profile_path, profile_dir, "logins.json")
            ]
        elif target == 'safari':
            raise OSError("Safari is not supported on Windows")
        elif target == 'edge':
            profile_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default")
            login_data = [
                os.path.join(profile_path, "Web Data")
            ]
        else:
            raise ValueError("Unsupported target")
    else:
        raise OSError("Unsupported operating system")

    return login_data

#################### Commnads and Subprocess to Run:

def run_traceroute(target, options):
    # Run traceroute command on target with local options
    #print('Now running traceroute')
    command = ['traceroute']
    command.extend(options)
    command.append(target)
    #print_message("error", f"Running command: {' '.join(command)}")
    output = subprocess.check_output(command, universal_newlines=True)
    #print('Here is the output of traceroute:', output)
    return output

def run_traceroute6(target, options):
    # Run traceroute6 command on target
    #print('now running traceroute6')
    command = ['traceroute6']
    command.extend(options)
    command.append(target)
    #print_message("error", f"Running command: {' '.join(command)}")
    output = subprocess.check_output(command, universal_newlines=True)
    #print('hereis the output of traceroute6', output)
    return output

def check_open_ports(target, ports):
    open_ports = []
    progress = 0
    for port in ports:
        port = int(port)
        packet = scapy.IP(dst=target)/scapy.TCP(dport=port, flags='S')
        response = scapy.sr1(packet, timeout=2, verbose=0)
        if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 'SA':
            open_ports.append(port)
        progress += 1
        print_message("error",f"{progress}/{len(ports)} ports scanned...end=\r")
    return open_ports

def check_open_ports_nmap(target, ports=None):
    nm = nmap.PortScanner()

    if ports is None or "all" in ports:
        ports = range(1, 65536)  # Scan all ports

    total_ports = len(ports)
    open_ports = []

    for i, port in enumerate(ports, start=1):
        print_message("info",f"Scanning port {port}/{total_ports}...for target:{target}")

        nm.scan(target, str(port), arguments='-Pn -T4')

        for host in nm.all_hosts():
            if nm[host].has_tcp(port) and nm[host]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
                break

    return open_ports

def dump_target_sec(target,options):
    # Main code
    if "chrome" in target:
        if "cookies" in options or "all" in options:
            cookies_db = get_cookies(target)
            cookies_dict =  process_cookies(cookies_db, target)
            print_cookies_table(cookies_dict,target)
        
        elif "passwords" in options or "all" in options:
            login_data = get_login_data(target)
            safe_storage_key = get_safe_storage_key(target)
            if safe_storage_key is None:
                sys.exit()

            all_decrypted_passwords = []
            for data_file in login_data:
                if os.path.exists(data_file):
                    # Create a temporary copy of the SQLite database
                    temp_data_file = os.path.join(profile_path, "Temp Login Data")
                    shutil.copyfile(data_file, temp_data_file)
                    decrypted_passwords = process_passwords(safe_storage_key, temp_data_file)
                    all_decrypted_passwords.extend(decrypted_passwords)
                    # Delete the temporary copy
                    os.remove(temp_data_file)


            if all_decrypted_passwords:
                header = (Fore.BLUE + "No.", "Site", "Username", "Password" + Style.RESET_ALL)
                #print(all_decrypted_passwords) only for debuging integrity of sctipt output parsing
                print(f"{header[0]:<5} {header[1]:<30} {header[2]:<20} {header[3]:<20}")
                print("=" * 80)

                for i, x in enumerate(all_decrypted_passwords):
                    print(f"{Fore.GREEN}{i+1:<5}{Style.RESET_ALL} {Fore.CYAN}{x[0].decode():<30}{Style.RESET_ALL} {Fore.YELLOW}{x[1].decode():<20}{Style.RESET_ALL} {Fore.RED}{x[2].decode():<20}{Style.RESET_ALL}")
            else:
                print("No Chrome passwords found in the specified profiles.")
    elif "firefox" in target:
        if "cookies" in options or "all" in options:
            cookies_db = get_cookies(target)
            cookies_dict =  process_cookies(cookies_db, target)
            print_cookies_table(cookies_dict,target)
        else:
            print_message("error",f"no code logic for this target target {target} yet")
    elif "edge" in target:
        if "cookies" in options or "all" in options:
            cookies_db = get_cookies(target)
            cookies_dict =  process_cookies(cookies_db, target)
            print_cookies_table(cookies_dict,target)
        else:
            print_message("error",f"no code logic for this target target {target} yet")
    elif "safari" in target:
        if "cookies" in options or "all" in options:
            cookies_db = get_cookies(target)
            cookies_dict =  process_cookies(cookies_db, target)
            print(cookies_dict)
        else:
            print_message("error",f"no code logic for this target target {target} yet")
    else: 
        print_message("error","Error please Enter a valid target")

#################### Display Functions:
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

def print_colored_output(line):
    line = line.rstrip("\n")  # Remove the trailing newline character
    if "Request timeout for " in line or "100% packet loss" in line:
        line = f"{Fore.RED}{line}{Style.RESET_ALL}"
    elif "ttl=" in line:
        line_parts = line.split()
        for i, part in enumerate(line_parts):
            if "ttl=" in part:
                line_parts[i] = f"{Fore.MAGENTA}{part}{Style.RESET_ALL}"
            elif "time=" in part:
                line_parts[i] = f"{Fore.YELLOW}{part}{Style.RESET_ALL}"
            elif "icmp_seq=" in part:
                line_parts[i] = f"{Fore.GREEN}{part}{Style.RESET_ALL}"
        line = " ".join(line_parts)
    print(line)

def print_cookies_table(cookies_dict, target):
    header = (
        Fore.GREEN + "Host",
        "Cookie Name",
        "Cookie Value",
        "Path",
        "Expires",
        "Is Secure",
        "Is HTTP Only",
        "Has Expires",
        "Is Persistent",
        "Priority" + Style.RESET_ALL
    )
    print(f"{header[0]:<20} {header[1]:<30} {header[2]:<30} {header[3]:<20} {header[4]:<20} {header[5]:<12} {header[6]:<14} {header[7]:<12} {header[8]:<15} {header[9]:<10}")
    print("=" * 160)
    for host, cookies in cookies_dict.items():
        print(f"{Fore.RED}Domain: {host}{Style.RESET_ALL}\n")
        for cookie in cookies:
            is_secure = Fore.GREEN + "Yes" + Style.RESET_ALL if cookie['is_secure'] else Fore.RED + "No" + Style.RESET_ALL
            is_httponly = Fore.GREEN + "Yes" + Style.RESET_ALL if cookie['is_httponly'] else Fore.RED + "No" + Style.RESET_ALL
            has_expires = Fore.GREEN + "Yes" + Style.RESET_ALL if cookie['has_expires'] else Fore.RED + "No" + Style.RESET_ALL
            is_persistent = Fore.GREEN + "Yes" + Style.RESET_ALL if cookie['is_persistent'] else Fore.RED + "No" + Style.RESET_ALL
            priority = cookie.get('priority', '')

            if target == 'chrome' or target == 'edge':
                cookie_value = Fore.GREEN + cookie['encrypted_value'] + Style.RESET_ALL
                print(f"{host:<20} {cookie['name']:<30} {cookie_value:<{len(header[2])}} {cookie['path']:<20} {cookie['expires']:<20} {is_secure:<12} {is_httponly:<14} {has_expires:<12} {is_persistent:<15} {priority:<10}")
            elif target == 'firefox':
                cookie_value = Fore.GREEN + cookie['encrypted_value'] + Style.RESET_ALL
                print(f"{host:<20} {cookie['name']:<30} {cookie_value:<{len(header[2])}} {cookie['path']:<20} {cookie['expires']:<20} {is_secure:<12} {is_httponly:<14} {has_expires:<12} {is_persistent:<15}")
        print("\n")

def print_help():
    print("This script is built to run on Windows, Linux, or macOS.")
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py "+ Fore.CYAN + "[Option]" + Style.RESET_ALL +  Fore.RED + " [Arguments]" + Style.RESET_ALL +"\n")
    print(Fore.CYAN + "Options:"+ Style.RESET_ALL +"\n")
    print("  -i, --interactive        Run the script in interactive mode")
    print("  -tc, --tcpdump-color     Run tcpdump with colorized output")
    print("  -tw, --traceroute_whois  Run traceroute(4|6) and whois on hostname/ip hops")
    print("  -ps, --portscan_scapy    Run ports scan using scapy with colorized output")
    print("  -pn, --portscan_nmap     Run ports scan using Nmap with colorized output")
    print("  -p , --ping              Run ping(4|6) with colorized output")
    print("  -ds, --dump_target_sec  Run functions to dump secrets from targets")
    print("  -h , --help              Show help")
    print_message("error", f"Arguments:\n")
    print("for option specific arguments use options -h")
    print("example: netsec.py -tc -h")

def print_help_ping4():
    p4_options_prompt = subprocess.run(["ping", "-h"], text=True).stdout
    print(p4_options_prompt)

def print_help_ping6():
    p6_options_prompt = subprocess.run(["ping6", "-h"], text=True).stdout
    print(p6_options_prompt)

def print_help_trace():
    tr_options_prompt = subprocess.run(["traceroute", "-h"], text=True).stdout

def print_help_trace6():
    tr6_options_prompt = subprocess.run(["traceroute6", "-h"], text=True).stdout

def print_help_tcpdump():
    tc_options_prompt = subprocess.run(["tcpdump", "-h"], text=True).stdout

def print_help_tc():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + "python netsec.py -tc, --tcpdump-color "+ Style.RESET_ALL + Fore.RED + "[Arguments]" + Style.RESET_ALL + "\n")
    print_message("error", f"[Arguments]:\n")
    print("1. No arguments this will run traceroute without any filters")
    print("  Exampes: host -i src dst proto -Q pid=")
    print("2. -r filename.pcap read tcpdump from file")
    print("3. -h Print help for this subcommand (-tc)")
    print("4. tcpdump options:")
    print_help_tcpdump()

def print_help_tw():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -tw,  --traceroute_whois " + Fore.CYAN + "[local_options]" + Style.RESET_ALL + Fore.RED + "[tr_options]" + Style.RESET_ALL + Fore.GREEN +"[target]" + Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("hostname examples (google.com)")
    print("IPV4               (8.8.8.8)")
    print("IPV6               (2607:f8b0:4004:809::200e)")
    print(Fore.CYAN + "local_options:" + Style.RESET_ALL)
    print(" -4 or -6 for target[hostname]")
    print_message("error", f"tr_options:")
    print_help_trace()
    print_help_trace6()

def print_help_ps():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -ps, --portscan_scapy "+ Style.RESET_ALL + Fore.RED + "[ports]" + Style.RESET_ALL + Fore.GREEN +"[target]"+ Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("hostname examples (google.com)")
    print("IPV4               (8.8.8.8)")
    print("IPV6               (2607:f8b0:4004:809::200e)")
    print_message("error", f"ports")
    print("port[s] separated by spaces")
    print("if no port[s] entered, these ports will be scanned [21,22,25,80,53,443,445,8080,8443]")

def print_help_pn():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -pn, --portscan_nmap "+ Style.RESET_ALL + Fore.RED + "[ports]" + Style.RESET_ALL + Fore.GREEN +"[target]"+ Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("hostname examples (google.com)")
    print("IPV4               (8.8.8.8)")
    print("IPV6               (2607:f8b0:4004:809::200e)")
    print_message("error", f"ports")
    print("port[s] separated by spaces")
    print("if no port[s] entered, these ports will be scanned [21,22,25,80,53,443,445,8080,8443]")

def print_help_p():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -p, --ping "+ Fore.RED + "[ping_options]" + Style.RESET_ALL + Fore.CYAN + "[local_options]" + Style.RESET_ALL + Fore.GREEN +"[target]"+ Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("hostname examples (google.com)")
    print("IPV4               (8.8.8.8)")
    print("IPV6               (2607:f8b0:4004:809::200e)")
    print(Fore.CYAN + "local_options:" + Style.RESET_ALL)
    print("-4/-6 for target[hostname]")
    print_message("error", f"ping_options:")
    print_help_ping4()
    print_help_ping6()

def print_help_ds():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -ds, --dump_target_sec "+ Fore.RED + "[options]" + Style.RESET_ALL  + Fore.GREEN +"[target]"+ Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("chrome")
    print("safari")
    print("edge")
    print("firefox")
    print(Fore.RED + "options:" + Style.RESET_ALL)
    print("all : will print all secrets (cookies and passwords) from target")
    print("cookies : will print table of cookies information grouped by domain like Host, Cookie Name, Cookie Value, Path, Expires,...etc ")
    print("passwords : will print a table of all Sites, Usernames, Passwords")

def print_colored_table_ports(open_ports):
    headers = ["Port"]
    data = [[port] for port in open_ports]
    colored_data = []

    for row in data:
        colored_row = [f"{Fore.GREEN}{cell}{Style.RESET_ALL}" for cell in row]
        colored_data.append(colored_row)

    table = tabulate(colored_data, headers=headers, tablefmt="fancy_grid")
    print(table)

#################### Main Function:
def main():
    colorama.init(autoreset=True)
    readline.parse_and_bind('"\e[A": previous-history')
    readline.parse_and_bind('"\e[B": next-history')
    readline.parse_and_bind('"\e[C": forward-char')
    readline.parse_and_bind('"\e[D": backward-char')
    if len(sys.argv) < 2:
        print_message("error", f"No option provided.")
        print_help()
        return

    if len(sys.argv) > 1 and (sys.argv[1] == "-i" or sys.argv[1] == "--interactive"):
     	while True:
            print_message("info", f"\n========================================================================================")
            print_message("info", f"==============================Network and Security Management=============================")
            print_message("info", f"==========================================================================================")
            print_message("info", f"Select an option:")
            print_message("info", f"  1. Ping")
            print_message("info", f"  2. Run tcpdump with color")
            print_message("info", f"  3. Traceroute with whois")
            print_message("info", f"  4. Portscan using scapy")
            print_message("info", f"  5. Portscan using Nmap")
            print(Fore.YELLOW + "  6. Help" + Style.RESET_ALL)
            print(Fore.RED +"  0. Quit" + Style.RESET_ALL)
            pass
            choice = input(Fore.MAGENTA +  "Enter your choice: " )
            if choice == "1":
                try:
                    target = input(Fore.MAGENTA + "Enter the IP address or hostname to ping:" + Style.RESET_ALL)
                    target = target.strip(" ")
                    options = input(Fore.MAGENTA + "Enter the option(s) -4 or -6 for target(hostname), Press Enter for Autorun(target/hostname>ipv4) or if target(IPv4/IPv6) ping : " + Style.RESET_ALL)
                    if options == "-4":
                        print_help_ping4()
                        p_options = input(Fore.MAGENTA + "Enter Ping options(Press Enter to skip):" + Style.RESET_ALL)
                    elif options == "-6":
                        print_help_ping6()
                        p6_options = input(Fore.MAGENTA + "Enter Ping options(Press Enter to skip):" + Style.RESET_ALL)
                    else:
                        p_options = input(Fore.MAGENTA + "Enter Ping options(Press Enter to skip):" + Style.RESET_ALL)

                    if validate_hostname(target):
                        if not '-4' in options or '-4' in options:
                            ping_ipv4(target, p_options.split())
                        elif '-6' in options:
                            ping_ipv6(target, p6_options.split())
                        else:
                            print_message("error", f"Invalid options provided. ")
                    elif validate_ipv4(target):
                        if not '-4' in options or '-4' in options:
                            ping_ipv4(target, p_options.split())
                        else:
                            print_message("error", f"Invalid options provided for IPv4 target.")
                    elif validate_ipv6(target):
                        if not '-6' in options or '-6' in options:
                            ping_ipv6(target, p6_options.split())
                        else:
                            print_message("error", f"Invalid options provided for IPv6 target.")
                    else:
                        print_message("error", f"Invalid target provided, please Run Again. ")

                except KeyboardInterrupt:
                    print_message("info", "Ping interrupted by user.")
                    continue

            elif choice == "2":
                filter_choices = {
                "1": "port",
                "2": "host",
                "3": "-i",
                "4": "src",
                "5": "dst",
                "6": "proto",  # Protocol
                "7": "-Q pid=" 
                }
                logical_operators = {
                "1": "and",
                "2": "or",
                "3": "not"
                }
                print_message("info", f"Select the main tcpdump filters (you can choose multiple options, press 'Enter' to skip):")
                print_message("info", "  1. Port" )
                print_message("info", "  2. Host" )
                print_message("info", f"  3. Interface")
                print_message("info", f"  4. Source IP")
                print_message("info", f"  5. Destination IP")
                print_message("info", "  6. Protocol" )
                print_message("info", f"  7. PID")
                print_message("error", f"if No filter selected, tcpdump run without any filter(Press Enter)")
                selected_filters = []
                while True:
                    choice = input(Fore.MAGENTA + "Enter the filter choice (1-6) or press 'Enter' to skip: " + Style.RESET_ALL)
                    if choice == "":
                        break
                    if choice in filter_choices:
                        selected_filter = filter_choices[choice]
                        selected_filters.append(selected_filter)
                    else:
                        print_message("error", f"Invalid choice.")
                # If no filters were selected, run tcpdump with no filters    
                if not selected_filters:
                    print_message("info", f"Running tcpdump with no filters.")
                    num_threads = 1
                    color_output = input(Fore.MAGENTA + "Read a file with colors or live? (yes for Read)(no for live) :" + Style.RESET_ALL)
                    if color_output == "yes":
                        read_tcpdump_output([], num_threads,) 
                    elif color_output == "no":
                        process_tcpdump_output([],num_threads)
                    else:
                        break
                else:
                    logical_operator = ""
                    if len(selected_filters) > 1:
                        print_message("info", f"Select the logical operator to combine the filters:")
                        print_message("info", f"  1. AND")
                        print_message("info", f"  2. OR")
                        print_message("info", f"  3. NOT")
                        operator_choice = input(Fore.MAGENTA + "Enter your choice (1-3): " + Style.RESET_ALL)
                        if operator_choice in logical_operators:
                            logical_operator = logical_operators[operator_choice] 
                        else:
                            print_message("error", f"Invalid choice. Using default logical operator 'AND'.")
                            logical_operator = "and"
                    elif len(selected_filters) == 1:
                        operator_choice = input(Fore.MAGENTA + "for logical operator NOT please Enter 3 (or Enter to skip) :" + Style.RESET_ALL)
                        if operator_choice in logical_operators:
                            logical_operator = logical_operators[operator_choice] 
                    else:
                        break

                    # Construct the pcap filter expression based on the selected filters and logical operator
                    pcap_filter = ""
                    for selected_filter in selected_filters:
                        value = input(Fore.MAGENTA + "Enter the value for {selected_filter}: " + Style.RESET_ALL)
                        pcap_filter += f"{selected_filter} {value} {logical_operator} "
                    # Remove the trailing logical operator from the filter expression
                    pcap_filter = pcap_filter.rstrip(" {logical_operator} ")
                    num_threads = 1
                    # Call tcpdump function with the constructed pcap filter expression
                    color_output = input(Fore.MAGENTA + "Read a file with colors or live? (yes for Read)(no for live) :" + Style.RESET_ALL)
                    if color_output == "yes":
                        read_tcpdump_output([pcap_filter], num_threads,)
                    elif color_output == "no":
                        process_tcpdump_output([pcap_filter], num_threads)
                    else:
                        break

            elif choice == "3":
                target = input(Fore.MAGENTA + "Enter the target to run traceroute and whois on :" + Style.RESET_ALL)
                target = target.strip(" ")
                options = input(Fore.MAGENTA + "Enter the option(s) -4 or -6 for target(hostname), Press Enter for Autorun(target/hostname>ipv4) or if target(IPv4/IPv6) traceroute :" + Style.RESET_ALL)

                if options == "-4":
                    print_help_trace()
                    tr_options = input(Fore.MAGENTA + "Enter Traceroute options(Press Enter to skip):" + Style.RESET_ALL)
                elif options == "-6":
                    print_help_trace6()
                    tr_options = input(Fore.MAGENTA + "Enter Traceroute options(Press Enter to skip):" + Style.RESET_ALL)
                else:
                    tr_options = input(Fore.MAGENTA + "Enter Traceroute options(Press Enter to skip):" + Style.RESET_ALL)

                if validate_hostname(target):
                    if not '-4' in options or '-4' in options:
                        output = run_traceroute(target, tr_options.split() + ['-a', '-e'])
                        table = parse_output_ipv4(output)
                        print(table)
                    elif '-6' in options:
                        output = run_traceroute6(target, tr_options.split() + ['-l'])
                        table = parse_output_ipv6(output)
                        print(table)
                    else:
                        print_message("error", f"Invalid options provided. ")
                elif validate_ipv4(target):
                    if not '-4' in options or '-4' in options:
                        output = run_traceroute(target, tr_options.split() + ['-a', '-e'])
                        table = parse_output_ipv4(output)
                        print(table)
                    else:
                        print_message("error", f"Invalid options provided for IPv4 target.")
                elif validate_ipv6(target):
                    if not '-6' in options or '-6' in options:
                        output = run_traceroute6(target, tr_options.split() + ['-l'])
                        table = parse_output_ipv6(output)
                        print(table)
                    else:
                        print_message("error", f"Invalid options provided for IPv6 target.")
                else:
                    print_message("error", f"Invalid target provided, please Run Again. ")

            elif choice == "4":
                targets = input(Fore.MAGENTA + "Enter the ip/hostname(s) to scan (if more than one, separated by spaces): " + Style.RESET_ALL).split()
                if not targets:
                    print_message("info", f"Please enter target IP/hostname to scan")  
                    input(Fore.MAGENTA + "Enter the ip/hostname(s) to scan (if more than one, separated by spaces): " + Style.RESET_ALL).split()                   
                for target in targets:
                    if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target) == 'False':
                        ports = input(Fore.MAGENTA + "Enter the port(s) to scan (separated by spaces): " + Style.RESET_ALL).split()
                        if not ports:
                            ports = [21, 22, 25, 80, 53, 443, 445, 8080, 8443]
                        open_ports = check_open_ports(target, ports)
                        for port in open_ports:
                            print("Open port:", port, "for target:" , target)
                        if ports:
                            ports = list(map(int, ports))
                    else:
                        print_message("info", f"Please enter target IP/hostname to scan")  
                        input(Fore.MAGENTA + "Enter the ip/hostname(s) to scan (if more than one, separated by spaces): " + Style.RESET_ALL).split()
                        ports = input(Fore.MAGENTA + "Enter the port(s) to scan (separated by spaces): " + Style.RESET_ALL).split()
                        if not ports:
                            ports = [21, 22, 25, 80, 53, 443, 445, 8080, 8443]
                        open_ports = check_open_ports(target, ports)
                        for port in open_ports:
                            print("Open port:", port, "for target:" , target)
                        if ports:
                            ports = list(map(int, ports))

            elif choice == "5":
                targets = input(Fore.MAGENTA + "Enter the ip/hostname(s) to scan (if more than one, separated by spaces): " + Style.RESET_ALL).split()
                if not targets:
                    print_message("info", f"Please enter target IP/hostname to scan")  
                    input(Fore.MAGENTA + "Enter the ip/hostname(s) to scan (if more than one, separated by spaces): " + Style.RESET_ALL).split()
                for target in targets:
                    if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target) == 'False':
                        ports = input(Fore.MAGENTA + "Enter the port(s) to scan for target{target} (separated by spaces): " + Style.RESET_ALL).split()
                        if not ports:
                            ports = [21, 22, 25, 80, 53, 443, 445, 8080, 8443]
                            print_message("info",f"these ports : {ports} will be scanned for target:{target}")
                            open_ports = check_open_ports_nmap(target, ports)
                            print_message("info", f"Open ports for {target}:")
                            print_colored_table_ports(open_ports)
                        elif ports == "all":
                            print_message("info",f"these ports : {ports} will be scanned for target:{target}")
                            open_ports = check_open_ports_nmap(target,all)
                            print_message("info", f"Open ports for {target}:")
                            print_colored_table_ports(open_ports)
                        else:
                            print_message("info",f"these ports : {ports} will be scanned for target:{target}")
                            open_ports = check_open_ports_nmap(target,ports)
                            print_message("info", f"Open ports for {target}:")
                            print_colored_table_ports(open_ports)
                    else:
                        break
                        
            elif choice == "6":
                print_help()
            
            elif choice == "0":
                print_message("info", f"Goodbye!")
                break

            else:
                print_message("error", f"Invalid choice. Please try again.")
                print_help()
    
    elif len(sys.argv) >= 2:
        option = sys.argv[1]
        if option in ['-tc', '--tcpdump-color']:
            pcap_filter = sys.argv[2:]
            tc_arguments = [arg for arg in pcap_filter if arg != "-r" and not arg.endswith(".pcap")]
            tc_arguments_str = ' '.join(tc_arguments)
            num_threads = 4
            pcap_input_filename = [arg for arg in pcap_filter if arg.endswith(".pcap")]
            if len(pcap_filter) == 0:
                process_tcpdump_output([],num_threads)
            elif "-r" in pcap_filter :
                read_tcpdump_output(tc_arguments_str,num_threads,pcap_input_filename)
            elif "-h" in pcap_filter :
                print_help_tc()
            else:
                process_tcpdump_output(tc_arguments,num_threads)
        
        elif option in ['-tw', '--traceroute_whois']:
            if len(sys.argv) < 3:
                print_message("info", f"Enter the target to run traceroute and whois on ")
                print_help_tw()
                return
            options = sys.argv[2:-1]
            target = sys.argv[-1]
            tr_options = extract_tr_options(options)
            if '-h' in options:
                print_help_tw()

            if validate_hostname(target):
                if not '-4' in options or '-4' in options:
                    output = run_traceroute(target, (tr_options + ['-a', '-e']))
                    table = parse_output_ipv4(output)
                    print(table)
                elif '-6' in options:
                    output = run_traceroute6(target, (tr_options + ['-l']))
                    table = parse_output_ipv6(output)
                    print(table)
                else:
                    print_message("error", f"Invalid options provided.")
                    print_help_tw()
            elif validate_ipv4(target):
                if not '-4' in options or '-4' in options:
                    output = run_traceroute(target, (tr_options + ['-a', '-e']))
                    table = parse_output_ipv4(output)
                    print(table)
                else:
                    print_message("error", f"Invalid options provided for IPv4 target.")
                    print_help_trace()
            elif validate_ipv6(target):
                if not '-6' in options or '-6' in options:
                    output = run_traceroute6(target, (tr_options + ['-l']))
                    table = parse_output_ipv6(output)
                    print(table)
                else:
                    print_message("error", f"Invalid options provided for IPv6 target.")
                    print_help_trace6()
            else:
                print_message("error", f"Invalid target provided.")
                print_help_tw()
            pass

        elif option in ['-ps', '--portscan_scapy']:
            if len(sys.argv) < 3:
                print_message("info", f"Enter the target to run traceroute and whois on ")
                print_help_ps()
                return
            if len(sys.argv) == 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = [21,22,25,80,53,443,445,8080,8443]
                    open_ports = check_open_ports(target, ports)
                    print_message("info", f"The open ports on the destination host are:")
                    print_colored_table_ports(open_ports)
                else:
                    print_message("error", f"Please enter valid ip/hostname to scan")
                    print_help_ps()
            if len(sys.argv) > 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = sys.argv[2:-1]
                    open_ports = check_open_ports(target, ports)
                    print_message("info", f"The open ports on the destination host are:")
                    print_colored_table_ports(open_ports)
                else:
                    print_message("error", f"Please enter valid ip/hostname to scan")
                    print_help_ps()
            pass

        elif option in ['-pn', '--portscan_nmap']:
            if len(sys.argv) < 3:
                print_message("info",  "Enter the target to scan port using namp on ")
                print_help_pn()
                return
            if len(sys.argv) == 3:
                target = sys.argv[-1]
                ports = [21, 22, 25, 80, 53, 443, 445, 8080, 8443]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    open_ports = check_open_ports_nmap(target, ports)
                    print_message("info", f"The open ports on the destination host are:")
                else:
                    print_message("error", f"Please enter valid ip/hostname to scan")
                    print_help_pn()
            if len(sys.argv) > 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = sys.argv[2:-1]
                    open_ports = check_open_ports_nmap(target, ports)
                    print_message("info", f"Open ports:")
                    print_colored_table_ports(open_ports)
                else:
                    print_message("error", f"Please enter valid ip/hostname to scan")
                    print_help_pn()
            pass

        elif option in ['-p', '--ping']:
            if  "-h" in sys.argv[2:] :
                print_help_p()
            elif len(sys.argv) < 3:
                print_message("info", f"Enter the target to ping")
                print_help_p()
                return
            elif len(sys.argv) >= 3:
                target = sys.argv[-1]
                options = sys.argv[2:-1]
                p_options = [opt for opt in options if opt not in ['-4', '-6']]
                try:
                    if validate_hostname(target):
                        if not '-4' in options or '-4' in options:
                            ping_ipv4(target, p_options)
                        elif '-6' in options:
                            ping_ipv6(target, p_options)
                        else:
                            print_message("error", f"Invalid options provided. ")
                    elif validate_ipv4(target):
                        if not '-4' in options or '-4' in options:
                            ping_ipv4(target, p_options)
                        else:
                            print_message("error","Invalid options provided for IPv4 target." )
                    elif validate_ipv6(target):
                        if not '-6' in options or '-6' in options:
                            ping_ipv6(target, p_options)
                        else:
                            print_message("error","Invalid options provided for IPv6 target." )
                    else:
                        print_message("error", f"Invalid target provided, please Run Again. ")
                except KeyboardInterrupt:
                            print_message("info", "Ping interrupted by user.")
                            sys.exit(0)
            pass    

        elif option in ['-ds', '--dump_target_sec']:
            if  "-h" in sys.argv[2:] :
                print_help_ds()
            elif len(sys.argv) < 3:
                print_message("info", f"No Target target chosen (chrome, firefox, edge, safari) or Options(all, cookies, Passwords)")
                print_help_ds()
                return
            elif len(sys.argv) >= 3:
                target = sys.argv[-1]
                options = sys.argv[2:-1]
                if "firefox" in target or "safari" in target or "edge" in target or "chrome" in target:
                    if "all" in options or "passwords" in options or "cookies" in options:
                        dump_target_sec(target,options)
                    else:
                        print_message("error", "Enter a valid option")
                        print_help_ds()
                else:
                    print_message("error", "Enter a valid target")
                    print_help_ds()

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
