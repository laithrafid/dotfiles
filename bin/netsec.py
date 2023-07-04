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
import readline  # Added readline module for arrow key support
import threading
import datetime
import colorama
from colorama import init, Fore, Style
from prettytable import PrettyTable
from termcolor import colored
import scapy.all as scapy
from tabulate import tabulate

#################### Utility Functions:

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
        ping_output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print_colored_output(ping_output)
    except subprocess.CalledProcessError as e:
        print_message("error", f"Ping failed. Check the IPv4 address or hostname. Error: {e.output}")

def ping_ipv6(target, options):
    command = ["ping6"] + options + [target]
    try:
        ping_output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print_colored_output(ping_output)
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

def primt_help_tw():
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

def primt_help_ps():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -ps, --portscan_scapy "+ Style.RESET_ALL + Fore.RED + "[ports]" + Style.RESET_ALL + Fore.GREEN +"[target]"+ Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("hostname examples (google.com)")
    print("IPV4               (8.8.8.8)")
    print("IPV6               (2607:f8b0:4004:809::200e)")
    print_message("error", f"ports")
    print("port[s] separated by spaces")
    print("if no port[s] entered, these ports will be scanned [21,22,25,80,53,443,445,8080,8443]")

def primt_help_pn():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -pn, --portscan_nmap "+ Style.RESET_ALL + Fore.RED + "[ports]" + Style.RESET_ALL + Fore.GREEN +"[target]"+ Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("hostname examples (google.com)")
    print("IPV4               (8.8.8.8)")
    print("IPV6               (2607:f8b0:4004:809::200e)")
    print_message("error", f"ports")
    print("port[s] separated by spaces")
    print("if no port[s] entered, these ports will be scanned [21,22,25,80,53,443,445,8080,8443]")

def primt_help_p():
    print(Fore.MAGENTA + "Usage:" + Style.RESET_ALL + " python netsec.py -p, --ping "+ Fore.RED + "[ping_options]" + Style.RESET_ALL + Fore.CYAN + "[local_options]" + Style.RESET_ALL + Fore.GREEN +"[target]"+ Style.RESET_ALL +"\n")
    print(Fore.GREEN +"target:" + Style.RESET_ALL)
    print("hostname examples (google.com)")
    print("IPV4               (8.8.8.8)")
    print("IPV6               (2607:f8b0:4004:809::200e)")
    print(Fore.CYAN + "local_options:" + Style.RESET_ALL)
    print("-4/-6 for target[hostname]")
    print_message("error", f"ping_options:")
    print_help_ping4()
    print_help_trace6()

def print_colored_output(output):
    # Define colors
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    
    lines = output.strip().split('\n')
    for line in lines:
        if "icmp_seq" in line or "64 bytes" in line:
            print(GREEN + line + RESET)
        elif "Destination Host Unreachable" in line or "Request timeout" in line:
            print(RED + line + RESET)
        else:
            print(line)

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
                    if not options or '-4' in options:
                        ping_ipv4(target, p_options.split())
                    elif '-6' in options:
                        ping_ipv6(target, p6_options.split())
                    else:
                        print_message("error", f"Invalid options provided. ")
                elif validate_ipv4(target):
                    if not options or '-4' in options:
                        ping_ipv4(target, p_options.split())
                    else:
                        print_message("error", f"Invalid options provided for IPv4 target.")
                elif validate_ipv6(target):
                    if not options or '-6' in options:
                        ping_ipv6(target, p6_options.split())
                    else:
                        print_message("error", f"Invalid options provided for IPv6 target.")
                else:
                    print_message("error", f"Invalid target provided, please Run Again. ")

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
                    if not options or '-4' in options:
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
                    if not options or '-4' in options:
                        output = run_traceroute(target, tr_options.split() + ['-a', '-e'])
                        table = parse_output_ipv4(output)
                        print(table)
                    else:
                        print_message("error", f"Invalid options provided for IPv4 target.")
                elif validate_ipv6(target):
                    if not options or '-6' in options:
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
                primt_help_tw()
                return
            options = sys.argv[2:-1]
            target = sys.argv[-1]
            tr_options = extract_tr_options(options)
            if '-h' in options:
                primt_help_tw()

            if validate_hostname(target):
                if not options or '-4' in options:
                    output = run_traceroute(target, (tr_options + ['-a', '-e']))
                    table = parse_output_ipv4(output)
                    print(table)
                elif '-6' in options:
                    output = run_traceroute6(target, (tr_options + ['-l']))
                    table = parse_output_ipv6(output)
                    print(table)
                else:
                    print_message("error", f"Invalid options provided.")
                    primt_help_tw()
            elif validate_ipv4(target):
                if not options or '-4' in options:
                    output = run_traceroute(target, (tr_options + ['-a', '-e']))
                    table = parse_output_ipv4(output)
                    print(table)
                else:
                    print_message("error", f"Invalid options provided for IPv4 target.")
                    print_help_trace()
            elif validate_ipv6(target):
                if not options or '-6' in options:
                    output = run_traceroute6(target, (tr_options + ['-l']))
                    table = parse_output_ipv6(output)
                    print(table)
                else:
                    print_message("error", f"Invalid options provided for IPv6 target.")
                    print_help_trace6()
            else:
                print_message("error", f"Invalid target provided.")
                primt_help_tw()
            pass

        elif option in ['-ps', '--portscan_scapy']:
            if len(sys.argv) < 3:
                print_message("info", f"Enter the target to run traceroute and whois on ")
                primt_help_ps()
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
                    primt_help_ps()
            if len(sys.argv) > 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = sys.argv[2:-1]
                    open_ports = check_open_ports(target, ports)
                    print_message("info", f"The open ports on the destination host are:")
                    print_colored_table_ports(open_ports)
                else:
                    print_message("error", f"Please enter valid ip/hostname to scan")
                    primt_help_ps()
            pass

        elif option in ['-pn', '--portscan_nmap']:
            if len(sys.argv) < 3:
                print_message("info",  "Enter the target to scan port using namp on ")
                primt_help_pn()
                return
            if len(sys.argv) == 3:
                target = sys.argv[-1]
                ports = [21, 22, 25, 80, 53, 443, 445, 8080, 8443]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    open_ports = check_open_ports_nmap(target, ports)
                    print_message("info", f"The open ports on the destination host are:")
                else:
                    print_message("error", f"Please enter valid ip/hostname to scan")
                    primt_help_pn()
            if len(sys.argv) > 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = sys.argv[2:-1]
                    open_ports = check_open_ports_nmap(target, ports)
                    print_message("info", f"Open ports:")
                    print_colored_table_ports(open_ports)
                else:
                    print_message("error", f"Please enter valid ip/hostname to scan")
                    primt_help_pn()
            pass

        elif option in ['-p', '--ping']:
            
            if len(sys.argv) < 3:
                print_message("info", f"Enter the target to ping")
                primt_help_p()
                return
            elif len(sys.argv) == 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target):
                    ping_ipv4(target,)
                elif validate_ipv6(target):
                    ping_ipv6(target,)
                else:
                     primt_help_p()
            elif len(sys.argv) > 3:
                target = sys.argv[-1]
                options = sys.argv[2:-1]
                p_options = options.strip("-4","-6")
                if validate_hostname(target):
                    if not options or '-4' in options:
                        ping_ipv4(target, p_options.split())
                    elif '-6' in options:
                        ping_ipv6(target, p6_options.split())
                    else:
                        print_message("error", f"Invalid options provided. ")
                elif validate_ipv4(target):
                    if not options or '-4' in options:
                        ping_ipv4(target, p_options.split())
                    else:
                        print_message("error","Invalid options provided for IPv4 target." )
                elif validate_ipv6(target):
                    if not options or '-6' in options:
                        ping_ipv6(target, p6_options.split())
                    else:
                        print_message("error","Invalid options provided for IPv6 target." )
                else:
                    print_message("error", f"Invalid target provided, please Run Again. ")

            pass    

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
