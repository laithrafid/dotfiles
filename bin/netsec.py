#!/usr/bin/python3
'''
pyhton3 script to do these functions : 

Utility Functions:

print_help()
validate_hostname()
validate_ipv4()
validate_ipv6()
extract_tr_options()
extract_local_options()
classify_ipv4()
classify_ipv6()

Information Retrieval and Parsing Functions:

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
import sys
import subprocess
import socket
import ipaddress
import readline  # Added readline module for arrow key support
import threading
import datetime
import pcap
from colorama import init, Fore, Style
from prettytable import PrettyTable
from termcolor import colored
from scapy.all import *
from scapy.layers.inet import IP
from tabulate import tabulate

#################### Utility Functions:

def print_help():
    print("This script is built to run on Windows, Linux, or macOS.")
    print("Usage: python netsec.py [option] [arguments] \n")
    print("Options:\n")
    print("  -i, --interactive      Run the script in interactive mode")
    print("  -tc, --tcpdump-color    Run tcpdump with colorized output")
    print("  -tw, --traceroute_whois Run traceroute(6) and whois on hostname/ip hops")
    print("  -tc, --tcpdump-color    Run tcpdump with colorized output")
    print("  -tc, --tcpdump-color    Run tcpdump with colorized output")
    print("  Example: netsec.py -tc src_ip=X.X.X.X")
    print("  -tw, --traceroute_whois Run traceroute(6) and whois on hostname/ip hops")
    print("  Usage: python netsec.py -tw <local options> <traceroute options> <hostname/IP>")
    print("  Example:  netsec.py -tw -4 google.com")
    print("            netsec.py -tw  8.8.8.8")
    print("            netsec.py -tw 2001:4860:4860::8888  (IPv6)")
    print("            netsec.py -tw -d -P TCP -p 443 google.com")
    print("             <local options> ")
    print("             -4 for IPv4 trace on <hostname>")
    print("             -6 for IPv6 trace on <hostname>")
    print("             <traceroute options> ")
    print("             [-adDeFInrSvx] [-A as_server] [-f first_ttl] [-g gateway] [-i iface]")
    print("             [-M first_ttl] [-m max_ttl] [-p port] [-P proto] [-q nqueries] [-s src_addr]")
    print("             [-t tos] [-w waittime] [-z pausemsecs] host [packetlen]")
    print("                                                                  ")
    print("  -h, --help             Show help")

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
    tr_options = [opt for opt in options if opt not in ['-4', '-6', '-how', '--how']]
    return tr_options

def extract_local_options(options):
    # Extract options other than -4, -6, -how, and --how
    local_options = [opt for opt in options if opt in ['-4', '-6', '-how', '--how']]
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

#################### Information Retrieval Functions:

def ping_ipv4(target, options):
    command = ["ping"] + options + [target]
    try:
        ping_output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print_colored_output(ping_output)
    except subprocess.CalledProcessError as e:
        print(f"Ping failed. Check the IPv4 address or hostname. Error: {e.output}")

def ping_ipv6(target, options):
    command = ["ping6"] + options + [target]
    try:
        ping_output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print_colored_output(ping_output)
    except subprocess.CalledProcessError as e:
        print(f"Ping failed. Check the IPv6 address or hostname. Error: {e.output}")

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
    
    # Chunk 1: Collect packet data
    if re.match(r'\t0x', line):
        hex_data = re.search(r'^[\t\s]+0x(.*)', line).group(1)
        hex_data = re.sub(r'\s+', '', hex_data)
        raw = bytes.fromhex(hex_data)
        print(f'  (found {len(raw)} bytes)\n{raw}')
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

def process_output(tcpdump_process):
    for line in iter(tcpdump_process.stdout.readline, ''):
        line = line.rstrip('\n')
        process_line(line)

def process_tcpdump_output(options, num_threads):
    try:
        # Run tcpdump command and capture the output
        tcpdump_args = ['sudo', 'tcpdump', '-Knv'] + options
        check_write = '-w' in options
        print_write = Fore.RED + ' '.join(tcpdump_args) + " will run now:" + Style.RESET_ALL
        print(print_write)

        if check_write:
            # Generate filenames with timestamps
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_output_filename = f"tcpdump_output_{timestamp}.pcap"

            # Create the pcap file object for saving the output
            pcap_output_file = pcap.pcapObject()
            pcap_output_file.open_dead(pcap.DLT_RAW, 65536)  # DLT_RAW for raw packets
            pcap_output_file.dump_open(pcap_output_filename)

            def save_packet_to_file(raw_packet):
                pcap_output_file.dump(raw_packet)

            def save_packet_and_process(tcpdump_process):
                for line in iter(tcpdump_process.stdout.readline, ''):
                    line = line.rstrip('\n')
                    save_packet_to_file(line)
                    process_line(line)
                    print(line)

            tcpdump_process = subprocess.Popen(tcpdump_args, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
            save_packet_and_process(tcpdump_process)
        else:
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

        print("tcpcolor has finished processing.")

    except KeyboardInterrupt:
        print("\ntcpdump interrupted by user.")

    try:
        # Run tcpdump command and capture the output
        tcpdump_args = ['sudo', 'tcpdump', '-Knv'] + options
        check_write = Fore.RED + ' '.join(tcpdump_args) + " will run now:" + Style.RESET_ALL
        print(check_write)
        if check_write == "-w"
            tcpdump_process = subprocess.Popen(tcpdump_args, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
            pcap_output_file = pcap.pcapObject()
            pcap_output_file.open_dead(pcap.DLT_RAW, 65536)  # DLT_RAW for raw packets
            pcap_output_file.dump_open(pcap_output_filename)
            def save_packet_to_file(raw_packet):
                pcap_output_file.dump(raw_packet)

            def save_packet_and_process(tcpdump_process):
                for line in iter(tcpdump_process.stdout.readline, ''):
                    line = line.rstrip('\n')
                    save_packet_to_file(line)
                    process_line(line)
        else:
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

        print("tcpcolor has finished processing.")

    except KeyboardInterrupt:
        print("\ntcpdump interrupted by user.")

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


#################### Commnads and Subprocess to Run:

def run_traceroute(target, options):
    # Run traceroute command on target with local options
    #print('Now running traceroute')
    command = ['traceroute']
    command.extend(options)
    command.append(target)
    #print(f"Running command: {' '.join(command)}")
    output = subprocess.check_output(command, universal_newlines=True)
    #print('Here is the output of traceroute:', output)
    return output

def run_traceroute6(target, options):
    # Run traceroute6 command on target
    #print('now running traceroute6')
    command = ['traceroute6']
    command.extend(options)
    command.append(target)
    #print(f"Running command: {' '.join(command)}")
    output = subprocess.check_output(command, universal_newlines=True)
    #print('hereis the output of traceroute6', output)
    return output

def check_open_ports(target, ports):
    open_ports = []
    progress = 0
    for port in ports:
        packet = scapy.TCP(dst=target, dport=port)
        response = scapy.sr1(packet)
        if response and response.getlayer(scapy.TCP).flags == 'SA':
            open_ports.append(port)
            progress += 1
            print(f"{progress}/{len(ports)} ports scanned...", end="\r")
    return open_ports

def dns_scan(target):
    ans,unans = sr(IP(dst=target)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    if ans:
        print("DNS Server at %s"%target)

def scapy_traceroute(target):
    hops = []
    progress = 0
    for ttl in range(1, 30):
        packet = scapy.IP(dst=target, ttl=ttl)
        response = scapy.sr1(packet)
    if response:
        hops.append(response.getlayer(scapy.IP).src)
        progress += 1
        print(f"{progress}/{len(hops)} hops completed...", end="\r")
        return hops

#################### Display Functions:

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

def print_help_ping4():
    p4_options_prompt = subprocess.run(["ping", "-h"], text=True).stdout
    print(p4_options_prompt)

def print_help_ping6():
    p6_options_prompt = subprocess.run(["ping6", "-h"], text=True).stdout
    print(p6_options_prompt)

def print_help_trace():
    tr_options_prompt = subprocess.run(["traceroute", "-h"], capture_output=True, text=True).stdout.strip().splitlines()
    print(tr_options_prompt)

def print_help_trace6():
    tr6_options_prompt = subprocess.run(["traceroute6", "-h"], capture_output=True, text=True).stdout.strip().splitlines()
    print(tr6_options_prompt)

#################### Main Function:

def main():
    if len(sys.argv) < 2:
        print("No option provided.")
        print_help()
        return
    if len(sys.argv) > 1 and (sys.argv[1] == "-i" or sys.argv[1] == "--interactive"):
     	while True:
            print("\n===========================")
            print("Network and Security Management")
            print("===========================")
            print("Select an option:")
            print("  1. Ping")
            print("  2. Run tcpdump with color")
            print("  3. Traceroute with whois")
            print("  4. Portscan using scapy")
            print("  5. Traceroute using scapy")
            print("  6. Help")
            print("  0. Quit")
            pass
            choice = input("Enter your choice: ")
            if choice == "1":
                target = input("Enter the IP address or hostname to ping: ")
                target = target.strip(" ")
                options = input("Enter the option(s) -4 or -6 for target(hostname), Press Enter for Autorun(target/hostname>ipv4) or if target(IPv4/IPv6) ping : ")
                
                if options == "-4":
                    print_help_ping4()
                    p_options = input("Enter Ping options(Press Enter to skip):")
                elif options == "-6":
                    print_help_ping6()
                    p6_options = input("Enter Ping options(Press Enter to skip):")
                else:
                    p_options = input("Enter Ping options(Press Enter to skip):")

                if validate_hostname(target):
                    if not options or '-4' in options:
                        ping_ipv4(target, p_options.split())
                    elif '-6' in options:
                        ping_ipv6(target, p6_options.split())
                    else:
                        print("Invalid options provided. ")
                elif validate_ipv4(target):
                    if not options or '-4' in options:
                        ping_ipv4(target, p_options.split())
                    else:
                        print("Invalid options provided for IPv4 target.")
                elif validate_ipv6(target):
                    if not options or '-6' in options:
                        ping_ipv6(target, p6_options.split())
                    else:
                        print("Invalid options provided for IPv6 target.")
                else:
                    print("Invalid target provided, please Run Again. ")

            elif choice == "2":
                filter_choices = {
                "1": "port",
                "2": "host",
                "3": "-i",
                "4": "src",
                "5": "dst",
                "6": "proto",  # Protocol
                }
                logical_operators = {
                "1": "and",
                "2": "or"
                }
                print("Select the main tcpdump filters (you can choose multiple options, press 'Enter' to finish):")
                print("  1. Port")
                print("  2. Host")
                print("  3. Interface")
                print("  4. Source IP")
                print("  5. Destination IP")
                print("  6. Protocol")
                print("  if No filter selected, tcpdump run without any filter(Press Enter)")
                selected_filters = []
                while True:
                    choice = input("Enter the filter choice (1-6) or press 'Enter' to finish: ")
                    if choice == "":
                        break
                    if choice in filter_choices:
                        selected_filter = filter_choices[choice]
                        selected_filters.append(selected_filter)
                    else:
                        print("Invalid choice.")
                
                # If no filters were selected, run tcpdump with no filters    
                if not selected_filters:
                    num_threads = 1                    
                    print("Running tcpdump with no filters.")
                    save_output = input("Do you want to save the output? (yes/no): ")
                    if save_output.lower() == "yes":
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        pcap_output_filename = f"tcpdump_output_{timestamp}.pcap"
                        process_tcpdump_output(["-w","pcap_output_filename"], num_threads)
                    else:
                        process_tcpdump_output([], num_threads)
                else:
                    logical_operator = ""
                    if len(selected_filters) > 1:
                        print("Select the logical operator to combine the filters:")
                        print("  1. AND")
                        print("  2. OR")
                        operator_choice = input("Enter your choice (1-2): ")
                        if operator_choice in logical_operators:
                            logical_operator = logical_operators[operator_choice]
                        else:
                            print("Invalid choice. Using default logical operator 'AND'.")
                            logical_operator = "and"
                    else:
                        logical_operator = "and"

                    # Construct the pcap filter expression based on the selected filters and logical operator
                    pcap_filter = ""
                    for selected_filter in selected_filters:
                        value = input(f"Enter the value for {selected_filter}: ")
                        pcap_filter += f"{selected_filter} {value} {logical_operator} "

                # Remove the trailing logical operator from the filter expression
                pcap_filter = pcap_filter.rstrip(f" {logical_operator} ")
                save_output = input("Do you want to save the output? (yes/no): ")

                # Call tcpdump function with the constructed pcap filter expression
                num_threads = 1
                save_output = input("Do you want to save the output? (yes/no): ")
                if save_output.lower() == "yes":
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    pcap_output_filename = f"tcpdump_output_{timestamp}.pcap"
                    process_tcpdump_output([pcap_filter, "-w", pcap_output_filename], num_threads)
                else:
                process_tcpdump_output([pcap_filter], num_threads)

            elif choice == "3":
                target = input("Enter the target to run traceroute and whois on: ")
                target = target.strip(" ")
                options = input("Enter the option(s) -4 or -6 for target(hostname), Press Enter for Autorun(target/hostname>ipv4) or if target(IPv4/IPv6) traceroute : ")

                if options == "-4":
                    print_help_trace()
                    tr_options = input("Enter Traceroute options(Press Enter to skip):")
                elif options == "-6":
                    print_help_trace6()
                    tr_options = input("Enter Traceroute options(Press Enter to skip):")
                else:
                    tr_options = input("Enter Traceroute options(Press Enter to skip):")

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
                        print("Invalid options provided. ")
                elif validate_ipv4(target):
                    if not options or '-4' in options:
                        output = run_traceroute(target, tr_options.split() + ['-a', '-e'])
                        table = parse_output_ipv4(output)
                        print(table)
                    else:
                        print("Invalid options provided for IPv4 target.")
                elif validate_ipv6(target):
                    if not options or '-6' in options:
                        output = run_traceroute6(target, tr_options.split() + ['-l'])
                        table = parse_output_ipv6(output)
                        print(table)
                    else:
                        print("Invalid options provided for IPv6 target.")
                else:
                    print("Invalid target provided, please Run Again. ")

            elif choice == "4":
                target = input("Enter the ip/hostname(s) to scan (if more than one, separated by spaces): ").split()
                if target == '': 
                    print("please enter target ip/hostname to scan")
                else:
                    ports = input("Enter the port(s) to scan (separated by spaces): ").split()
                    if ports == '':
                        ports = [21,22,25,80,53,443,445,8080,8443]
                        open_ports = check_open_ports(target,ports)
                        dns = dns_scan(target)
                        for port in open_ports:
                            print(port)
                            print(dns)
                    else: 
                        open_ports = check_open_ports(target,ports)
                        dns = dns_scan(target)
                        for port in open_ports:
                            print(port)
                            print(dns)

            elif choice == "5":
                target = input("Enter the target ip/hostname to traceroute using scapy: ")
                scapy_traceroute(target)
            
            elif choice == "6":
                print_help()
           
            elif choice == "0":
                print("Goodbye!")
                break

            else:
                print("Invalid choice. Please try again.")
                print_help()
    
    elif len(sys.argv) >= 2:
        option = sys.argv[1]
        if option in ['-tc', '--tcpdump-color']:
            tc_arguments = sys.argv[2:]
            tcp2color(tc_arguments)
        
        elif option in ['-tw', '--traceroute_whois']:
            if len(sys.argv) < 3:
                print("Enter the target to run traceroute and whois on ")
                print_help()
                return
            options = sys.argv[2:-1]
            target = sys.argv[-1]
            tr_options = extract_tr_options(options)
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
                    print("Invalid options provided.")
                    print_help()
            elif validate_ipv4(target):
                if not options or '-4' in options:
                    output = run_traceroute(target, (tr_options + ['-a', '-e']))
                    table = parse_output_ipv4(output)
                    print(table)
                else:
                    print("Invalid options provided for IPv4 target.")
                    print_help()

            elif validate_ipv6(target):
                if not options or '-6' in options:
                    output = run_traceroute6(target, (tr_options + ['-l']))
                    table = parse_output_ipv6(output)
                    print(table)
                else:
                    print("Invalid options provided for IPv6 target.")
                    print_help()
            else:
                print("Invalid target provided.")
                print_help()
            pass

        elif option in ['-ps', '--portscan_scapy']:
            if len(sys.argv) < 3:
                print("Enter the target to run traceroute and whois on ")
                print_help()
                return
            if len(sys.argv) == 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = [21,22,25,80,53,443,445,8080,8443]
                    open_ports = check_open_ports(target, ports)
                    dns_scan(target)
                    print('The open ports on the destination host are:')
                    for port in open_ports:
                        print(port)
                else:
                    print("please enter valid ip/hostname to scan")
                    print_help()
            if len(sys.argv) > 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = sys.argv[2:-1]
                    open_ports = check_open_ports(target, ports)
                    dns_scan(target)	
                    print('The open ports on the destination host are:')
                    for port in open_ports:
                        print(port)
                else:
                    print("please enter valid ip/hostname to scan")
                    print_help()
            pass

        elif option in ['-ps', '--portscan_nmap']:
            if len(sys.argv) < 3:
                print("Enter the target to run traceroute and whois on ")
                print_help()
                return
            if len(sys.argv) == 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = [21,22,25,80,53,443,445,8080,8443]
                    open_ports = check_open_ports_nmap(target, ports)
                    print('The open ports on the destination host are:')
                    for port in open_ports:
                        print(port)
                else:
                    print("please enter valid ip/hostname to scan")
                    print_help()
            if len(sys.argv) > 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    ports = sys.argv[2:-1]
                    open_ports = check_open_ports_nmap(target, ports)
                    print('The open ports on the destination host are:')
                    for port in open_ports:
                        print(port)
                else:
                    print("please enter valid ip/hostname to scan")
                    print_help()
            pass
        elif option in ['-tss', '--traceroute_scapy']:
            if len(sys.argv) < 3:
                print("Enter the target to run traceroute using scapy on ")
                print_help()
                return
            if len(sys.argv) == 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                    scapy_traceroute(target)
                else:
                    print("please enter valid ip/hostname to scan")
                    print_help()
            if len(sys.argv) > 3:
                print("please enter only one valid ip/hostname to scan")
                print_help()
            pass
        elif option in ['-p', '--ping']:
            '''
            if len(sys.argv) < 3:
                print("Enter the target to ping")
                print_help()
                return
            if len(sys.argv) == 3:
                target = sys.argv[-1]
                if validate_hostname(target) or validate_ipv4(target) or validate_ipv6(target):
                else:
                    print("please enter valid ip/hostname to scan")
                    print_help()
            if len(sys.argv) > 3:
                print("please enter only one valid ip/hostname to scan")
                print_help()
            pass
            '''
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
