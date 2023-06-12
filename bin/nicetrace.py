#!/usr/bin/python3
'''
write a pyhton3 script  to do these functions : 
1. create a table (hop, Ip address ,class, Hostname, AS , Organization, Country, RTT ) with each column in different colour add columns to this table depends on traceroute options provided
2. write this script to be run on windows , linux or osx (check tools need installed on os )
3. Run traceroute with traceroute with ability for user to pass through options to run traceroute with host/ip provided 
(if hostname provide then resolve to ipv4 or ipv6 depends on -4 or -6 option provided then run traceroute or traceroute6 ) 
(if ipv4 or ipv6 provided then run traceroute for ipv4 or traceroute6 for ipv6) at the time of starting the script, 
if no ip or hostname provided show a help and how to use this script (script_name = nicetrace.py) like this 
def print_help():
    print("Usage: python nicetrace.py <hostname/IP>")
    print("Example: python nicetrace.py google.com")
    print("         python nicetrace.py 8.8.8.8")
    print("         python nicetrace.py 2001:4860:4860::8888  (IPv6)")
    sys.exit(0)
4. if there's no hop number in the begining of each line then fill it with empty space in hop column
5. put ip in ip address columns and hostnames in hostname column 
6. do whois on every ip of in ip column put result into table
7. Add a function classify each ip in ip column to private or public and which class is it (A,B,C,D,E) for ipv4 or ipv6 (global, linklocal...etc)


'''
import re
import sys
import subprocess
import socket
import ipaddress
import whois
from prettytable import PrettyTable
from termcolor import colored

def print_help():
    print("This script is built to run on Windows, Linux, or macOS.")
    print("Usage: python nicetrace.py <local options> <traceroute options> <hostname/IP>")
    print("Example: python nicetrace.py google.com")
    print("         python nicetrace.py 8.8.8.8")
    print("         python nicetrace.py 2001:4860:4860::8888  (IPv6)")
    print("         python nicetrace.py -d -P TCP -p 443 google.com")
    print("<local options> -4 for IPv4 trace on <hostname>")
    print("                -6 for IPv6 trace on <hostname>")
    print("                -how/--how to show how this script works")
    print("<traceroute options> [-adDeFInrSvx] [-A as_server] [-f first_ttl] [-g gateway] [-i iface]")
    print("[-M first_ttl] [-m max_ttl] [-p port] [-P proto] [-q nqueries] [-s src_addr]")
    print("[-t tos] [-w waittime] [-z pausemsecs] host [packetlen]")
    sys.exit(0)

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
        colored('Country', 'green'),
        colored('RTT', 'blue')
    ]
    table.align = 'c'
    # Set color for each value in the table
    table.format = True
    return table

def get_whois_info(IP_Address):
    organization = ''
    country = ''

    try:
        w = whois.whois(IP_Address)
        if 'org' in w:
            organization = w['org']
            if organization is None:
                organization = ''
        if 'country' in w:
            country = w['country']
            if country is None:
                country = ''
    except Exception:
        pass

    return organization, country


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

def run_traceroute(target, options):
    # Run traceroute command on target with local options
    command = ['traceroute']
    command.extend(options)
    command.append(target)
    output = subprocess.check_output(command, universal_newlines=True)
    return output

def run_traceroute6(target, options):
    # Run traceroute6 command on target
    command = ['traceroute6']
    command.extend(options)
    command.append(target)
    output = subprocess.check_output(command, universal_newlines=True)
    return output

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


def parse_output_ipv4(output):
    # Parse the IPv4 traceroute output into a table
    table = create_colored_table()
    lines = output.splitlines()
    for line in lines:
        split_line = line.split()
        if line.startswith('*'):
            # Handle lines starting with stars
            table.add_row(['*' for _ in range(8)])  # Add empty space in each column
        else:
            Hop = split_line[0] if len(split_line) > 0 and split_line[0].isdigit() else ' '
            AS = ''
            Hostname = ''
            IP_Address = ''
            if len(split_line) > 1:
                if split_line[1].startswith('['):
                    AS = split_line[1]
                    Hostname = split_line[2] if len(split_line) > 2 else ''
                    IP_Address = split_line[3].strip('()') if len(split_line) > 3 else ''
                    RTT = ','.join(split_line[4:]) if len(split_line) > 4 else ''

                else:
                    AS = split_line[0] if split_line[0].startswith('[') else ''
                    Hostname = split_line[1] if len(split_line) > 1 else ''
                    IP_Address = split_line[2].strip('()') if len(split_line) > 2 else ''
                    RTT = ','.join(split_line[3:]) if len(split_line) > 3 else ''
            Class = classify_ipv4(IP_Address)
            Organization, Country = get_whois_info(split_line[2].strip('()'))
            table.add_row([Hop, AS, Hostname, IP_Address, Class, Organization, Country, RTT])
    return table


def parse_output_ipv6(output):
    # Parse the IPv6 traceroute output into a table
    table = create_colored_table()
    lines = output.splitlines()
    for line in lines:
        split_line = line.split()
        if line.startswith('*'):
            # Handle lines starting with stars
            table.add_row(['' for _ in range(8)])  # Add empty space in each column
        else:
            Hop = split_line[0] if len(split_line) > 0 and split_line[0].isdigit() else ' '
            Hostname = split_line[1] if len(split_line) > 1 else ''
            IP_Address = split_line[2].strip('()') if len(split_line) > 2 else ''
            RTT = ' '.join(split_line[3:]) if len(split_line) > 3 else ''
            Class = classify_ipv6(IP_Address)
            Organization, Country = get_whois_info(split_line[2].strip('()'))
            table.add_row([Hop, AS, Hostname, IP_Address, Class, Organization, Country, RTT])
    return table

def main():
    options = sys.argv[1:-1]
    target = sys.argv[-1]

    if '-how' in options or '--how' in options:
        print_help()

    tr_options = extract_tr_options(options)

    if socket.gethostname() == target or socket.gethostbyname(socket.gethostname()) == target:
        print("Target IP address cannot be the same as the local machine.")
        sys.exit(1)

    if validate_hostname(target):
        if not options or '-4' in options:
            if validate_ipv6(target):
                output = run_traceroute6(target, (tr_options + ['-l']))
                table = parse_output_ipv6(output)
                print(table)
            else:
                output = run_traceroute(target, (tr_options + ['-a', '-e']))
                table = parse_output_ipv4(output)
                print(table)
        elif '-6' in options:
            if validate_ipv6(target):
                output = run_traceroute6(target, (tr_options + ['-l']))
                table = parse_output_ipv6(output)
                print(table)
            else:
                print("Invalid target provided for IPv6 traceroute.")
        else:
            print("Invalid options provided.")
    elif validate_ipv4(target):
        if not options or '-4' in options:
            output = run_traceroute(target, (tr_options + ['-l']))
            table = parse_output_ipv4(output)
            print(table)
        else:
            print("Invalid options provided for IPv4 target.")
    elif validate_ipv6(target):
        if not options or '-6' in options:
            output = run_traceroute6(target, (tr_options + ['-l']))
            table = parse_output_ipv6(output)
            print(table)
        else:
            print("Invalid options provided for IPv6 target.")
    else:
        print("Invalid target provided.")

if __name__ == '__main__':
    main()
