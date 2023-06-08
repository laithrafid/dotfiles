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
import sys
import subprocess
import socket
import ipaddress
from prettytable import PrettyTable
from termcolor import colored


def print_help():
    print("This script is built to run on OSX and Python3")
    print("Usage: python nicetrace.py <local options> <traceroute options> <hostname/IP>")
    print("Example: python nicetrace.py google.com")
    print("         python nicetrace.py 8.8.8.8")
    print("         python nicetrace.py 2001:4860:4860::8888  (IPv6)")
    print("         python nicetrace.py -d -P TCP -p 443 google.com")
    print("<local options> -d/--debug -h/--help")
    print("<traceroute options> [-adDeFInrSvx] [-A as_server] [-f first_ttl] [-g gateway] [-i iface]")
    print("[-M first_ttl] [-m max_ttl] [-p port] [-P proto] [-q nqueries] [-s src_addr]")
    print("[-t tos] [-w waittime] [-z pausemsecs] host [packetlen]")
    sys.exit(0)


def create_colored_table():
    # Create table with colored columns
    table = PrettyTable()
    table.field_names = [
        colored('hop', 'green'),
        colored('Ip address', 'blue'),
        colored('class', 'yellow'),
        colored('kind', 'yellow'),
        colored('Hostname', 'magenta'),
        colored('AS', 'cyan'),
        colored('Organization', 'red'),
        colored('Country', 'green'),
        colored('RTT', 'blue')
    ]
    return table


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
    # Extract options other than -4, -6, -d, and -h
    tr_options = [opt for opt in options if opt not in ['-4', '-6', '-d', '-h']]
    return tr_options


def extract_local_options(options):
    # Extract options other than -4, -6, -d, and -h
    local_options = [opt for opt in options if opt in ['-4', '-6', '-d', '-h']]
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


def parse_output(output):
    # Parse the traceroute output into a table
    table = create_colored_table()
    lines = output.splitlines()
    for line in lines:
        # Parse each line and extract relevant information
        # Modify this part according to the output format of your traceroute command
        # Example: line = ' 1  192.168.1.1  AS12345  example.com  10ms'
        hop, ip, as_number, class_, kind, hostname, org, country, rtt = line.split()
        table.add_row([hop, ip, class_, kind, hostname, as_number, org, country, rtt])
    return table


def main():
    options = sys.argv[1:-1]
    target = sys.argv[-1]

    if '-h' in options or '--help' in options:
        print_help()

    tr_options = extract_tr_options(options)

    if validate_hostname(target):
        if not options or '-4' in options:
            if validate_ipv6(target):
                output = run_traceroute6(target, tr_options)
            else:
                output = run_traceroute(target, tr_options)
        elif '-6' in options:
            if validate_ipv6(target):
                output = run_traceroute6(target, tr_options)
            else:
                print("Invalid target provided for IPv6 traceroute.")
                return
        else:
            print("Invalid options provided.")
            return
    elif validate_ipv4(target):
        if not options or '-4' in options:
            output = run_traceroute(target, tr_options)
        else:
            print("Invalid options provided for IPv4 target.")
            return
    elif validate_ipv6(target):
        if not options or '-6' in options:
            output = run_traceroute6(target, tr_options)
        else:
            print("Invalid options provided for IPv6 target.")
            return
    else:
        print("Invalid target provided.")
        return

    table = parse_output(output)
    print(table)


if __name__ == '__main__':
    main()
