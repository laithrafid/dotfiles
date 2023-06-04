#!/usr/bin/python3
import sys
import subprocess
import socket
import whois
import ipaddress
from termcolor import colored
import argparse
import threading

# Caching dictionary for WHOIS lookups
whois_cache = {}


def print_help():
    # Display usage instructions and examples
    print("Usage: python nicetrace.py [options] <hostname/IP>")
    print("Example: python nicetrace.py google.com")
    print("         python nicetrace.py 8.8.8.8")
    print("         python nicetrace.py 2001:4860:4860::8888  (IPv6)")
    print("This script performs a traceroute to the given hostname/IP address and does a WHOIS lookup for each hop.")
    print("The output is displayed in a table format.")
    print("\nOptions:")
    print("  -t TIMEOUT, --timeout TIMEOUT   Timeout value for traceroute (in seconds) (default: 2)")
    print("  -d, --debug                     Enable debug mode (performs traceroute and runs platform traceroute)")
    sys.exit(0)


def resolve_hostname(hostname):
    try:
        # Resolve the hostname to an IP address
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Error: Failed to resolve the hostname: {e}")
        sys.exit(1)


def get_whois_info(ip):
    if ip in whois_cache:
        return whois_cache[ip]

    retry_times = 3
    for _ in range(retry_times):
        try:
            # Perform a WHOIS lookup for the IP address
            w = whois.whois(ip)
            org = w.get('org', '')
            netname = w.get('netname', '')
            if org and netname and org.lower() == netname.lower():
                netname = ''
            whois_cache[ip] = (org, w.get('country', ''), w.get('city', ''))
            return whois_cache[ip]
        except whois.WhoisException:
            continue

    return '', '', ''


def classify_ip(ip):
    try:
        ip_address = ipaddress.ip_address(ip)
        if ip_address.version == 6:
            return classify_ipv6(ip_address)
        elif ip_address.is_private:
            return 'Private'
        else:
            return classify_ipv4(ip_address)
    except ValueError:
        return ''


def classify_ipv4(ip):
    first_octet = int(ip.exploded.split('.')[0])
    if 1 <= first_octet <= 126:
        return 'Pub (A)'
    elif 128 <= first_octet <= 191:
        return 'Pub (B)'
    elif 192 <= first_octet <= 223:
        return 'Pub (C)'
    elif 224 <= first_octet <= 239:
        return 'Pub (D)'
    else:
        return 'Pub (E)'


def classify_ipv6(ip):
    if ip.is_link_local:
        return 'Link'
    elif ip.is_site_local:
        return 'Site'
    elif ip.is_unique_local:
        return 'Unique'
    elif ip.is_multicast:
        return 'Multicast'
    else:
        return 'Global'


def perform_traceroute(ip_address, timeout):
    try:
        command = ["traceroute", "-w", str(timeout), "-6", ip_address] if ':' in ip_address else ["traceroute", "-w", str(timeout), ip_address]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        print_table_header()

        try:
            for line in iter(process.stdout.readline, ''):
                line_parts = line.split()
                if line_parts[0].isdigit():
                    handle_line(line_parts)
                elif '*' in line_parts:
                    handle_line(['*'] * 4)
                else:
                    line_parts.insert(0, '')
                    handle_line(line_parts)
        except KeyboardInterrupt:
            print("\nTraceroute interrupted by user.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to perform traceroute: {e}")
        sys.exit(1)

def print_table_line(hop, hostname, ip, rtt, org, country, city, classification):
    # Format and print a line of the table
    hop = colored(f"{hop:<5}", 'cyan')
    hostname = colored(f"{hostname:<20}", 'yellow')
    ip = colored(f"{ip:<15}", 'green')
    whois_info = colored(f"{org or ''} ({country or ''} {city or ''})", 'blue')
    classification = colored(f"{classification or ''}", 'cyan')
    rtt = colored(f"{rtt:>8}", 'magenta')
    print(f"{hop} | {hostname} | {ip} | {whois_info:<30} | {classification:<10} | {rtt}")


def handle_line(line_parts):
    hop, hostname, ip, rtt = line_parts[0], line_parts[1], line_parts[2].strip('()'), ' '.join(line_parts[3:])
    org, country, city = get_whois_info(ip)
    classification = classify_ip(ip) if ip != '*' else ''
    print_table_line(hop, hostname, ip, rtt, org, country, city, classification)


def print_table_header():
    # Print the header line of the table
    headers = ["Hop", "Hostname", "IP Addr", "WHOIS", "Class", "RTT"]
    header_row = colored(f"{headers[0]:<5} | {headers[1]:<20} | {headers[2]:<15} | {headers[3]:<30} | {headers[4]:<10} | {headers[5]}", 'yellow')
    print(f"\r{header_row}")
    print("-" * len(header_row))


def debug(ip_address, timeout):
    try:
        command = ["traceroute", "-w", str(timeout), "-6", ip_address] if ':' in ip_address else ["traceroute", "-w", str(timeout), ip_address]
        process = subprocess.Popen(command)
        process.wait()
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to perform traceroute: {e}")
        sys.exit(1)


def perform_traceroute_concurrent(targets, timeout):
    threads = []
    for target in targets:
        thread = threading.Thread(target=perform_traceroute, args=(target, timeout))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="+", help="Hostname(s) or IP address(es)")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout value for traceroute (in seconds)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode (performs traceroute and runs platform traceroute)")

    args = parser.parse_args()

    targets = args.targets
    timeout = args.timeout
    debug_mode = args.debug

    if debug_mode:
        perform_traceroute_concurrent(targets, timeout)
        for target in targets:
            debug(target, timeout)
    else:
        if len(sys.argv) != 2 or sys.argv[1].lower() == "help":
            print_help()

        for target in targets:
            input_value = target
            try:
                socket.inet_pton(socket.AF_INET, input_value)
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, input_value)
                except socket.error:
                    input_value = resolve_hostname(input_value)

            perform_traceroute(input_value, timeout)


if __name__ == '__main__':
    main()
