#!/usr/bin/env python3

import subprocess
import re
import sys

# Check if the '-v' option is provided
if len(sys.argv) > 1 and sys.argv[1] == '-v':
    print("tcpdumpcolor v1.0")
    print("Copyright (c) 2023 laith rafid\n")
    sys.exit(0)

# Define color codes
ip_header_color = '\033[0;38;5;18m'
tcp_header_color = '\033[0;38;5;52m'
tcp_data_color = '\033[0;48;5;10m'
ip_address1_color = '\033[1;38;5;51m'
port1_color = '\033[1;38;5;46m'
ip_address2_color = '\033[1;38;5;208m'
port2_color = '\033[1;38;5;226m'
filter_ok_color = '\033[1;38;5;46m'
filter_end_color = '\033[1;38;5;196m'

# Run tcpdump command and capture the output
tcpdump_args = ['tcpdump', '-Knv'] + sys.argv[1:]
tcpdump_process = subprocess.Popen(tcpdump_args, stdout=subprocess.PIPE)

# Process each line of the tcpdump output
for line in tcpdump_process.stdout:
    line = line.decode('utf-8')

    # Chunk 1: Collect packet data
    if re.match(r'\t0x', line):
        hex_data = re.search(r'^[\t\s]+0x(.*)', line).group(1)
        hex_data = re.sub(r'\s+', '', hex_data)
        raw = bytes.fromhex(hex_data)
        print(f'  (found {len(raw)} bytes)\n{raw}')
        continue

    # Chunk 2.0: IPv4 address format matching
    if re.match(r'^(\s*)((?:\d{1,3}\.){3}\d{1,3})\.(\d+) > ((?:\d{1,3}\.){3}\d{1,3})\.(\d+):', line):
        line = re.sub(r'^(\s*)((?:\d{1,3}\.){3}\d{1,3})\.(\d+) > ((?:\d{1,3}\.){3}\d{1,3})\.(\d+):', rf'\1{ip_address1_color}\2\033[0m:{port1_color}\3\033[0m > {ip_address2_color}\4\033[0m:{port2_color}\5\033[0m:', line)

    # Chunk 2.1: IPv6 address format matching
    elif re.match(r'^(\s*)([\da-fA-F:]+) > ([\da-fA-F:]+):', line):
        line = re.sub(r'^(\s*)([\da-fA-F:]+) > ([\da-fA-F:]+):', rf'\1{ip_address1_color}\2\033[0m > {ip_address2_color}\3\033[0m:', line)

    # Chunk 2.2: IPv6 address with port format matching
    elif re.match(r'^(\s*)([\da-fA-F:]+)\.(\d+) > ([\da-fA-F:]+)\.(\d+):', line):
        line = re.sub(r'^(\s*)([\da-fA-F:]+)\.(\d+) > ([\da-fA-F:]+)\.(\d+):', rf'\1{ip_address1_color}\2\033[0m:{port1_color}\3\033[0m > {ip_address2_color}\4\033[0m:{port2_color}\5\033[0m:', line)

    # Chunk 2.3: Color formatting for ICMPv6 source and destination IP addresses
    if re.search(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', line):
        source_ip = re.search(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', line).group(1)
        dest_ip = re.search(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', line).group(2)
        line = re.sub(r'(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})', rf'{ip_address1_color}{source_ip}\033[0m > {ip_address2_color}{dest_ip}\033[0m', line)

    # Chunk 3: Add red color to timestamp
    if re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+) ', line):
        line = re.sub(r'^(\d{2}:\d{2}:\d{2}\.\d+) ', rf'{filter_end_color}\1\033[0m', line)

    # Chunk 4: Add color to TCP flags
    line = re.sub(r'\b(Flags|Ack|Seq|Win)\b', rf'{tcp_header_color}\1\033[0m', line)

    # Chunk 5: Add color to IP headers
    line = re.sub(r'\b(IP|ttl)\b', rf'{ip_header_color}\1\033[0m', line)

    # Chunk 6: Add color to TCP data
    line = re.sub(r'\b0x[\da-fA-F]+\b', rf'{tcp_data_color}\g<0>\033[0m', line)

    # Chunk 7: Add color to filter expressions
    line = re.sub(r'\b(port|src|dst)\b', rf'{filter_ok_color}\1\033[0m', line)

    # Chunk 8: Add color to Protocol Details
    line = re.sub(r'\b(Ethernet|IP|TCP|UDP|ICMP|IGMP)\b', r'\033[1;38;5;46m\1\033[0m', line)

    # Chunk 9: Add color to Packet Header Information (including ICMP and IGMP)
    line = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rf'{ip_address1_color}\1\033[0m', line)
    line = re.sub(r' > (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rf'{ip_address2_color}\1\033[0m', line)

    # Print the modified line
    print(line, end='')

# Wait for the tcpdump process to finish
tcpdump_process.wait()

print("tcpdumpcolor has finished processing.")
