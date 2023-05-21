#!/usr/bin/perl

use strict;
use warnings;

# Check if the '-v' option is provided
if (@ARGV && $ARGV[0] eq "-v") {
    print "tcpdumpcolor v1.0\n";
    print "Copyright (c) 2023 laith rafid\n\n";
    exit(0);
}

# Define color codes
my $ip_header_color = "\033[0;38;5;18m";
my $tcp_header_color = "\033[0;38;5;52m";
my $tcp_data_color = "\033[0;48;5;10m";
my $ip_address1_color = "\033[1;38;5;51m";
my $port1_color = "\033[1;38;5;46m";
my $ip_address2_color = "\033[1;38;5;208m";
my $port2_color = "\033[1;38;5;226m";
my $filter_ok_color = "\033[1;38;5;46m";
my $filter_end_color = "\033[1;38;5;196m";

# Run tcpdump command and capture the output
open(my $tcpdump_stream, '-|', 'tcpdump', '-Knv', @ARGV) or die "Cannot run tcpdump: $!";

# Process each line of the tcpdump output
while (my $line = <$tcpdump_stream>) {
    # Chunk 1: Collect packet data
    if ($line =~ /^\t0x/) {
        my ($hex_data) = $line =~ /^[\t\s]+0x(.*)/;
        $hex_data =~ s/\s+//g;
        my $raw = pack("H*", $hex_data);
        print "  (found " . length($raw) . " bytes)\n$raw\n";
        next;
    }

    # Chunk 2.0: IPv4 address format matching
    if ($line =~ /^(\s*)((?:\d{1,3}\.){3}\d{1,3})\.(\d+) > ((?:\d{1,3}\.){3}\d{1,3})\.(\d+):/) {
        $line =~ s/^(\s*)((?:\d{1,3}\.){3}\d{1,3})\.(\d+) > ((?:\d{1,3}\.){3}\d{1,3})\.(\d+):/$1$ip_address1_color$2\033[0m:$port1_color$3\033[0m > $ip_address2_color$4\033[0m:$port2_color$5\033[0m:/;
    }

    # Chunk 2.1: IPv6 address format matching
    elsif ($line =~ /^(\s*)([\da-fA-F:]+) > ([\da-fA-F:]+):/) {
           $line =~ s/^(\s*)([\da-fA-F:]+) > ([\da-fA-F:]+):/$1$ip_address1_color$2\033[0m > $ip_address2_color$3\033[0m:/;
    }

    # Chunk 2.2: IPv6 address with port format matching
    elsif ($line =~ /^(\s*)([\da-fA-F:]+)\.(\d+) > ([\da-fA-F:]+)\.(\d+):/) {
           $line =~ s/^(\s*)([\da-fA-F:]+)\.(\d+) > ([\da-fA-F:]+)\.(\d+):/$1$ip_address1_color$2\033[0m:$port1_color$3\033[0m > $ip_address2_color$4\033[0m:$port2_color$5\033[0m:/;
    }
    # Chunk 2.3: Color formatting for ICMPv6 source and destination IP addresses
    if ($line =~ /(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})/) {
        my $source_ip = $1;
        my $dest_ip = $2;
        $line =~ s/(\d{1,3}(?:::\d{1,3}){0,6}) > (\d{1,3}(?:::\d{1,3}){0,6})/$ip_address1_color$source_ip\033[0m > $ip_address2_color$dest_ip\033[0m/;
    }
    # Chunk 3: Add red color to timestamp
    if ($line =~ /^(\d{2}:\d{2}:\d{2}\.\d+) /) {
        $line =~ s/^(\d{2}:\d{2}:\d{2}\.\d+) /$filter_end_color$1\033[0m/;
    }

    # Chunk 4: Add color to TCP flags
    $line =~ s/\b(Flags|Ack|Seq|Win)\b/$tcp_header_color$1\033[0m/g;

    # Chunk 5: Add color to IP headers
    $line =~ s/\b(IP|ttl)\b/$ip_header_color$1\033[0m/g;

    # Chunk 6: Add color to TCP data
    $line =~ s/\b0x[\da-fA-F]+\b/$tcp_data_color$&\033[0m/g;

    # Chunk 7: Add color to filter expressions
    $line =~ s/\b(port|src|dst)\b/$filter_ok_color$1\033[0m/g;

    # Chunk 8: Add color to Protocol Details
    $line =~ s/\b(Ethernet|IP|TCP|UDP|ICMP|IGMP)\b/\033[1;38;5;46m$1\033[0m/g;
    # Chunk 9: Add color to Packet Header Information (including ICMP and IGMP)
    $line =~ s/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/$ip_address1_color$1\033[0m/g;
    $line =~ s/ > (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/$ip_address2_color$1\033[0m/g;

    # Print the modified line
    print $line;
}

# Close file handle
close($tcpdump_stream);

print "tcpdumpcolor has finished processing.\n";
