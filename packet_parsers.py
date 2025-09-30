# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print_hex_dump(hex_data)

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route the payload based on the EtherType.
    if ether_type == "0806":            # 0806 (ARP)
        parse_arp_header(payload)
    elif ether_type == "0800":          # 0800 (IPv4)
        parse_ipv4_header(payload)
    elif ether_type == "86dd":          # 86dd (IPv6)
        parse_ipv6_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


def print_hex_dump(data):

    # Handle hex string (which is what we receive)
    if isinstance(data, str):
        hex_str = data
    else:
        hex_str = data.hex()

    print("Hex Dump:")
    
    for i in range(0, len(hex_str), 32):  # 32 hex chars = 16 bytes
        offset = i // 2
        line = hex_str[i:i+32]
        
        formatted = ' '.join(line[j:j+2] for j in range(0, len(line), 2)) # Insert spaces every 2 characters
        print(f"{offset:04x}   {formatted}")

    print() # Blank line spacing before Ethernet Header info



def parse_icmp_header(hex_data):
    
    icmp_type = int(hex_data[0:2], 16)  # Type - 1 byte
    code = int(hex_data[2:4], 16)       # Code - 1 byte  
    checksum = int(hex_data[4:8], 16)   # Checksum - 2 bytes
    rest_of_header = hex_data[8:16]     # rest_of_header vary by ICMP type, contains additional fields based on the msg type.
    
    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[0:2]:<20} | {icmp_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")
    
    # For ping (Echo Request/Reply), the next 4 bytes are ID and Sequence
    if icmp_type in [8, 0]:  # Echo Request (8) or Echo Reply (0)
        identifier = int(hex_data[8:12], 16)
        sequence = int(hex_data[12:16], 16)
        print(f"  {'Identifier:':<25} {hex_data[8:12]:<20} | {identifier}")
        print(f"  {'Sequence Number:':<25} {hex_data[12:16]:<20} | {sequence}")
    else:
        print(f"  {'Rest of Header:':<25} {rest_of_header}")
    
    # Show payload if it exists (ping data)
    if len(hex_data) > 16:
        payload = hex_data[16:]
        print(f"  {'Payload (hex):'} {payload}")
    
    return icmp_type, code



def parse_icmpv6_header(hex_data):
   
    icmpv6_type = int(hex_data[0:2], 16)    # Type - 1 byte
    code = int(hex_data[2:4], 16)           # Code - 1 byte
    checksum = hex_data[4:8]                # Checksum - 2 bytes
    message_body = hex_data[8:16]           # Message body varies by type (4 bytes typically)
    
    print(f"ICMPv6 Header:")
    print(f"  {'Type:':<25} {hex_data[0:2]:<20} | {icmpv6_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
    
    # Identify common ICMPv6 message types
    type_names = {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        4: "Parameter Problem",
        128: "Echo Request",
        129: "Echo Reply",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
        137: "Redirect Message"
    }
    
    if icmpv6_type in type_names:
        print(f"  {'Message Type:':<25} {type_names[icmpv6_type]}")
    
    # For Echo Request/Reply
    if icmpv6_type in [128, 129]:
        identifier = int(hex_data[8:12], 16)
        sequence = int(hex_data[12:16], 16)
        print(f"  {'Identifier:':<25} {hex_data[8:12]:<20} | {identifier}")
        print(f"  {'Sequence Number:':<25} {hex_data[12:16]:<20} | {sequence}")
    
    # For Neighbor Discovery messages (133-137)
    elif icmpv6_type in [133, 134, 135, 136, 137]:
        print(f"  {'Reserved/Flags:':<25} {message_body}")
    
    else:
        print(f"  {'Message Body:':<25} {message_body}")
    
    # Show payload if it exists
    if len(hex_data) > 16:
        payload = hex_data[16:]
        print(f"  {'Payload (hex):'} {payload}")

    
    return icmpv6_type, code



def parse_tcp_header(hex_data):

    # Should be the same for iPv4 and iPv6, reuse function. Test it works.

    src_port = int(hex_data[0:4], 16)           # Source Port - 2 bytes
    dst_port = int(hex_data[4:8], 16)           # Destination Port - 2 bytes
    sequence = int(hex_data[8:16], 16)          # Sequence Number - 4 bytes
    acknowledgment = int(hex_data[16:24], 16)   # Acknowledgment Number - 4 bytes
    
    # Data Offset (4 bits) and Reserved (3 bits) and Flags (9 bits) - 2 bytes total
    data_offset_flags = hex_data[24:28]
    data_offset = int(data_offset_flags[0], 16) # First nibble
    header_length_bytez = data_offset * 4       # Data offset is in 32-bit words
    
    # Extract flags from the 2-byte field
    flags_value = int(data_offset_flags, 16)
    flags = {
        'NS ':  (flags_value >> 8) & 1,   # ECN-nonce concealment protection
        'CWR': (flags_value >> 7) & 1,   # Congestion Window Reduced
        'ECE': (flags_value >> 6) & 1,   # ECN-Echo
        'URG': (flags_value >> 5) & 1,   # Urgent
        'ACK': (flags_value >> 4) & 1,   # Acknowledgment
        'PSH': (flags_value >> 3) & 1,   # Push
        'RST': (flags_value >> 2) & 1,   # Reset
        'SYN': (flags_value >> 1) & 1,   # Synchronize
        'FIN': flags_value & 1           # Finish
    }
    
    window_size = int(hex_data[28:32], 16)      # Window Size - 2 bytes
    checksum = hex_data[32:36]                  # Checksum - 2 bytes
    urgent_pointer = int(hex_data[36:40], 16)   # Urgent Pointer - 2 bytes
    
    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[0:4]:<20} | {src_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {dst_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {sequence}")
    print(f"  {'Acknowledgment Number:':<25} {hex_data[16:24]:<20} | {acknowledgment}")
    print(f"  {'Data Offset:':<25} {data_offset} | {header_length_bytez} bytes")
    print(f"  {'Reserved:':<25} 0")
    print(f"  {'Flags:':<25} {data_offset_flags:<20} | {bin(flags_value)}")
    
    # Print individual flags
    flag_list = []
    for flag_name, flag_value in flags.items():
        print(f"    {flag_name}:{'':>20} {flag_value}")
        if flag_value:
            flag_list.append(flag_name)
    
    print(f"  {'Window Size:':<25} {hex_data[28:32]:<20} | {window_size}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[36:40]:<20} | {urgent_pointer}")
    
    # Show payload if it exists (skip TCP header)
    payload_start = header_length_bytez * 2  # Convert to hex string positions
    if len(hex_data) > payload_start:
        payload = hex_data[payload_start:]
        print(f"  {'Payload (hex):'} {payload}")

    
    return src_port, dst_port, flag_list




def parse_udp_header(hex_data):

    # Should be the same for iPv4 and iPv6, reuse function. Test it works.
   
    src_port = int(hex_data[0:4], 16)   # Source Port - 2 bytes
    dst_port = int(hex_data[4:8], 16)   # Destination Port - 2 bytes
    length = int(hex_data[8:12], 16)    # Length - 2 bytes (includes UDP header + data)
    checksum = hex_data[12:16]          # Checksum - 2 bytes
    
    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[0:4]:<20} | {src_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {dst_port}")
    print(f"  {'Length:':<25} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
  
    # UDP payload starts after 8-byte header (16 hex characters)
    if len(hex_data) > 16:
        payload = hex_data[16:]
        
        # Check if this is DNS traffic (port 53)
        if src_port == 53 or dst_port == 53:
            parse_dns_header(payload)
        else:
            # Show payload preview for non-DNS traffic
            print(f"  {'Payload (hex):'} {payload}")

    
    return src_port, dst_port, length



def parse_dns_header(hex_data):

    # Normally called by UDP only (Port 53)
   
    transaction_id = hex_data[0:4]  # Transaction ID - 2 bytes
    
    flags = hex_data[4:8]           # Flags - 2 bytes
    flags_int = int(flags, 16)
    
    # Parse flag bits
    qr = (flags_int >> 15) & 1        # Query (0) or Response (1)
    opcode = (flags_int >> 11) & 0xF  # Operation code
    aa = (flags_int >> 10) & 1        # Authoritative Answer
    tc = (flags_int >> 9) & 1         # Truncated
    rd = (flags_int >> 8) & 1         # Recursion Desired
    ra = (flags_int >> 7) & 1         # Recursion Available
    z = (flags_int >> 4) & 0x7        # Reserved
    rcode = flags_int & 0xF           # Response code
    
    questions = int(hex_data[8:12], 16)       # Question count - 2 bytes
    answer_rrs = int(hex_data[12:16], 16)     # Answer RRs - 2 bytes
    authority_rrs = int(hex_data[16:20], 16)  # Authority RRs - 2 bytes
    additional_rrs = int(hex_data[20:24], 16) # Additional RRs - 2 bytes
    
    print(f"DNS Header:")
    print(f"  {'Transaction ID:':<25} {transaction_id:<20} | {int(transaction_id, 16)}")
    print(f"  {'Flags:':<25} {flags:<20} | {bin(flags_int)}")
    print(f"    {'QR (Query/Response):':<23} {qr} | {'Response' if qr else 'Query'}")
    print(f"    {'Opcode:':<23} {opcode}")
    print(f"    {'Recursion Desired:':<23} {rd}")
    print(f"    {'Recursion Available:':<23} {ra}")
    print(f"  {'Questions:':<25} {hex_data[8:12]:<20} | {questions}")
    print(f"  {'Answer RRs:':<25} {hex_data[12:16]:<20} | {answer_rrs}")
    print(f"  {'Authority RRs:':<25} {hex_data[16:20]:<20} | {authority_rrs}")
    print(f"  {'Additional RRs:':<25} {hex_data[20:24]:<20} | {additional_rrs}")
    
    # Parse query name (starts at byte 12, position 24 in hex string)
    if len(hex_data) > 24 and questions > 0:
        query_start = 24
        query_name = ""
        pos = query_start
        
        try:
            while pos < len(hex_data):
                length = int(hex_data[pos:pos+2], 16)
                if length == 0:  # End of name
                    break
                if length > 63:  # Likely a pointer or error
                    break
                pos += 2
                
                # Extract label
                for i in range(length):
                    if pos + 2 <= len(hex_data):
                        char_hex = hex_data[pos:pos+2]
                        query_name += chr(int(char_hex, 16))
                        pos += 2
                query_name += "."
            
            if query_name:
                query_name = query_name.rstrip('.')
                print(f"  {'Query Name:':<25} {query_name}")
                
                # Query Type and Class follow the name
                if pos + 8 <= len(hex_data):
                    query_type = int(hex_data[pos+2:pos+6], 16)
                    query_class = int(hex_data[pos+6:pos+10], 16)
                    
                    type_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
                    type_name = type_names.get(query_type, f"Type {query_type}")
                    
                    print(f"  {'Query Type:':<25} {hex_data[pos+2:pos+6]:<20} | {type_name}")
                    print(f"  {'Query Class:':<25} {hex_data[pos+6:pos+10]:<20} | {query_class} (IN)")
        except:
            print(f"  {'Query Name:':<25} [Parsing error - complex DNS format]")
    
    return transaction_id, qr


def parse_arp_header(hex_data):
    
    hardware_type = int(hex_data[0:4], 16) # Hardware Type - 2 bytes
    protocol_type = int(hex_data[4:8], 16) # Protocol Type - 2 bytes  
    hardware_size = int(hex_data[8:10], 16) # Hardware Size - 1 byte
    protocol_size = int(hex_data[10:12], 16) # Protocol Size - 1 byte
    opcode = int(hex_data[12:16], 16) # Opcode - 2 bytes
    
    # Sender MAC - 6 bytes (12 hex chars)
    sender_mac_hex = hex_data[16:28] 
    sender_mac = ':'.join(sender_mac_hex[i:i+2] for i in range(0, 12, 2))
    
    # Sender IP - 4 bytes (8 hex chars)
    sender_ip_hex = hex_data[28:36]
    sender_ip = '.'.join([str(int(sender_ip_hex[i:i+2], 16)) for i in range(0, 8, 2)])
    
    # Target MAC - 6 bytes (12 hex chars)
    target_mac_hex = hex_data[36:48]
    target_mac = ':'.join(target_mac_hex[i:i+2] for i in range(0, 12, 2))
    
    # Target IP - 4 bytes (8 hex chars)
    target_ip_hex = hex_data[48:56]
    target_ip = '.'.join([str(int(target_ip_hex[i:i+2], 16)) for i in range(0, 8, 2)])

    ########## END. THERE IS NO TCP/UDP/IPvX Parser in ARP! Just Ethernet Header > ARP. ##########

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[0:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Opcode:':<25} {hex_data[12:16]:<20} | {opcode}")
    print(f"  {'Sender MAC:':<25} {sender_mac_hex:<20} | {sender_mac}")
    print(f"  {'Sender IP:':<25} {sender_ip_hex:<20} | {sender_ip}")
    print(f"  {'Target MAC:':<25} {target_mac_hex:<20} | {target_mac}")
    print(f"  {'Target IP:':<25} {target_ip_hex:<20} | {target_ip}")

    return opcode


def parse_ipv4_header(hex_data):
    
    version_ihl = hex_data[0:2]             # Version and IHL (Internet Header Length) - 1 byte total
    version = int(version_ihl[0], 16)       # First nibble (4 bits)
    ihl = int(version_ihl[1], 16)           # Second nibble (4 bits)
    header_length_bytes = ihl * 4           # IHL is in 32-bit words
    tos = hex_data[2:4]                     # Type of Service - 1 byte
    total_length = int(hex_data[4:8], 16)   # Total Length - 2 bytes
    identification = hex_data[8:12]         # Identification - 2 bytes
    flags_fragment = hex_data[12:16]        # Flags and Fragment Offset - 2 bytes
    ttl = int(hex_data[16:18], 16)          # Time to Live - 1 byte
    protocol = int(hex_data[18:20], 16)     # Protocol - 1 byte (this tells us what's inside the IPv4 packet)
    checksum = hex_data[20:24]              # Header Checksum - 2 bytes
    src_ip_hex = hex_data[24:32]            # Source IP - 4 bytes (8 hex characters)

    # Convert to dotted decimal: split into 2-char chunks, convert each to int
    src_ip = '.'.join([str(int(src_ip_hex[i:i+2], 16)) for i in range(0, 8, 2)])
    
    # Destination IP - 4 bytes (8 hex characters)
    dst_ip_hex = hex_data[32:40]
    dst_ip = '.'.join([str(int(dst_ip_hex[i:i+2], 16)) for i in range(0, 8, 2)])
    
    # Print the IPv4 header information
    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {version}")
    print(f"  {'Header Length:':<25} {ihl} | {header_length_bytes} bytes")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {flags_fragment}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Source IP:':<25} {src_ip_hex:<20} | {src_ip}")
    print(f"  {'Destination IP:':<25} {dst_ip_hex:<20} | {dst_ip}")
    
    # Calculate where the payload starts (skip IPv4 header)
    payload_start = header_length_bytes * 2  # Convert bytes to hex string positions
    payload = hex_data[payload_start:]
    
    # Route to the next protocol based on Protocol field
    if protocol == 1:    # ICMP
        parse_icmp_header(payload)
    elif protocol == 6:  # TCP
        parse_tcp_header(payload)
    elif protocol == 17: # UDP  
        parse_udp_header(payload)
    else:
        print(f"  {'Unknown Protocol:':<25} {protocol}")
        print("  No parser available for this protocol.")
    
    return protocol, payload


def parse_ipv6_header(hex_data):

    version_tc_flow = hex_data[0:8]                         # Version, Traffic Class, and Flow Label - 4 bytes total
    version = int(version_tc_flow[0], 16)                   # First nibble 4 bits
    traffic_class = int(version_tc_flow[1:3], 16)           # Next 8 bits
    flow_label = int(version_tc_flow[2:8], 16) & 0xFFFFF    # Last 20 bits
    payload_length = int(hex_data[8:12], 16)                # Payload Length - 2 bytes
    next_header = int(hex_data[12:14], 16)                  # Next Header - 1 byte (equivalent to IPv4's Protocol field)
    hop_limit = int(hex_data[14:16], 16)                    # Hop Limit - 1 byte (equivalent to IPv4's TTL)
    
    # Source IPv6 Address - 16 bytes (32 hex characters), then format IPv6 address standard notation (groups of 4 hex digits)
    src_ipv6_hex = hex_data[16:48]                          
    src_ipv6 = ':'.join([src_ipv6_hex[i:i+4] for i in range(0, 32, 4)]) 
    
    # Destination IPv6 Address - 16 bytes (32 hex characters)
    dst_ipv6_hex = hex_data[48:80]
    dst_ipv6 = ':'.join([dst_ipv6_hex[i:i+4] for i in range(0, 32, 4)])
    
    print(f"IPv6 Header:")
    print(f"  {'Version:':<25} {version}")
    print(f"  {'Traffic Class:':<25} {hex_data[1:3]:<20} | {traffic_class}")
    print(f"  {'Flow Label:':<25} {hex_data[2:8]:<20} | {flow_label}")
    print(f"  {'Payload Length:':<25} {hex_data[8:12]:<20} | {payload_length}")
    print(f"  {'Next Header:':<25} {hex_data[12:14]:<20} | {next_header}")
    print(f"  {'Hop Limit:':<25} {hex_data[14:16]:<20} | {hop_limit}")
    print(f"  {'Source IPv6:':<25} {src_ipv6_hex} | {src_ipv6}")
    print(f"  {'Destination IPv6:':<25} {dst_ipv6_hex} | {dst_ipv6}")
    
    # IPv6 header is always 40 bytes (80 hex characters)
    payload = hex_data[80:]
    
    # Route to next protocol based on Next Header field
    if next_header == 6:   # TCP
        parse_tcp_header(payload)
    elif next_header == 17: # UDP
        parse_udp_header(payload)
    elif next_header == 58: # ICMPv6
        parse_icmpv6_header(payload)
    else:
        print(f"  {'Unknown Next Header:':<25} {next_header}")
        print("  No parser available for this protocol.")
    
    return next_header, payload
