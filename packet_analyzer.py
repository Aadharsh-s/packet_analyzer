from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter, defaultdict
from datetime import datetime
import time


# ==========================================
# PACKETWATCH
# Python Packet Analyzer + IDS / IPS
# ==========================================


# ==========================================
# Statistics
# ==========================================

total_packets = 0
total_bytes = 0

protocol_counts = Counter()
destination_ports = Counter()
source_ips = Counter()


# ==========================================
# IDS / IPS Configuration
# ==========================================

# Ports that may deserve additional monitoring
SUSPICIOUS_PORTS = {
    23: "Telnet",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC"
}

# Number of unique destination ports from one IP
# before it is considered a possible port scan
PORT_SCAN_THRESHOLD = 10

# Packets per second before a possible flood is detected
PACKET_FLOOD_THRESHOLD = 100


# ==========================================
# IDS Tracking
# ==========================================

# Stores destination ports contacted by each source IP
connection_tracker = defaultdict(set)

# Stores packet timestamps for flood detection
flood_tracker = defaultdict(list)

# Stores detected security alerts
security_alerts = []

# Stores IPs that have been flagged
flagged_ips = set()


# ==========================================
# IPS Tracking
# ==========================================

# IPs blocked by the IPS logic
blocked_ips = set()

# False = IDS mode
# True  = IDS + IPS mode
IPS_ENABLED = False


# ==========================================
# Service Identification
# ==========================================

def identify_service(protocol, port):

    if protocol == "TCP":

        if port == 80:
            return "HTTP"

        elif port == 443:
            return "HTTPS"

        elif port == 22:
            return "SSH"

        elif port == 21:
            return "FTP"

        elif port == 25:
            return "SMTP"

        elif port == 110:
            return "POP3"

        elif port == 143:
            return "IMAP"

    elif protocol == "UDP":

        if port == 53:
            return "DNS"

        elif port == 443:
            return "QUIC"

        elif port == 1900:
            return "SSDP"

    return "UNKNOWN"


# ==========================================
# IDS - Generate Security Alert
# ==========================================

def generate_alert(alert_type, source_ip, details):

    timestamp = datetime.now().strftime("%H:%M:%S")

    alert = {
        "time": timestamp,
        "type": alert_type,
        "source_ip": source_ip,
        "details": details
    }

    security_alerts.append(alert)

    print("\n" + "!" * 100)
    print("                         IDS SECURITY ALERT")
    print("!" * 100)

    print(f"Time      : {timestamp}")
    print(f"Alert     : {alert_type}")
    print(f"Source IP : {source_ip}")
    print(f"Details   : {details}")

    print("!" * 100)

    # IPS response
    if IPS_ENABLED:
        block_ip(source_ip)

    print()


# ==========================================
# IDS - Suspicious Port Detection
# ==========================================

def detect_suspicious_port(source_ip, destination_port):

    if destination_port in SUSPICIOUS_PORTS:

        service = SUSPICIOUS_PORTS[destination_port]

        # Avoid generating the same alert repeatedly
        alert_key = f"PORT-{source_ip}-{destination_port}"

        already_alerted = any(
            alert["source_ip"] == source_ip
            and alert["type"] == "SUSPICIOUS PORT ACCESS"
            and alert["details"].startswith(
                f"Traffic detected on port {destination_port}"
            )
            for alert in security_alerts
        )

        if not already_alerted:

            generate_alert(
                "SUSPICIOUS PORT ACCESS",
                source_ip,
                f"Traffic detected on port {destination_port} ({service})"
            )


# ==========================================
# IDS - Port Scan Detection
# ==========================================

def detect_port_scan(source_ip, destination_port):

    connection_tracker[source_ip].add(destination_port)

    unique_ports = len(connection_tracker[source_ip])

    if unique_ports >= PORT_SCAN_THRESHOLD:

        if source_ip not in flagged_ips:

            generate_alert(
                "PORT SCAN DETECTED",
                source_ip,
                f"Attempted connections to "
                f"{unique_ports} different destination ports"
            )

            flagged_ips.add(source_ip)


# ==========================================
# IDS - Packet Flood Detection
# ==========================================

def detect_packet_flood(source_ip):

    current_time = time.time()

    # Add current packet timestamp
    flood_tracker[source_ip].append(current_time)

    # Keep only packets from the last one second
    flood_tracker[source_ip] = [
        timestamp
        for timestamp in flood_tracker[source_ip]
        if current_time - timestamp <= 1
    ]

    packet_rate = len(flood_tracker[source_ip])

    if packet_rate >= PACKET_FLOOD_THRESHOLD:

        flood_alert_exists = any(
            alert["source_ip"] == source_ip
            and alert["type"] == "POSSIBLE PACKET FLOOD"
            for alert in security_alerts
        )

        if not flood_alert_exists:

            generate_alert(
                "POSSIBLE PACKET FLOOD",
                source_ip,
                f"Detected approximately "
                f"{packet_rate} packets per second"
            )


# ==========================================
# IPS - Block IP
# ==========================================

def block_ip(source_ip):

    if source_ip not in blocked_ips:

        blocked_ips.add(source_ip)

        print("\n" + "#" * 80)
        print("                         IPS ACTION")
        print("#" * 80)

        print(f"IP Address : {source_ip}")
        print("Action     : BLOCKED")
        print("Reason     : Suspicious network activity detected")

        print("#" * 80)
        print()


# ==========================================
# IPS - Check Blocked IP
# ==========================================

def is_ip_blocked(source_ip):

    return source_ip in blocked_ips


# ==========================================
# Packet Analyzer
# ==========================================

def analyze_packet(packet):

    global total_packets
    global total_bytes

    # Ignore packets without IPv4
    if IP not in packet:
        return

    total_packets += 1
    total_bytes += len(packet)

    timestamp = datetime.now().strftime("%H:%M:%S")

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    source_ips[source_ip] += 1

    # ======================================
    # Default Values
    # ======================================

    protocol = "OTHER"

    source_port = "-"
    destination_port = "-"

    flags = "-"

    service = "UNKNOWN"

    # ======================================
    # IPS Check
    # ======================================

    if is_ip_blocked(source_ip):

        print(
            f"[IPS] Blocked traffic detected "
            f"from {source_ip}"
        )

        return

    # ======================================
    # TCP
    # ======================================

    if TCP in packet:

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        service = identify_service(
            protocol,
            destination_port
        )

        flags = packet[TCP].flags

        destination_ports[destination_port] += 1

        # ----------------------------------
        # IDS checks
        # ----------------------------------

        detect_suspicious_port(
            source_ip,
            destination_port
        )

        detect_port_scan(
            source_ip,
            destination_port
        )

    # ======================================
    # UDP
    # ======================================

    elif UDP in packet:

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        service = identify_service(
            protocol,
            destination_port
        )

        destination_ports[destination_port] += 1

        # ----------------------------------
        # IDS checks
        # ----------------------------------

        detect_suspicious_port(
            source_ip,
            destination_port
        )

        detect_port_scan(
            source_ip,
            destination_port
        )

    # ======================================
    # ICMP
    # ======================================

    elif ICMP in packet:

        protocol = "ICMP"

    # ======================================
    # General IDS Checks
    # ======================================

    detect_packet_flood(source_ip)

    # ======================================
    # Update Protocol Statistics
    # ======================================

    protocol_counts[protocol] += 1

    # ======================================
    # Display Packet
    # ======================================

    print(
        f"{timestamp:<10}"
        f"{source_ip:<18}"
        f"{destination_ip:<18}"
        f"{protocol:<8}"
        f"{str(source_port):<8}"
        f"{str(destination_port):<8}"
        f"{service:<10}"
        f"{len(packet):<8}"
        f"{str(flags):<8}"
    )


# ==========================================
# General Statistics
# ==========================================

def show_statistics():

    print("\n")

    print("=" * 70)
    print("                    PACKETWATCH STATISTICS")
    print("=" * 70)

    print(f"Total Packets : {total_packets}")
    print(f"Total Bytes   : {total_bytes}")

    # ======================================
    # Protocol Statistics
    # ======================================

    print("\nProtocol Statistics")
    print("-" * 40)

    if protocol_counts:

        for protocol, count in protocol_counts.most_common():

            print(
                f"{protocol:<15}: {count}"
            )

    else:

        print("No protocol data available.")

    # ======================================
    # Top Destination Ports
    # ======================================

    print("\nTop Destination Ports")
    print("-" * 40)

    if destination_ports:

        for port, count in destination_ports.most_common(10):

            service = identify_service(
                "TCP",
                port
            )

            if service == "UNKNOWN":

                service = identify_service(
                    "UDP",
                    port
                )

            print(
                f"{port:<10}: "
                f"{count:<8} "
                f"{service}"
            )

    else:

        print("No destination port data available.")

    # ======================================
    # Top Source IPs
    # ======================================

    print("\nTop Source IPs")
    print("-" * 40)

    if source_ips:

        for ip, count in source_ips.most_common(10):

            print(
                f"{ip:<20}: {count}"
            )

    else:

        print("No source IP data available.")

    print("=" * 70)


# ==========================================
# IDS / IPS Security Report
# ==========================================

def show_security_report():

    print("\n")

    print("=" * 80)
    print("                       SECURITY REPORT")
    print("=" * 80)

    print(
        f"IDS Alerts           : {len(security_alerts)}"
    )

    print(
        f"Flagged IPs          : {len(flagged_ips)}"
    )

    print(
        f"Blocked IPs          : {len(blocked_ips)}"
    )

    print(
        f"IPS Mode             : "
        f"{'ENABLED' if IPS_ENABLED else 'DISABLED'}"
    )

    # ======================================
    # Detected Threats
    # ======================================

    print("\nDetected Threats")
    print("-" * 80)

    if not security_alerts:

        print("No suspicious activity detected.")

    else:

        for alert in security_alerts:

            print(
                f"[{alert['time']}] "
                f"{alert['type']:<25} "
                f"Source: {alert['source_ip']:<16} "
                f"{alert['details']}"
            )

    # ======================================
    # Flagged IPs
    # ======================================

    print("\nFlagged IP Addresses")
    print("-" * 40)

    if flagged_ips:

        for ip in sorted(flagged_ips):

            print(ip)

    else:

        print("No IP addresses flagged.")

    # ======================================
    # Blocked IPs
    # ======================================

    print("\nBlocked IP Addresses")
    print("-" * 40)

    if blocked_ips:

        for ip in sorted(blocked_ips):

            print(ip)

    else:

        print("No IP addresses blocked.")

    print("=" * 80)


# ==========================================
# Main Program
# ==========================================

print("=" * 100)

print(
    "                         PACKETWATCH"
)

print(
    "                Python Packet Analyzer + IDS / IPS"
)

print("=" * 100)

print(
    f"{'TIME':<10}"
    f"{'SOURCE IP':<18}"
    f"{'DESTINATION IP':<18}"
    f"{'PROTO':<8}"
    f"{'SPORT':<8}"
    f"{'DPORT':<8}"
    f"{'SERVICE':<10}"
    f"{'SIZE':<8}"
    f"{'FLAGS':<8}"
)

print("-" * 100)

print(
    "\nCapturing packets for 30 seconds..."
)

print(
    "Please browse normally while the analyzer is running."
)

print(
    f"IDS Mode : ENABLED"
)

print(
    f"IPS Mode : "
    f"{'ENABLED' if IPS_ENABLED else 'DISABLED'}"
)

print()


# ==========================================
# Packet Capture
# ==========================================

try:

    sniff(
        prn=analyze_packet,
        store=False,
        timeout=30
    )

except PermissionError:

    print(
        "\n[ERROR] Permission denied."
    )

    print(
        "Run the program with administrator/root privileges."
    )

except Exception as error:

    print(
        f"\n[ERROR] Packet capture failed: {error}"
    )


# ==========================================
# Capture Finished
# ==========================================

print("\nCapture completed.")


# ==========================================
# Show Statistics
# ==========================================

show_statistics()


# ==========================================
# Show Security Report
# ==========================================

show_security_report()