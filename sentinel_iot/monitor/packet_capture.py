import scapy.all as scapy
import time
import sys
import os
import logging

logger = logging.getLogger(__name__)

def list_interfaces():
    """List available network interfaces."""
    print("\n[*] Available Interfaces:")
    interfaces = scapy.get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"    [{i}] {iface}")
    return interfaces

def packet_callback(packet):
    """Callback for each captured packet."""
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto
        size = len(packet)
        # Log to console for real-time feedback
        # print(f"[+] CAPTURE: {ip_src} -> {ip_dst} | Proto: {proto} | Size: {size}")

def start_capture(interface=None, duration=10, output_file="capture.pcap", verbose=True):
    """
    Passive network monitoring using Scapy.
    Captures traffic and optionally saves to a PCAP file, or returns packets in memory.
    """
    if interface is None:
        # On Windows, scapy.conf.iface might be useful but sometimes needs manual selection
        try:
            interface = scapy.conf.iface
        except:
            interface = None

    if verbose:
        print(f"[*] Starting Passive Monitoring on interface: {interface}")
        print(f"[*] Duration: {duration} seconds | Output: {output_file}")

    try:
        # Sniffing with a store=True to enable writing to pcap later
        # prn is used for optional real-time processing/logging
        packets = scapy.sniff(iface=interface, timeout=duration, prn=packet_callback, store=True)
        
        if packets:
            if verbose:
                print(f"[+] Captured {len(packets)} packets.")
            if output_file:
                scapy.wrpcap(output_file, packets)
                if verbose:
                    print(f"[+] Successfully saved to {output_file}")
                return output_file
            return packets
        else:
            if verbose:
                print("[-] No packets captured in the given timeframe.")
            return [] if output_file is None else None

    except PermissionError:
        logger.error("Administrative privileges required for packet capture.", exc_info=True)
    except Exception as e:
        logger.error("Error during packet capture: %s", e, exc_info=True)
    
    return None

if __name__ == "__main__":
    # If run directly, offer interface selection if no args
    if len(sys.argv) == 1:
        ifaces = list_interfaces()
        # default to scapy default if no choice made
        start_capture(duration=5)
    elif len(sys.argv) == 2:
        # Use provided duration
        start_capture(duration=int(sys.argv[1]))
    elif len(sys.argv) >= 3:
        # Use provided duration and interface
        start_capture(duration=int(sys.argv[1]), interface=sys.argv[2])
