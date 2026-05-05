import socket
import sys
import shutil

import nmap


DISCOVERY_ARGUMENTS = (
    "-sn -n -T4 --max-retries 1 --host-timeout 8s "
    "-PE -PS22,80,443,445,554,1883,8080 -PA80,443,502,1883"
)


class ScannerRuntimeError(RuntimeError):
    """Raised when a local scanner dependency or Nmap execution fails."""


def ensure_nmap_available():
    """Fail early with an actionable error if the Nmap binary is unavailable."""
    if not shutil.which("nmap"):
        raise ScannerRuntimeError("Nmap executable was not found. Install Nmap and ensure it is available on PATH.")


def get_local_network():
    """Dynamically determine the local network range."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    if local_ip == "127.0.0.1":
        return None

    network = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    return network


def scan(ip_range):
    """Perform stronger Nmap host discovery and collect basic host metadata."""
    print(f"[*] Discovering devices in range: {ip_range} using Nmap...")
    from sentinel_iot.scanner.device_fingerprint import discover_ssdp, get_vendor_from_mac

    ensure_nmap_available()
    ssdp_devices = discover_ssdp()
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_range, arguments=DISCOVERY_ARGUMENTS)
    except nmap.PortScannerError as exc:
        raise ScannerRuntimeError(f"Nmap discovery failed: {exc}") from exc
    except Exception as exc:
        raise ScannerRuntimeError(f"Unexpected discovery failure: {exc}") from exc

    devices_list = []
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        addresses = nm[host].get("addresses", {})
        mac = addresses.get("mac", "Unknown")
        vendor = nm[host].get("vendor", {}).get(mac, "Unknown")
        hostname = ""
        if nm[host].hostnames():
            hostname = nm[host].hostnames()[0].get("name", "")

        if not vendor or vendor == "Unknown":
            vendor = get_vendor_from_mac(mac)

        discovery_sources = []
        if hostname:
            discovery_sources.append("hostname")

        if host in ssdp_devices:
            discovery_sources.append("ssdp")
            if vendor == "Unknown":
                vendor = f"UPnP: {ssdp_devices[host][:32]}"

        if mac != "Unknown":
            discovery_sources.append("arp")

        device_info = {
            "ip": host,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "discovery_sources": discovery_sources,
        }
        devices_list.append(device_info)

    return devices_list


def display_results(results):
    """Pretty print the discovery results."""
    print("\n[+] Devices found on network:")
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Vendor':<24} {'Hostname':<20}")
    print("-" * 85)
    for device in results:
        print(
            f"{device['ip']:<15} {device['mac']:<20} "
            f"{device['vendor']:<24} {device.get('hostname', ''):<20}"
        )


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_network = sys.argv[1]
    else:
        target_network = get_local_network()

    if not target_network:
        print("[-] Could not determine local network.")
        sys.exit(1)

    try:
        scan_results = scan(target_network)
        display_results(scan_results)
    except Exception as e:
        print(f"[-] An error occurred: {e}")
