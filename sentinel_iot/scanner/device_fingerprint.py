import socket
import re
import urllib.request
import ssl

# A curated dict of major IoT OUIs often missed by default Nmap
OUI_DICT = {
    "48:BD:4A": "Tuya Smart Device",
    "EC:FA:BC": "Tuya Smart Device",
    "28:6C:07": "Xiaomi Smart Home",
    "50:EC:50": "Xiaomi Smart Home",
    "C8:02:8F": "Hikvision IP Camera",
    "E0:50:8B": "Dahua IP Camera",
    "00:1A:3F": "Dahua Protocol",
    "CC:50:E3": "Espressif IoT Node",
    "24:6F:28": "Espressif IoT Node",
    "00:17:88": "Philips Hue Bridge",
    "28:39:5E": "Samsung Smart Appliance",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi 4",
    "00:00:00": "Unknown"
}

def get_vendor_from_mac(mac):
    """Retrieve Vendor Name from extended MAC OUI database."""
    if not mac or mac == "Unknown":
        return "Unknown"
    
    clean_mac = mac.upper().replace(":", "").replace("-", "")
    if len(clean_mac) >= 6:
        prefix = f"{clean_mac[0:2]}:{clean_mac[2:4]}:{clean_mac[4:6]}"
        return OUI_DICT.get(prefix, "Unknown")
    return "Unknown"

def get_http_title(ip, port):
    """Scrape the HTML <title> and Server header from default web interfaces."""
    url = f"http://{ip}:{port}" if port in (80, 8080) else f"https://{ip}:{port}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
            html = response.read().decode('utf-8', errors='ignore')
            server = response.headers.get('Server', '')
            
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            title = match.group(1).strip() if match else ""
            return title, server
    except Exception:
        return "", ""

def discover_ssdp():
    """Active broadcast to discover UPnP/SSDP devices hidden from general scanning."""
    discovered = {}
    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(3)
    try:
        sock.sendto(ssdp_request.encode('utf-8'), ('239.255.255.250', 1900))
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                response = data.decode('utf-8', errors='ignore')
                server_name = ""
                for line in response.split('\r\n'):
                    if line.lower().startswith('server:'):
                        server_name = line.split(':', 1)[1].strip()
                        break
                
                if server_name:
                    discovered[ip] = server_name
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] SSDP Discovery Error: {e}")
    finally:
        sock.close()
    return discovered
