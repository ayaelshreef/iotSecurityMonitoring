import ipaddress, os, subprocess, re, socket

from nmap import PortScanner
from django.http import JsonResponse
from scapy.all import ARP, Ether, srp, sniff, TCP, IP
from .models import Device
from django.shortcuts import render
from .sniffer import start_sniffing
import threading
from datetime import datetime

# Pages viewing
def home(request) :
    data = Device.objects.all()
    return render(request, 'home/home.html', {'devices' : data})

def device(request, id) :
    data = Device.objects.get(pk=id)
    return render(request, 'data/data.html', {'device' : data})

# Scan iot devices
def convert_to_cidr(ip, netmask):
    # Create an IPv4 network object
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    
    # Return the network in CIDR notation
    return str(network)

def load_oui_database(filename):
    oui_dict = {}
    with open(filename, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 3:
                oui = parts[1].replace('-', ':')
                manufacturer = ' '.join(parts[2:])
                oui_dict[oui] = manufacturer
    return oui_dict

def get_mac_manufacturer(mac, oui_dict):
    mac_prefix = ':'.join(mac.split(':')[:3]).upper()  # Get the first 3 octets
    return oui_dict.get(mac_prefix, "Unknown Manufacturer")

def resolve_hostname(ip):
    """Resolve the hostname from the IP address."""

# List of known IoT manufacturers' OUI prefixes
IOT_MANUFACTURERS_OUI = [
    '00:1A:11',  # Example OUI for manufacturer
    '00:1B:57',  # Example OUI for another manufacturer
    'd0:27:02',  # Example OUI for IoT devices
    # Add more known OUI prefixes for IoT devices
]

def is_iot_device(mac_address, os_name, services):
    """Determine if a device is likely an IoT device."""
    # Check if the MAC address belongs to a known IoT manufacturer
    if any(mac_address.startswith(oui) for oui in IOT_MANUFACTURERS_OUI):
        return True
    
    # Check for common IoT operating systems
    if "lwIP" in os_name or "FreeRTOS" in os_name:
        return True
    
    return False

def identify_iot_devices(devices):
    """Filter and return a list of devices that are likely IoT devices."""
    iot_devices = []
    
    for device in devices:
        if is_iot_device(device.get('mac'), device.get('os'), device.get('services', {})):
            iot_devices.append(device)
    return iot_devices

def scan_network_devices(request):
    try:
        command = 'ipconfig' if os.name == 'nt' else 'ifconfig'
        output = subprocess.run(command, capture_output=True, text=True, shell=True).stdout

        # Refined adapter detection
        target_adapters = ['wi-fi', 'wireless', 'wifi']
        wifi_info = None
        
        for target in target_adapters:
            adapters = re.split(r'\n\s*Ethernet adapter |Wireless LAN adapter ', output)
            for adapter in adapters:
                if target in adapter.lower():
                    wifi_info = adapter
                    break
            if wifi_info:
                break

        if not wifi_info:
            return JsonResponse({"error": "No Wi-Fi information found."})

        # Extract IPv4 Address and Netmask
        ipv4_address = re.search(r'IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)', wifi_info)
        netmask = re.search(r'Subnet Mask[.\s]+:\s+([\d\.]+)', wifi_info)

        if ipv4_address and netmask:
            IP_address = ipv4_address.group(1)
            Netmask = netmask.group(1)

            # Define the target network range
            target_ip = convert_to_cidr(IP_address, Netmask)

            # Create and send ARP request
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send the packet and receive responses
            result = srp(packet, timeout=2, verbose=False)[0]

            devices = []
            for sent, received in result:
                nm = PortScanner()
                nm.scan(received.psrc, arguments='-O')  # -O for OS detection

                os_info = nm[received.psrc].get('osmatch', [])
                services_info = nm[received.psrc].get('tcp', {})

                # Handle the case where os_info is a list
                os_name = 'Unknown'
                if os_info and isinstance(os_info, list):
                    os_name = os_info[0].get('name', 'Unknown')

                device_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'manufacturer': get_mac_manufacturer(received.hwsrc, load_oui_database('data/ieee-oui-database.txt')),
                    'hostname': resolve_hostname(received.psrc),
                    'os': os_name,
                    'services': services_info
                }
                devices.append(device_info)
            
            return JsonResponse({"devices": devices})
    
            # Identify IoT devices
            iot_devices = identify_iot_devices(devices)
            return render(request, 'home/home.html', {'iot_devices' : devices})

        return JsonResponse({"error": "No IPv4 or Netmask found."})

    except Exception as e:
        return JsonResponse({"error": str(e)})

sniffer_thread = None
sniffer_running = False
filter_ip_address = None  # This will be set dynamically

def start_sniffing():
    global sniffer_running
    sniffer_running = True
    sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffer_running)

def stop_sniffer_view(request):
    global sniffer_running
    sniffer_running = False
    return JsonResponse({'status': 'Sniffer stopped'})

def display_packets_view(request):
    return render(request, 'data/data.html', {})

def start_sniffer_view(request):
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_thread = threading.Thread(target=start_sniffing)
        sniffer_thread.start()
        return JsonResponse({'status': 'Sniffer started'})
    else:
        return JsonResponse({'status': 'Sniffer is already running'})
    
captured_packets = []

def packet_callback(packet):
    global captured_packets, filter_ip_address
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Check if the packet's source or destination IP matches the filter IP
        if src_ip == filter_ip_address or dst_ip == filter_ip_address:
            packet_data = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': packet[IP].proto,
                'details': packet.summary()
            }
            captured_packets.append(packet_data)

def packets_view(request, ip_address):
    global filter_ip_address
    filter_ip_address = ip_address  # Set the filter IP address from the request
    return render(request, 'packets.html', {'ip_address': ip_address})

def fetch_packets_view(request, ip_address):
    filtered_packets = [
        packet for packet in captured_packets 
        if packet['src_ip'] == ip_address or packet['dst_ip'] == ip_address
    ]
    return JsonResponse({'packets': filtered_packets})