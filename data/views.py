import ipaddress, os, subprocess, re, socket

from nmap import PortScanner
from django.http import JsonResponse
from scapy.all import ARP, Ether, srp, sniff, TCP, IP, sr1, UDP, DNS, DNSQR, RandShort
from .models import Device, DeviceVolume
from django.shortcuts import render
from .sniffer import start_sniffing
import threading
from datetime import datetime
from time import time
from collections import deque

# Pages viewing
def home(request) :
    data = Device.objects.all()
    return render(request, 'home/home.html', {'devices' : data})

# def device(request, id) :
#     data = Device.objects.get(pk=id)
#     return render(request, 'data/data.html', {'device' : data})

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
        # Identify the command for fetching network configurations
        command = 'ipconfig' if os.name == 'nt' else 'ifconfig'
        output = subprocess.run(command, capture_output=True, text=True, shell=True).stdout
        
        wifi_section_start = output.find("Wi-Fi")
        if wifi_section_start == -1:
            return "Wi-Fi section not found"

        # Extract the section after "Wi-Fi"
        wifi_section = output[wifi_section_start:]
        
        # Look for the first IPv4 address (starting with "192")
        ip_address = re.search(r"192(?:\.\d+){3}", wifi_section).group()
        netmask = re.search(r"255(?:\.\d+){3}", wifi_section).group()
        
        target_ip = convert_to_cidr(ip_address, netmask)

        # ARP request to scan devices on the network
        arp_request = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send ARP packet and capture responses
        answered = srp(packet, timeout=2, verbose=False)[0]

        devices = []
        for sent, received in answered:
            device_info = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'os': 'Unknown',  # Optional: Integrate OS detection below if needed
                'services': []    # Optional: Add service scanning with PortScanner if needed
            }

            # Optional OS and service detection (comment out if not needed)
            try:
                nm = PortScanner()
                nm.scan(received.psrc, arguments='-O')  # '-O' for OS detection
                os_info = nm[received.psrc].get('osmatch', [])
                if os_info:
                    device_info['os'] = os_info[0].get('name', 'Unknown')
                device_info['services'] = nm[received.psrc].get('tcp', {}).keys()
            except Exception as e:
                pass  # Handle optional scanning errors gracefully

            devices.append(device_info)

        return JsonResponse({"devices": devices})

    except Exception as e:
        return JsonResponse({"error": f"An error occurred: {str(e)}"})

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
                'bytes_transferred': len(packet),
                'details': packet.summary(),
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



def get_packets_func():
    packets = []
    def packet_callback(packet):
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            data = bytes(packet)  # Entire packet as bytes

            packets.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'data': data  # This can be the raw packet bytes or payload
            })

    # Capture packets for 1 second
    sniff(timeout=1, prn=packet_callback)

    return packets

def calculate_bps(packet, ip_address, monitor_duration_minutes=1):
    results = []  # To store the total bits transferred for each minute
    start_time = time()  # Start time of monitoring
    current_minute_start = start_time  # Track when the current minute started

    while (time() - start_time) < monitor_duration_minutes * 60:
        # Initialize variables for the current minute
        minute_bits = 0

        # Loop through the current minute
        while time() - current_minute_start < 60:
            # Get packets for the current second
            packets = get_packets_func()
            
            # Calculate bits transferred for packets in the current second
            for packet in packets:
                if packet['src_ip'] == ip_address or packet['dst_ip'] == ip_address:
                    minute_bits += len(packet) * 8  # Convert bytes to bits

        # After 60 seconds, append the result for the current minute
        bps = minute_bits/60
        results.append(bps)

        print(f"The volume for the device {ip_address}: {bps} bits per second")

        # Reset the minute timer and continue to the next minute
        current_minute_start = time()

    device_volume, created = DeviceVolume.objects.update_or_create(
    ip_address=ip_address,
    defaults={'volume': max(results)}
    )
    return JsonResponse({'volume': max(results)})

def get_volume(request, ip_address):
    try:
        device_volume = DeviceVolume.objects.get(ip_address=ip_address)
        return JsonResponse({'volume': device_volume.volume}, status=200)
    except DeviceVolume.DoesNotExist:
        return JsonResponse({'volume': None}, status=404)