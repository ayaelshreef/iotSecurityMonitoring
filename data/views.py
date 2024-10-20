import ipaddress, os, subprocess, re, socket

from nmap import PortScanner
from django.http import JsonResponse
from django.shortcuts import render
import requests
from scapy.all import ARP, Ether, srp, sniff, TCP, IP
from .models import Device
from django.shortcuts import render
from .sniffer import start_sniffing
import threading
from datetime import datetime

def home(request) :
    data = Device.objects.all()
    return render(request, 'home/home.html', {'devices' : data})

def device(request, id) :
    data = Device.objects.get(pk=id)
    return render(request, 'data/data.html', {'device' : data})

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
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


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

                os_info = nm[received.psrc].get('osmatch', [{}])
                services_info = nm[received.psrc].get('tcp', {})

                device_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'manufacturer': get_mac_manufacturer(received.hwsrc, load_oui_database('data/ieee-oui-database.txt')),
                    'hostname': resolve_hostname(received.psrc),
                    'os': os_info[0].get('name', 'Unknown') if os_info else 'Unknown',
                    'services': services_info
                }
                devices.append(device_info)

            return JsonResponse({'devices': devices})

        return JsonResponse({"error": "No IPv4 or Netmask found."})

    except Exception as e:
        return JsonResponse({"error": str(e)})

sniffer_thread = None
sniffer_running = False
captured_packets = []

def packet_callback(packet):
    global captured_packets
    if packet.haslayer(IP):
        packet_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto,
            'details': packet.summary()
        }
        captured_packets.append(packet_data)

def start_sniffing():
    global sniffer_running
    sniffer_running = True
    sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffer_running)

def start_sniffer_view(request):
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_thread = threading.Thread(target=start_sniffing)
        sniffer_thread.start()
        return JsonResponse({'status': 'Sniffer started'})
    else:
        return JsonResponse({'status': 'Sniffer is already running'})
    
def stop_sniffer_view(request):
    global sniffer_running
    sniffer_running = False
    return JsonResponse({'status': 'Sniffer stopped'})

def display_packets_view(request):
    return render(request, 'data/data.html', {})

def fetch_packets_view(request):
    return JsonResponse({'packets': captured_packets})
