import ipaddress, os, subprocess, re, socket, nmap

from django.http import JsonResponse
from django.shortcuts import render
from scapy.all import ARP, Ether, srp, conf
from .models import Device


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
    command = 'ipconfig' if os.name == 'nt' else 'ifconfig'
    output = subprocess.run(command, capture_output=True, text=True, shell=True).stdout
    target = 'wi-fi'
    adapters = re.split(r'\n\s*Ethernet adapter |Wireless LAN adapter ', output)[1:]
    for adapter in adapters:
        adapter_name = adapter.lower()  # Convert to lowercase for comparison
        if target in adapter_name:  # Check if 'wi-fi' is in the interface name
            wifi_info = adapter
            break

    if len(wifi_info) == 0:
        return JsonResponse({"error": "No Wi-Fi information found."})

    # Clean up the details and find the IPv4 address and netmask
    ipv4_address = re.search(r'IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)', wifi_info)
    netmask = re.search(r'Subnet Mask[.\s]+:\s+([\d\.]+)', wifi_info)

    if ipv4_address and netmask:
        IP_address = ipv4_address.group(1)
        Netmask = netmask.group(1)

        # Define the target network range (e.g., '192.168.1.0/24')
        target_ip = convert_to_cidr(IP_address, Netmask)  # Your function defined earlier

        # Create an ARP request
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send the packet and receive responses
        result = srp(packet, timeout=2, verbose=False)[0]

        # Parse the results to extract IP and MAC addresses
        devices = []
        for sent, received in result:
            nm = nmap.PortScanner()
            nm.scan(received.psrc, arguments='-O')  # -O for OS detection

            info = {}
            if nm.all_hosts():
                for host in nm.all_hosts():
                    os_matches = nm[host].get('osmatch', [])
                    info['os'] = os_matches[0]['name'] if os_matches else 'Unknown'
                    info['services'] = nm[host]['tcp'] if 'tcp' in nm[host] else {}
            else:
                info['os'] == 'Unknown'
                info['services'] == 'Unknown'
        
            device_info = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'manufacturer': get_mac_manufacturer(received.hwsrc, load_oui_database('data/ieee-oui-database.txt')),
                'hostname': resolve_hostname(received.psrc),
                'os' : info['os'],
                'services' : info['services']
            }
            devices.append(device_info)

            for device in devices:
                Device.objects.update_or_create(
                    ip_address=device["ip"],
                    mac_address=device["mac"]
                )
        return JsonResponse({'devices': list(Device.objects.all().values())})
    
    return JsonResponse({"error": "No IPv4 or Netmask found."})
