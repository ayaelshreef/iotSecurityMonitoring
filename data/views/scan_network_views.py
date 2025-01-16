import ipaddress, subprocess, re, os
from django.http import JsonResponse
from scapy.all import ARP, Ether, srp
from data.models import Device
from data.utils import firebase

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
        processed_mac_addresses = []

        for sent, received in answered:
            device_info = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'os': 'Unknown',  # Optional: Integrate OS detection below if needed
                # 'services': []    # Optional: Add service scanning with PortScanner if needed
            }

            Device.objects.update_or_create(
            mac_address=device_info['mac'],
            defaults={
                "ip_address" : device_info['ip'],
                "is_active" : True
                }
            )
            
            processed_mac_addresses.append(device_info['mac'])
            
            defaults={
                "ip_address" : device_info['ip'],
                "is_active" : True
                }
            
            firebase.update_or_create_device(device_info['mac'], defaults)
            devices.append(device_info)
            # # Optional OS and service detection (comment out if not needed)
            # try:
            #     # nm = PortScanner()
            #     nm.scan(received.psrc, arguments='-O')  # '-O' for OS detection
            #     os_info = nm[received.psrc].get('osmatch', [])
            #     if os_info:
            #         device_info['os'] = os_info[0].get('name', 'Unknown')
            #     device_info['services'] = nm[received.psrc].get('tcp', {}).keys()
                
            # except Exception as e:
            #     pass  # Handle optional scanning errors gracefully

        Device.objects.exclude(mac_address__in=processed_mac_addresses).update(is_active=False)

        firebase.update_devices_activity(processed_mac_addresses)

        return JsonResponse({"devices": devices})

    except Exception as e:
        return JsonResponse({"error": f"An error occurred: {str(e)}"})
