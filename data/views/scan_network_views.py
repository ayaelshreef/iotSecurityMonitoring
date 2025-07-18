import ipaddress, subprocess, re, os
from django.http import JsonResponse
from scapy.all import ARP, Ether, srp
from data.models import Device
# from data.utils import firebase
from django.views.decorators.http import require_http_methods

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

def scan_network_devices(request, update_only):
    """
    Scan network for devices.
    If update_only is True, only update existing devices' statuses.
    If update_only is False, discover new devices and update existing ones' status.
    """
    try:
        command = 'ipconfig' if os.name == 'nt' else 'ifconfig'
        output = subprocess.run(command, capture_output=True, text=True, shell=True).stdout
        
        wifi_section_start = output.find("Wi-Fi")
        if wifi_section_start == -1:
            return "Wi-Fi section not found"

        # Extract the section after "Wi-Fi"
        wifi_section = output[wifi_section_start:]
        
        # Look for the IPv4 address 
        ip_address = re.search(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", wifi_section).group()
        netmask = re.search(r"255(?:\.\d+){3}", wifi_section).group()
        target_ip = convert_to_cidr(ip_address, netmask)
        arp = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(broadcast/arp, timeout=3, verbose=False)[0]
        
        # Get all MAC addresses and their current IPs found in the scan
        active_macs = {received.hwsrc.lower(): received.psrc for _, received in result}
        
        if update_only:
            # Update status and IP addresses of all existing devices
            devices = Device.objects.all()
            for device in devices:
                mac = device.mac_address.lower()
                if mac in active_macs:
                    device.is_active = True
                    device.ip_address = active_macs[mac]  # Update IP address
                else:
                    device.is_active = False
                device.save()
            return {
                'status': 'success',
                'message': 'Device statuses and IPs updated'
            }
        else:
            # Get existing MAC addresses from database
            existing_devices = {device.mac_address.lower(): device 
                              for device in Device.objects.all()}
            
            # Add new devices and update existing ones
            new_devices = []
            for mac, ip in active_macs.items():
                if mac in existing_devices:
                    # Update existing device
                    device = existing_devices[mac]
                    device.is_active = True
                    device.ip_address = ip
                    device.save()
                else:
                    # Create new device
                    device = Device.objects.create(
                        mac_address=mac,
                        ip_address=ip,
                        is_active=True,
                        name=f"Device_{mac[-6:]}"
                    )
                    new_devices.append({
                        'mac': mac,
                        'ip': ip,
                        'name': device.name
                    })
            
            # Set devices not found in scan as inactive
            for mac, device in existing_devices.items():
                if mac not in active_macs:
                    device.is_active = False
                    device.save()
            
            return {
                'status': 'success',
                'message': f'Found {len(new_devices)} new devices' if new_devices else 'No new devices found',
                'new_devices': new_devices
            }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

@require_http_methods(["GET"])
def scan_network_devices_view(request):
    """View function to handle scan request from web interface."""
    result = scan_network_devices(request,update_only=False)
    return JsonResponse(result)


# def scan_network_devices(request):
#     try:
#         # Identify the command for fetching network configurations
#         command = 'ipconfig' if os.name == 'nt' else 'ifconfig'
#         output = subprocess.run(command, capture_output=True, text=True, shell=True).stdout
        
#         wifi_section_start = output.find("Wi-Fi")
#         if wifi_section_start == -1:
#             return "Wi-Fi section not found"

#         # Extract the section after "Wi-Fi"
#         wifi_section = output[wifi_section_start:]
        
#         # Look for the IPv4 address 
#         ip_address = re.search(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", wifi_section).group()
#         netmask = re.search(r"255(?:\.\d+){3}", wifi_section).group()
#         #if not found ip4_address
#         target_ip = convert_to_cidr(ip_address, netmask)

#         # ARP request to scan devices on the network
#         arp_request = ARP(pdst=target_ip)
#         broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
#         packet = broadcast / arp_request

#         # Send ARP packet and capture responses
#         answered = srp(packet, timeout=2, verbose=False)[0]

#         devices = []
#         processed_mac_addresses = []

#         for sent, received in answered:
#             device_info = {
#                 'ip': received.psrc,
#                 'mac': received.hwsrc,
#                 'os': 'Unknown',  # Optional: Integrate OS detection below if needed
#                 # 'services': []    # Optional: Add service scanning with PortScanner if needed
#             }

#             Device.objects.update_or_create(
#             mac_address=device_info['mac'],
#             defaults={
#                 "ip_address" : device_info['ip'],
#                 "is_active" : True
#                 }
#             )
            
#             processed_mac_addresses.append(device_info['mac'])
            
#             defaults={
#                 "ip_address" : device_info['ip'],
#                 "is_active" : True
#                 }
            
#             firebase.update_or_create_device(device_info['mac'], defaults)
#             devices.append(device_info)
            
#         Device.objects.exclude(mac_address__in=processed_mac_addresses).update(is_active=False)

#         firebase.update_devices_activity(processed_mac_addresses)

#         return JsonResponse({"devices": devices})

#     except Exception as e:
#         return JsonResponse({"error": f"An error occurred: {str(e)}"})
