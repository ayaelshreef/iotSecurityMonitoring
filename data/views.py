import ipaddress
import os
import subprocess
import re

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

def scan_network_devices(request):
    command = 'ipconfig' if os.name == 'nt' else 'ifconfig'
    output = subprocess.run(command, capture_output=True, text=True, shell=True).stdout

    if os.name == 'nt':  # Windows
        wifi_info = re.findall(r'(Wi-Fi|Wireless LAN adapter Wi-Fi)[^\n]*\n((?:.*\n)+?)(?=\n)', output)
    else:  # Unix-like OS
        wifi_info = re.findall(r'([^\n]*Wi-Fi[^\n]*)\s*.*?((?:\n\s+\S+)+)', output, re.DOTALL)

    if len(wifi_info) == 0:
        return JsonResponse({"error": "No Wi-Fi information found."})

    # Extract the first matched Wi-Fi interface details
    details = wifi_info[0][1]

    # Clean up the details and find the IPv4 address and netmask
    ipv4_address = re.search(r'IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)', details)
    netmask = re.search(r'Subnet Mask[.\s]+:\s+([\d\.]+)', details)

    if ipv4_address and netmask:
        IP_address = ipv4_address.group(1)
        Netmask = netmask.group(1)

        # Define the target network range (e.g., '192.168.1.0/24')
        target_ip = convert_to_cidr(IP_address, Netmask) # Change this to your network range

        # Create an ARP request
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send the packet and receive responses
        result = srp(packet, timeout=2, verbose=False)[0]

        # Parse the results to extract IP and MAC addresses
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return JsonResponse(devices, safe=False)
    return JsonResponse({"error": "No IPv4 or Netmask found."})

    # command = 'ipconfig' if os.name == 'nt' else 'ifconfig'
    # output = subprocess.run(command, capture_output=True, text=True, shell=True).stdout
    # target = 'wi-fi'
    # adapters = re.split(r'\n\s*Ethernet adapter |Wireless LAN adapter ', output)[1:]
    # for adapter in adapters:
    #     adapter_name = adapter.lower()  # Convert to lowercase for comparison
    #     if target in adapter_name:  # Check if 'wi-fi' is in the interface name
    #         wifi_info = adapter
    #         break
    # return JsonResponse(wifi_info[1], safe=False)
    # print(wifi_info)
    # if len(wifi_info) == 0: 
    #     return JsonResponse({"error": "No Wi-Fi information found."})
        
    # # Extract the first matched Wi-Fi interface details
    # details = wifi_info[0][1]