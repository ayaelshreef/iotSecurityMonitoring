
import ipaddress, os, subprocess, re, socket, threading
from nmap import PortScanner
from django.http import JsonResponse
from scapy.all import sniff, IP
from django.shortcuts import render
from datetime import datetime
from collections import deque

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
