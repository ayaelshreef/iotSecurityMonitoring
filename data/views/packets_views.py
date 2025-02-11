import ipaddress, os, subprocess, re, socket, threading
from nmap import PortScanner
from django.http import JsonResponse, Http404
from scapy.all import sniff, IP
from django.shortcuts import render
from datetime import datetime
from collections import deque
from data.models import Device, Packet
from django.db.models import Min
from django.utils import timezone
from data.models import Setting
sniffer_thread = None
sniffer_running = False
filter_ip_address = None 
captured_packets = []

def packets_view(request, ip_address):

    global filter_ip_address
    filter_ip_address = ip_address
    
    # Check if IP exists in active devices
    device = Device.objects.get(ip_address=ip_address, is_active=True)
    
    if not Device.objects.filter(ip_address=ip_address, is_active=True).exists():
        return render(request, 'packets.html', {
            'error_message': f"No active device found with IP: {ip_address}",
            'ip_address': None
        })

    return render(request, 'packets.html', {
        'ip_address': ip_address,
        'mac_address': device.mac_address,
        'volume': device.volume,
        'speed': device.speed,
        'protocols': device.protocols,
        'connected_ips': device.connected_ips,
        'number_of_users': device.number_of_users
    })

def start_sniffer_view(request):
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_thread = threading.Thread(target=start_sniffing)
        sniffer_thread.start()
        return JsonResponse({'status': 'Sniffer started'})
    else:
        return JsonResponse({'status': 'Sniffer is already running'})

def start_sniffing():
    global sniffer_running
    sniffer_running = True
    sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffer_running)

def packet_callback(packet):
    global captured_packets, filter_ip_address
    current_time = timezone.now()

    device = Device.objects.get(ip_address=filter_ip_address, is_active=True)
    first_packet_time = device.packet_set.aggregate(
        first_time=Min('timestamp')
    )['first_time']

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
        if device.training_minutes < Setting.objects.first().training_minutes and (not first_packet_time or 
                    (current_time - first_packet_time).total_seconds() <= 60):
                    Packet.objects.create(
                        device=device,
                        timestamp=current_time,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=packet[IP].proto,
                        bytes_transferred=len(packet),
                        details=packet.summary()
                    )

def stop_sniffer_view(request):
    global sniffer_running
    sniffer_running = False
    return JsonResponse({'status': 'Sniffer stopped'})

def fetch_packets_view(request, ip_address):
    filtered_packets = [
        packet for packet in captured_packets 
        if packet['src_ip'] == ip_address or packet['dst_ip'] == ip_address
    ]
    return JsonResponse({'packets': filtered_packets})

def capture_device_packets(duration=60):
    global filter_ip_address, sniffer_running
    
    # Get all active devices
    active_devices = Device.objects.filter(is_active=True)
    
    # Start time of capture
    start_time = timezone.now()
    
    for device in active_devices:
        filter_ip_address = device.ip_address
        sniffer_running = True
        
        # Create a separate thread for packet capture
        capture_thread = threading.Thread(
            target=sniff,
            kwargs={
                'prn': packet_callback,
                'store': 0,
                'timeout': duration,
                'stop_filter': lambda x: not sniffer_running
            }
        )
        
        capture_thread.start()
        capture_thread.join()  # Wait for the capture to complete
        
        sniffer_running = False
    
    return {
        'message': f'Packet capture completed for {len(active_devices)} active devices',
        'duration': duration,
        'start_time': start_time,
        'end_time': timezone.now()
    }