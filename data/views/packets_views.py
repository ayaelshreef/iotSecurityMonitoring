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
from ..utils import format_timestamp
sniffer_thread = None
sniffer_running = False
filter_ip_address = None 
captured_packets = []

def packets_view(request, ip_address):
    try:
        global filter_ip_address
        filter_ip_address = ip_address  # Set the global filter IP
        
        # Try to get the device regardless of active status
        device = Device.objects.get(ip_address=ip_address)
        training_minutes_required = Setting.objects.first().training_minutes
        
        context = {
            'ip_address': ip_address,
            'device': device,
            'volume': device.volume,
            'speed': device.speed,
            'protocols': device.protocols,
            'connected_ips': device.connected_ips,
            'number_of_users': device.number_of_users,
            'training_minutes_required': training_minutes_required,
            'is_active': device.is_active
        }
        return render(request, 'packets.html', context)
    except Device.DoesNotExist:
        context = {
            'error_message': f'No device found with IP address {ip_address}'
        }
        return render(request, 'packets.html', context)

def start_sniffer_view(request):
    global sniffer_thread, sniffer_running, captured_packets
    
    # Clear previous packets
    captured_packets = []
    
    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_running = True
        sniffer_thread = threading.Thread(target=start_sniffing)
        sniffer_thread.daemon = True  # Make thread daemon so it stops when main thread stops
        sniffer_thread.start()
        return JsonResponse({'status': 'Sniffer started'})
    else:
        return JsonResponse({'status': 'Sniffer is already running'})

def start_sniffing():
    global sniffer_running, filter_ip_address
    try:
        # Create BPF filter for the specific IP
        ip_filter = f"host {filter_ip_address}"
        sniff(filter=ip_filter, prn=packet_callback, store=0, stop_filter=lambda x: not sniffer_running)
    except Exception as e:
        print(f"Error in sniffing: {e}")
        sniffer_running = False

def packet_callback(packet):
    global captured_packets, filter_ip_address
    try:
        if IP in packet:
            current_time = timezone.now()
            packet_data = {
                'timestamp': format_timestamp(current_time),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'bytes_transferred': len(packet),
            }
            
            # Only store if packet involves our target IP
            if packet_data['src_ip'] == filter_ip_address or packet_data['dst_ip'] == filter_ip_address:
                captured_packets.append(packet_data)
                
                # Keep only the last 100 packets to prevent memory issues
                if len(captured_packets) > 100:
                    captured_packets = captured_packets[-100:]
                
                # Store packet in database if device is in training
                try:
                    device = Device.objects.get(ip_address=filter_ip_address)
                    if device.training_minutes < Setting.objects.first().training_minutes:
                        Packet.objects.create(
                            device=device,
                            timestamp=current_time,
                            src_ip=packet_data['src_ip'],
                            dst_ip=packet_data['dst_ip'],
                            protocol=packet_data['protocol'],
                            bytes_transferred=packet_data['bytes_transferred'],
                            details=str(packet.summary())
                        )
                except Device.DoesNotExist:
                    pass
    except Exception as e:
        print(f"Error in packet callback: {e}")

def stop_sniffer_view(request):
    global sniffer_running, sniffer_thread
    sniffer_running = False
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer_thread.join(timeout=1)
    sniffer_thread = None
    return JsonResponse({'status': 'Sniffer stopped'})

def fetch_packets_view(request, ip_address):
    global captured_packets
    return JsonResponse({
        'packets': captured_packets
    })

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