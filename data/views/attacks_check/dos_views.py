from django.http import JsonResponse
from scapy.all import sniff
from data.models import Device, Packet, Notification, Setting
from datetime import datetime
from collections import defaultdict
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from datetime import timedelta
import json
import os
from ...utils import format_timestamp

def get_packets_func():
    packets = []
    def packet_callback(packet):
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            protocol = packet['IP'].proto
        
            data = bytes(packet)  # Entire packet as bytes
            packets.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'data': data
            })

    # Capture packets for 60 seconds
    sniff(timeout=60, prn=packet_callback)

    return packets

def calculate_parameters(request):
    # Get settings and devices
    setting_minutes = Setting.objects.first().training_minutes
    devices = Device.objects.filter(is_active=True)

    if not devices.exists():
        return JsonResponse({
            'status': 'success',
            'message': "No devices found",
            'processed_devices': 0
        })
    
    results = []
    for device in devices:
        # Get all packets for this device
        packets = device.packet_set.all()
        
        if not packets.exists():
            continue
        
        # Calculate basic metrics
        total_bits = sum(packet.bytes_transferred * 8 for packet in packets)
        num_packets = packets.count()
        
        # Track connected IPs and protocols
        connected_ips = []
        protocols = []
        for packet in packets:
            try:
                if packet.src_ip != device.ip_address and packet.dst_ip == device.ip_address:
                    connected_ips.append(packet.src_ip)
                if packet.dst_ip != device.ip_address and packet.src_ip == device.ip_address:
                    connected_ips.append(packet.dst_ip)
                protocols.append(packet.protocol)
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

        # Calculate current metrics
        bps = total_bits / 60
        pps = num_packets / 60
        
        if device.training_minutes < setting_minutes:
            # Training mode: Update baseline metrics
            device.volume = max(float(bps), float(device.volume))
            device.speed = max(float(pps), float(device.speed))
            device.protocols = list(set(device.protocols + protocols))
            existing_ips = device.connected_ips if device.connected_ips else []
            device.connected_ips = list(set(existing_ips + connected_ips))
            device.training_minutes += 1
            
            if device.training_minutes >= setting_minutes:
                device.is_trained = True
        else:
            current_metrics = {
                "volume": float(bps),
                "speed": float(pps),
                "protocols": protocols,
                "connected_ips": connected_ips
            }
            
            threshold_metrics = {
                "volume": float(device.volume),
                "speed": float(device.speed),
                "protocols": device.protocols,
                "connected_ips": device.connected_ips
            }
            # Anomaly detection mode for trained devices
            # Check volume anomaly
            if float(bps) > float(device.volume) * 1.5:
                create_alert(device, 'Volume', float(bps), float(device.volume))
            
            # Check speed anomaly
            if float(pps) > float(device.speed) * 1.5:
                create_alert(device, 'Speed', float(pps), float(device.speed))
            
            # Check protocol anomalies
            for protocol in protocols:
                if protocol not in device.protocols:
                    create_alert(device, 'Protocol', 
                               f"Unauthorized protocol detected: {protocol}", 
                               f"Allowed protocols: {device.protocols}")
            
            # Check connected IPs anomalies
            for ip in connected_ips:
                if ip not in device.connected_ips:
                    create_alert(device, 'IP', 
                               f"Unauthorized IP detected: {ip}", 
                               f"Allowed IPs: {device.connected_ips}")
            
            # Log detection data
            log_detection_data(device, current_metrics, threshold_metrics)
        
        device.save()
        
        # Delete processed packets
        device.packet_set.all().delete()
        
    return JsonResponse({
        "status": "success",
    })

def store_captured_packets():
    devices = Device.objects.filter(
        is_active=True,
    ).exclude(
        packet__isnull=False  # Exclude devices that already have packets
    )
    
    if not devices.exists():
        return {"message": "No eligible devices found"}
    
    device_packets = defaultdict(list)
    device_ips = {device.ip_address: device for device in devices}
    
    packets = get_packets_func()
    
    for packet in packets:
        if packet['src_ip'] in device_ips:
            device_packets[packet['src_ip']].append(packet)
        if packet['dst_ip'] in device_ips:
            device_packets[packet['dst_ip']].append(packet)
    
    for ip_address, packets in device_packets.items():
        device = device_ips[ip_address]
        timestamp = timezone.now()  # Use timezone-aware datetime
        
        Packet.objects.bulk_create([
            Packet(
                device=device,
                timestamp=timestamp,
                src_ip=packet['src_ip'],
                dst_ip=packet['dst_ip'],
                protocol=packet['protocol'],
                bytes_transferred=len(packet.get('data', '')),
                details=str(packet)
            ) for packet in packets
        ])
    
    return {
        "status": "success",
        "message": f"Packets captured and stored for {len(device_packets)} devices"
    }

def create_alert(device, parameter, current_value, trained_value, severity='high'):
    """Create an alert notification for parameter deviation with comprehensive details."""
    # Check for recent similar alerts in the last 5 minutes
    five_minutes_ago = timezone.now() - timezone.timedelta(minutes=5)
    recent_similar_alert = Notification.objects.filter(
        device=device,
        type='alert',
        parameter=parameter,
        timestamp__gte=five_minutes_ago
    ).exists()

    if recent_similar_alert:
        return None  # Skip creating duplicate alert
    
    # Format the timestamp
    timestamp = format_timestamp(timezone.now())
    
    # Create a detailed message based on the parameter type
    if parameter == 'Volume':
        message = (
            f"[{timestamp}] Volume Anomaly Detected\n"
            f"Device: {device.name} ({device.ip_address})\n"
            f"Current Traffic: {float(current_value):.2f} bits/sec\n"
            f"Trained Baseline: {float(trained_value):.2f} bits/sec\n"
            f"Deviation: {((float(current_value) - float(trained_value)) / float(trained_value) * 100):.1f}%"
        )
    elif parameter == 'Speed':
        message = (
            f"[{timestamp}] Speed Anomaly Detected\n"
            f"Device: {device.name} ({device.ip_address})\n"
            f"Current Rate: {float(current_value):.2f} packets/sec\n"
            f"Trained Baseline: {float(trained_value):.2f} packets/sec\n"
            f"Deviation: {((float(current_value) - float(trained_value)) / float(trained_value) * 100):.1f}%"
        )
    elif parameter == 'Protocol':
        message = (
            f"[{timestamp}] Protocol Anomaly Detected\n"
            f"Device: {device.name} ({device.ip_address})\n"
            f"Unauthorized Protocol Usage:\n"
            f"Details: {current_value}\n"
            f"Allowed Protocols: {trained_value}"
        )
    elif parameter == 'IP':
        message = (
            f"[{timestamp}] Unauthorized IP Connection Detected\n"
            f"Device: {device.name} ({device.ip_address})\n"
            f"Unauthorized IP: {current_value}\n"
            f"Allowed IPs: {trained_value}"
        )
    else:
        message = (
            f"[{timestamp}] {parameter} Anomaly Detected\n"
            f"Device: {device.name} ({device.ip_address})\n"
            f"Current Value: {current_value}\n"
            f"Trained Value: {trained_value}"
        )

    # Enhanced details dictionary
    details = {
        'timestamp': timestamp,
        'device_id': device.id,
        'device_name': device.name,
        'device_ip': device.ip_address,
        'parameter': parameter,
        'current_value': str(current_value),
        'trained_value': str(trained_value),
        'severity': severity,
        'training_status': {
            'is_trained': device.is_trained,
            'training_minutes': device.training_minutes
        },
        'device_status': {
            'is_active': device.is_active,
            'number_of_users': device.number_of_users
        }
    }
    
    return Notification.objects.create(
        device=device,
        message=message,
        type='alert',
        parameter=parameter,  # Add parameter field for filtering
        details=json.dumps(details, indent=2)
    )

def dos_detection_training():
    """Train devices to detect DoS attacks."""
    try:
        Packet.objects.all().delete()
        store_captured_packets()
        calculate_parameters(None)  # Pass None since we're not using request
        return "Successfully processed device data"
    except Exception as e:
        return f"Error: {str(e)}"

def log_detection_data(device, current_metrics, threshold_metrics):
    """Log detection data to a JSON file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = "data/logs"
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = f"{log_dir}/detection_log.json"
    
    log_entry = {
        "timestamp": timestamp,
        "device": {
            "id": device.id,
            "name": device.name,
            "ip": device.ip_address,
            "is_trained": device.is_trained,
            "training_minutes": device.training_minutes
        },
        "current_metrics": {
            "volume_bps": current_metrics["volume"],
            "speed_pps": current_metrics["speed"],
            "protocols": list(set(current_metrics["protocols"])),  # Convert to set to remove duplicates
            "connected_ips": list(set(current_metrics["connected_ips"]))  # Convert to set to remove duplicates
        },
        "threshold_metrics": {
            "volume_bps": threshold_metrics["volume"],
            "speed_pps": threshold_metrics["speed"],
            "allowed_protocols": threshold_metrics["protocols"],
            "allowed_ips": threshold_metrics["connected_ips"]
        }
    }
    
    try:
        # Read existing log file
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
        else:
            logs = []
        
        # Append new log entry
        logs.append(log_entry)
        
        # Write updated logs back to file
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=4)
            
    except Exception as e:
        print(f"Error logging detection data: {e}")
