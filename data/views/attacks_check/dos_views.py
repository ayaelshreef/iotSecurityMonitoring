from django.http import JsonResponse
from scapy.all import sniff
from data.models import Device, Packet, Notification, Setting
from datetime import datetime
from collections import defaultdict

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
                'data': data
            })

    # Capture packets for 60 seconds
    sniff(timeout=60, prn=packet_callback)

    return packets

def check_dos_attack(request):
    # Get all eligible devices
    devices = Device.objects.filter(is_active=True, is_trained=True)
    
    if not devices.exists():
        return JsonResponse({'message': "No eligible devices to monitor"}, status=404)

    # Monitor network for one minute
    packets = get_packets_func()
    
    # Track metrics per device
    device_metrics = defaultdict(lambda: {'bits': 0, 'packet_count': 0})
    
    # Calculate metrics for each device
    for packet in packets:
        for device in devices:
            if packet['src_ip'] == device.ip_address or packet['dst_ip'] == device.ip_address:
                device_metrics[device.ip_address]['bits'] += len(packet['data']) * 8
                device_metrics[device.ip_address]['packet_count'] += 1

    # Check for potential DoS attacks
    attacked_devices = []
    for device in devices:
        metrics = device_metrics[device.ip_address]
        current_volume = metrics['bits'] / 60  # bits per second
        current_speed = metrics['packet_count'] / 60  # packets per second
        
        if current_volume > device.volume and current_speed > device.speed:
            attacked_devices.append({
                'ip_address': device.ip_address,
                'current_volume': current_volume,
                'threshold_volume': device.volume,
                'current_speed': current_speed,
                'threshold_speed': device.speed
            })
    
    if attacked_devices:
        # Create notification for the DoS attack
        notification_message = f"Potential DoS attack detected on {len(attacked_devices)} device(s)"
        Notification.objects.create(
            type='dos_attack',
            message=notification_message,
            details=attacked_devices
        )
        
        return JsonResponse({
            'status': 'warning',
            'message': 'Potential DoS attack detected',
            'attacked_devices': attacked_devices
        })
    
    return JsonResponse({
        'status': 'ok',
        'message': 'No DoS attacks detected'
    })

def calculate_parameters(request):
    devices = Device.objects.filter(
        is_active=True,
        training_minutes__lt= Setting.objects.first().training_minutes      
    )
    
    if not devices.exists():
        return JsonResponse({'message': "There are no active devices in the network"}, status=404)
        
    for device in devices:
        # Replace direct packet capture with database query
        packets = device.packet_set.all()
        
        total_bits = sum(packet.bytes_transferred * 8 for packet in packets)  # Convert bytes to bits
        num_packets = packets.count()

        bps = total_bits / 60
        pps = num_packets / 60
        
        device.volume = max(bps, device.volume)
        device.speed = max(pps, device.speed)
        device.training_minutes += 1
        
        if device.training_minutes >= Setting.objects.first().training_minutes:
            device.is_trained = True
        else:
            device.is_trained = False
    
        device.save()
        
        # Delete all packets for this device after calculations
        device.packet_set.all().delete()
        
    return JsonResponse({
        "status": "success",
        "processed_devices": len(devices),
    })

def store_captured_packets():
    # Get eligible devices (active and training_minutes < 60)
    devices = Device.objects.filter(
        is_active=True,
        training_minutes__lt=Setting.objects.first().training_minutes
    ).exclude(
        packet__isnull=False  # Exclude devices that already have packets
    )
    
    if not devices.exists():
        return {"message": "No eligible devices found"}
    
    # Create a dict to store packets for each device
    device_packets = defaultdict(list)
    device_ips = {device.ip_address: device for device in devices}
    
        # Get packets for all devices at once
    packets = get_packets_func()  # Assuming this returns packets for all network traffic
    
    # Sort packets by device
    for packet in packets:
        # Check if either source or destination IP belongs to our devices
        if packet['src_ip'] in device_ips:
            device_packets[packet['src_ip']].append(packet)
        if packet['dst_ip'] in device_ips and packet['src_ip'] != packet['dst_ip']:
            device_packets[packet['dst_ip']].append(packet)
    
    # Store all captured packets in the database
    for ip_address, packets in device_packets.items():
        device = device_ips[ip_address]
        timestamp = datetime.now()
        
        # Bulk create packets for better performance
        Packet.objects.bulk_create([
            Packet(
                device=device,
                timestamp=timestamp,
                src_ip=packet['src_ip'],
                dst_ip=packet['dst_ip'],
                protocol=packet.get('protocol', 0),
                bytes_transferred=len(packet.get('data', '')),
                details=str(packet)
            ) for packet in packets
        ])
    
    return {
        "status": "success",
        "message": f"Packets captured and stored for {len(device_packets)} devices"
    }
