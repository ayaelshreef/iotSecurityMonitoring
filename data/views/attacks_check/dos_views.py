from django.http import JsonResponse
from scapy.all import sniff
from data.models import Device, Packet, Notification, Setting
from datetime import datetime
from collections import defaultdict
import pyshark
from scapy.layers.inet import IP, TCP, UDP
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from datetime import timedelta
import json

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
        training_minutes__lt=Setting.objects.first().training_minutes      
    )
    
    if not devices.exists():
        return JsonResponse({'message': "There are no active devices in the network"}, status=404)
        
    for device in devices:
        # Get all packets for this device
        packets = device.packet_set.all()
        
        # Calculate basic metrics
        total_bits = sum(packet.bytes_transferred * 8 for packet in packets)
        num_packets = packets.count()
        
        # Protocol tracking
        protocol_counts = defaultdict(int)
        # Connected IPs tracking
        connected_ips = set()
        
        for packet in packets:
            try:
                # Track protocols
                protocol = str(packet.protocol)
                protocol_counts[protocol] += 1
                
                # Track connected IPs
                if packet.src_ip != device.ip_address:
                    connected_ips.add(packet.src_ip)
                if packet.dst_ip != device.ip_address:
                    connected_ips.add(packet.dst_ip)
                    
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

        # Update device metrics
        bps = total_bits / 60
        pps = num_packets / 60
        
        device.volume = max(bps, device.volume)
        device.speed = max(pps, device.speed)
        device.training_minutes += 1
        
        # Update protocols and connected IPs
        device.update_protocols(dict(protocol_counts))
        device.update_connected_ips(list(connected_ips))
        
        if device.training_minutes >= Setting.objects.first().training_minutes:
            device.is_trained = True
        else:
            device.is_trained = False
    
        device.save()
        
        # Delete processed packets
        device.packet_set.all().delete()
        
    return JsonResponse({
        "status": "success",
        "processed_devices": len(devices),
        "protocols_detected": list(protocol_counts.keys())
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

def create_alert(device, parameter, current_value, trained_value, severity='high'):
    """Create an alert notification for parameter deviation."""
    message = f"Anomaly detected for device {device.name} ({device.ip_address}): {parameter} deviation. " \
             f"Current: {current_value:.2f}, Trained: {trained_value:.2f}"
    
    return Notification.objects.create(
        message=message,
        type='alert',
        details=json.dumps({
            'device_id': device.id,
            'parameter': parameter,
            'current_value': current_value,
            'trained_value': trained_value,
            'severity': severity
        })
    )

def check_volume_anomaly(device, time_window=60):
    """Check for volume anomalies in the last time_window seconds."""
    end_time = timezone.now()
    start_time = end_time - timedelta(seconds=time_window)
    
    # Calculate current volume in the time window
    packets = device.packet_set.filter(timestamp__range=(start_time, end_time))
    current_volume = sum(p.bytes_transferred for p in packets)
    
    # Compare with trained volume
    if device.is_trained and current_volume > device.volume * 1.5:  # 50% threshold
        create_alert(device, 'Volume', current_volume, device.volume)
        return True, current_volume, device.volume
    return False, current_volume, device.volume

def check_speed_anomaly(device, time_window=60):
    """Check for speed anomalies in the last time_window seconds."""
    end_time = timezone.now()
    start_time = end_time - timedelta(seconds=time_window)
    
    # Calculate current speed (bytes per second) in the time window
    packets = device.packet_set.filter(timestamp__range=(start_time, end_time))
    total_bytes = sum(p.bytes_transferred for p in packets)
    current_speed = total_bytes / time_window if packets.exists() else 0
    
    # Compare with trained speed
    if device.is_trained and current_speed > device.speed * 1.5:  # 50% threshold
        create_alert(device, 'Speed', current_speed, device.speed)
        return True, current_speed, device.speed
    return False, current_speed, device.speed

def check_users_anomaly(device, time_window=60):
    """Check for number of users anomalies in the last time_window seconds."""
    end_time = timezone.now()
    start_time = end_time - timedelta(seconds=time_window)
    
    # Count unique IPs communicating with the device
    packets = device.packet_set.filter(timestamp__range=(start_time, end_time))
    current_users = len(set(p.src_ip for p in packets if p.src_ip != device.ip_address))
    
    # Compare with trained number of users
    if device.is_trained and current_users > device.number_of_users * 1.5:  # 50% threshold
        create_alert(device, 'Number of Users', current_users, device.number_of_users)
        return True, current_users, device.number_of_users
    return False, current_users, device.number_of_users

def check_protocols_anomaly(device, time_window=60):
    """Check for protocol usage anomalies in the last time_window seconds."""
    end_time = timezone.now()
    start_time = end_time - timedelta(seconds=time_window)
    
    # Get current protocol distribution
    packets = device.packet_set.filter(timestamp__range=(start_time, end_time))
    current_protocols = {}
    for packet in packets:
        current_protocols[packet.protocol] = current_protocols.get(packet.protocol, 0) + 1
    
    # Compare with trained protocols
    if device.is_trained and device.protocols:
        trained_protocols = device.protocols
        for protocol, count in current_protocols.items():
            if str(protocol) in trained_protocols:
                if count > trained_protocols[str(protocol)] * 2:  # 100% threshold
                    create_alert(device, f'Protocol {protocol}', count, trained_protocols[str(protocol)])
                    return True, count, trained_protocols[str(protocol)]
            elif count > 10:  # New protocol with significant usage
                create_alert(device, f'New Protocol {protocol}', count, 0)
                return True, count, 0
    return False, sum(current_protocols.values()), sum(device.protocols.values()) if device.protocols else 0

@csrf_exempt
@require_http_methods(["POST"])
def check_parameters(request, device_id=None):
    """API endpoint to check parameters for a specific device or all devices."""
    try:
        if device_id:
            devices = [Device.objects.get(id=device_id)]
        else:
            devices = Device.objects.filter(is_active=True, is_trained=True)

        results = []
        for device in devices:
            volume_result = check_volume_anomaly(device)
            speed_result = check_speed_anomaly(device)
            users_result = check_users_anomaly(device)
            protocols_result = check_protocols_anomaly(device)

            device_result = {
                'device_id': device.id,
                'device_name': device.name,
                'ip_address': device.ip_address,
                'anomalies': {
                    'volume': {
                        'is_anomaly': volume_result[0],
                        'current_value': volume_result[1],
                        'trained_value': volume_result[2]
                    },
                    'speed': {
                        'is_anomaly': speed_result[0],
                        'current_value': speed_result[1],
                        'trained_value': speed_result[2]
                    },
                    'users': {
                        'is_anomaly': users_result[0],
                        'current_value': users_result[1],
                        'trained_value': users_result[2]
                    },
                    'protocols': {
                        'is_anomaly': protocols_result[0],
                        'current_value': protocols_result[1],
                        'trained_value': protocols_result[2]
                    }
                }
            }
            results.append(device_result)

        return JsonResponse({
            'status': 'success',
            'results': results
        })

    except Device.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Device not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

def check_device_parameters_all():
    """Check all parameters for all active devices."""
    devices = Device.objects.filter(is_active=True, is_trained=True)
    
    results = []
    for device in devices:
        # Check each parameter independently and create notifications
        volume_anomaly, current_volume, threshold_volume = check_volume_anomaly(device)
        if volume_anomaly:
            Notification.objects.create(
                type='alert',
                message=f"Volume anomaly detected for device {device.name}",
                details=json.dumps({
                    'device_name': device.name,
                    'current_volume': current_volume,
                    'threshold_volume': threshold_volume
                })
            )

        speed_anomaly, current_speed, threshold_speed = check_speed_anomaly(device)
        if speed_anomaly:
            Notification.objects.create(
                type='alert',
                message=f"Speed anomaly detected for device {device.name}",
                details=json.dumps({
                    'device_name': device.name,
                    'current_speed': current_speed,
                    'threshold_speed': threshold_speed
                })
            )

        users_anomaly, current_users, threshold_users = check_users_anomaly(device)
        if users_anomaly:
            Notification.objects.create(
                type='alert',
                message=f"Unusual number of users detected for device {device.name}",
                details=json.dumps({
                    'device_name': device.name,
                    'current_users': current_users,
                    'threshold_users': threshold_users
                })
            )

        protocols_anomaly, current_protocols, threshold_protocols = check_protocols_anomaly(device)
        if protocols_anomaly:
            Notification.objects.create(
                type='alert',
                message=f"Protocol anomaly detected for device {device.name}",
                details=json.dumps({
                    'device_name': device.name,
                    'current_protocols': current_protocols,
                    'threshold_protocols': threshold_protocols
                })
            )
        
        # Log overall status if any anomaly detected
        if any([volume_anomaly, speed_anomaly, users_anomaly, protocols_anomaly]):
            print(f"Anomalies detected for device {device.name} ({device.ip_address})")
            print(f"Volume: {'❌' if volume_anomaly else '✓'}")
            print(f"Speed: {'❌' if speed_anomaly else '✓'}")
            print(f"Users: {'❌' if users_anomaly else '✓'}")
            print(f"Protocols: {'❌' if protocols_anomaly else '✓'}")
        
        results.append({
            'device': device.name,
            'anomalies': {
                'volume': volume_anomaly,
                'speed': speed_anomaly,
                'users': users_anomaly,
                'protocols': protocols_anomaly
            }
        })
    
    return results

def dos_detection_training():
    """Train devices to detect DoS attacks."""
    try:
        store_captured_packets()
        calculate_parameters(None)  # Pass None since we're not using request
        return "Successfully trained devices to detect DoS attacks"
    except Exception as e:
        return f"Error: {str(e)}"
