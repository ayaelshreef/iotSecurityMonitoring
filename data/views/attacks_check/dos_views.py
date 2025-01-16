from django.http import JsonResponse
from scapy.all import sniff, IP
from data.models import Device
from time import time

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
                'data': data  # This can be the raw packet bytes or payload
            })

    # Capture packets for 1 second
    sniff(timeout=1, prn=packet_callback)

    return packets

def calculate_bps(packet, ip_address, monitor_duration_minutes=1):
    results = []  # To store the total bits transferred for each minute
    start_time = time()  # Start time of monitoring
    current_minute_start = start_time  # Track when the current minute started

    while (time() - start_time) < monitor_duration_minutes * 60:
        # Initialize variables for the current minute
        minute_bits = 0

        # Loop through the current minute
        while time() - current_minute_start < 60:
            # Get packets for the current second
            packets = get_packets_func()
            
            # Calculate bits transferred for packets in the current second
            for packet in packets:
                if packet['src_ip'] == ip_address or packet['dst_ip'] == ip_address:
                    minute_bits += len(packet) * 8  # Convert bytes to bits

        # After 60 seconds, append the result for the current minute
        bps = minute_bits/60
        results.append(bps)

        print(f"The volume for the device {ip_address}: {bps} bits per second")

        # Reset the minute timer and continue to the next minute
        current_minute_start = time()

    Device.objects.filter(ip_address=ip_address).update(volume=max(results))

    return JsonResponse({'volume': max(results)})

def get_volume(request, ip_address):
    try:
        device_volume = Device.objects.get(ip_address=ip_address)
        return JsonResponse({'volume': device_volume.volume}, status=200)
    except Device.DoesNotExist:
        return JsonResponse({'volume': None}, status=404)

def check_dos_attack(request, ip_address):
    # Simulate fetching packets and calculating current minute volume
    device_volume = Device.objects.get(ip_address=ip_address).volume
    device_speed = Device.objects.get(ip_address=ip_address).speed
    minute_bits = 0
    current_minute_start = time()
    
    try:
        # Loop through the current minute
        while time() - current_minute_start < 60:
            # Get packets for the current second
            packets = get_packets_func()
            
            # Calculate bits transferred for packets in the current second
            for packet in packets:
                if packet['src_ip'] == ip_address or packet['dst_ip'] == ip_address:
                    minute_bits += len(packet) * 8  # Convert bytes to bits
                    minute_packets += 1  

        # After 60 seconds, append the result for the current minute
        current_volume = minute_bits/60
        current_speed = minute_packets/60
        if current_volume > device_volume and current_speed > device_speed:
            return JsonResponse({"exceeded": True})
        else:
            return JsonResponse({"exceeded": False})
    except Device.DoesNotExist:
            pass  # Ignore packets without a matching DeviceVolume entry
        
        



def calculate_pps(packet, ip_address, monitor_duration_minutes=1):
    results = []  # To store the total bits transferred for each minute
    start_time = time()  # Start time of monitoring
    current_minute_start = start_time  # Track when the current minute started

    while (time() - start_time) < monitor_duration_minutes * 60:
        # Initialize variables for the current minute
        minute_packets = 0

        # Loop through the current minute
        while time() - current_minute_start < 60:
            # Get packets for the current second
            packets = get_packets_func()
            
            # Calculate bits transferred for packets in the current second
            for packet in packets:
                if packet['src_ip'] == ip_address or packet['dst_ip'] == ip_address:
                    minute_packets += 1  

        # After 60 seconds, append the result for the current minute
        pps = minute_packets/60
        results.append(pps)

        print(f"The speed for the device {ip_address}: {pps} packets per second")

        # Reset the minute timer and continue to the next minute
        current_minute_start = time()

    Device.objects.filter(ip_address=ip_address).update(speed=max(results))

    return JsonResponse({'speed': max(results)})

def get_speed(request, ip_address):
    try:
        device_speed = Device.objects.get(ip_address=ip_address)
        return JsonResponse({'speed': device_speed.speed}, status=200)
    except Device.DoesNotExist:
        return JsonResponse({'speed': None}, status=404)
    

def add_request(device_ip):
    current_time = int(time() * 1000)  # Current time in milliseconds
    key = f"device:{device_ip}:requests"

    # Add timestamp to sorted set
    redis_client.zadd(key, {current_time: current_time})

    # Remove entries older than 60 seconds
    redis_client.zremrangebyscore(key, 0, current_time - 60000)

    # Set TTL for automatic cleanup
    redis_client.expire(key, 120)  # Optional: 2-minute expiration
