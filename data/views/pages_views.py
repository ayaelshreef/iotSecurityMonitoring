from data.models import Device, Setting
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from ..models import Notification
from django.views.decorators.http import require_http_methods
import json
from scapy.all import ARP, Ether, srp
import re

def check_network_for_device(identifier):
    # Create ARP request for the specific IP or MAC
    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', identifier):
        # MAC address search
        arp = ARP(pdst="192.168.1.0/24")  # Adjust network range as needed
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether/arp, timeout=2, verbose=False)[0]
        
        for sent, received in result:
            if received.hwsrc.lower() == identifier.lower():
                return {'ip': received.psrc, 'mac': received.hwsrc}
    else:
        # IP address search
        arp = ARP(pdst=identifier)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether/arp, timeout=2, verbose=False)[0]
        
        if result:
            received = result[0][1]
            return {'ip': received.psrc, 'mac': received.hwsrc}
    
    return None

def home(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Filter only active devices
        devices = Device.objects.filter(is_active=True)
        devices_data = [
            {
                'id': device.id,
                'ip': device.ip_address,
                'name': device.name,
                'is_active': device.is_active,
                'number_of_users': device.number_of_users,
            } for device in devices
        ]
        return JsonResponse({'devices': devices_data})
    
    return render(request, 'home.html')

def settings_view(request):
    # Get all notifications ordered by timestamp
    notifications = Notification.objects.all().order_by('-timestamp')
    
    # Get all devices with their related notifications
    devices = Device.objects.all()
    
    # Get the current training minutes from settings
    current_training_minutes = Setting.objects.first().training_minutes if Setting.objects.exists() else 60
    
    # Prepare devices with their related notifications
    for device in devices:
        device.notifications = Notification.objects.filter(
            message__icontains=device.ip_address
        ).order_by('-timestamp')
    
    context = {
        'notifications': notifications,
        'current_training_minutes': current_training_minutes,
        'devices': devices
    }
    
    return render(request, 'settings.html', context)

@require_http_methods(["POST"])
def update_device(request, device_id):
    try:
        device = get_object_or_404(Device, id=device_id)
        data = json.loads(request.body)
        
        # Update device fields
        if 'ip_address' in data:
            device.ip_address = data['ip_address']
        if 'volume' in data:
            device.volume = data['volume']
        if 'speed' in data:
            device.speed = data['speed']
        if 'is_active' in data:
            device.is_active = data['is_active']
            
        device.save()
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

@require_http_methods(["DELETE"])
def delete_device(request, device_id):
    try:
        device = get_object_or_404(Device, id=device_id)
        device.delete()
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def update_device(request, device_id):
    if request.method == 'POST':
        try:
            device = Device.objects.get(id=device_id)
            data = json.loads(request.body)
            
            # Update device fields
            if 'name' in data:
                device.name = data['name']
            if 'number_of_users' in data:
                device.number_of_users = data['number_of_users']
            
            device.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Device updated successfully'
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
            
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=405)

@require_http_methods(["POST"])
def add_device(request):
    try:
        data = json.loads(request.body)
        identifier = data.get('identifier')
        
        if not identifier:
            return JsonResponse({
                'status': 'error',
                'message': 'No identifier provided'
            }, status=400)

        # Check if it's a MAC or IP address
        import re
        is_mac = bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', identifier))
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', identifier))

        if not (is_mac or is_ip):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid MAC or IP address format'
            }, status=400)

        device_found = check_network_for_device(identifier)
        if not device_found:
            return JsonResponse({
                'status': 'error',
                'message': 'Device not found on the network'
            }, status=404)

        # Check if device already exists
        existing_device = Device.objects.filter(
            mac_address=device_found['mac']
        ).first()

        if existing_device:
            return JsonResponse({
                'status': 'error',
                'message': 'Device already exists in the system'
            }, status=400)

        # Create new device
        device = Device.objects.create(
            ip_address=device_found['ip'],
            mac_address=device_found['mac'],
            name=device_found.get('name', ''),
            is_active=True
        )

        return JsonResponse({
            'status': 'success',
            'message': 'Device added successfully'
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)