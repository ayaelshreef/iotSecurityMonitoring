from data.models import Device, Setting
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from ..models import Notification
from django.views.decorators.http import require_http_methods
import json

def home(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        devices = Device.objects.all()
        devices_data = [
            {
                'ip': device.ip_address,
                'is_active': device.is_active,
                'id': device.id,
                'number_of_users': device.number_of_users  # Add number of users
            } for device in devices
        ]
        return JsonResponse({'devices': devices_data})
    
    return render(request, 'home.html')

def settings_view(request):
    # Get all notifications ordered by timestamp
    notifications = Notification.objects.all().order_by('-timestamp')
    
    # Get the current training minutes from any device (assuming all devices have the same training time)
    current_training_minutes = Setting.objects.first().training_minutes
    
    context = {
        'notifications': notifications,
        'current_training_minutes': current_training_minutes
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
    