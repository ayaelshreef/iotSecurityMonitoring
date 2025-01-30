from data.models import Device, Setting
from django.shortcuts import render
from django.http import JsonResponse
from ..models import Notification

def home(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # For AJAX requests, return JSON
        devices = Device.objects.filter(is_active=True)
        devices_data = [
            {
                'ip': device.ip_address,
                'volume': device.volume,
                'speed': device.speed
            } for device in devices
        ]
        return JsonResponse({'devices': devices_data})
    
    # For regular page load, render the template
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