from data.models import Device
from django.shortcuts import render
from django.http import JsonResponse

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