from celery import shared_task
from data.views.scan_network_views import scan_network_devices
from data.views.attacks_check.dos_views import calculate_parameters, store_captured_packets, check_dos_attack
import requests
from django.http import HttpRequest

@shared_task
def dos_detection_training():
    try:
        request = HttpRequest()
        scan_network_devices()
        check_dos_attack()
        store_captured_packets()
        calculate_parameters(request)
        return "Successfully trained devices to detect DoS attacks, and checked for potential DoS attacks"
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"
    
