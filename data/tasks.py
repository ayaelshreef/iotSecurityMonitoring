from urllib import request
from celery import shared_task
from data.views.attacks_check.dos_views import check_device_parameters_all, dos_detection_training
from data.views.scan_network_views import scan_network_devices

@shared_task(name="scanning")
def update_device_statuses():
    """Task to update device statuses every minute."""
    return scan_network_devices(request,update_only=True)

@shared_task(name="training")
def train_dos_detection():
    """Task to train devices for DoS detection."""
    return dos_detection_training()

@shared_task(name="detection")
def check_device_parameters():
    """Task to check all parameters for all active devices."""
    return check_device_parameters_all()