from celery import shared_task
from data.views.attacks_check.dos_views import check_device_parameters_all, dos_detection_training

@shared_task
def check_device_parameters():
    """Task to check all parameters for all active devices."""
    return check_device_parameters_all()

@shared_task
def train_dos_detection():
    """Task to train devices for DoS detection."""
    return dos_detection_training()