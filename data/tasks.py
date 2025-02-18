from celery import shared_task
from data.views.attacks_check.dos_views import dos_detection_training
from data.views.scan_network_views import scan_network_devices
from celery.schedules import crontab
from data import celery_app

@shared_task(name="scanning")
def update_device_statuses():
    """Task to update device statuses every minute."""
    try:
        result = scan_network_devices(None, update_only=True)
        return f"Scanning completed: {result}"
    except Exception as e:
        return f"Error in scanning task: {str(e)}"

@shared_task(name="training")
def train_dos_detection():
    """Task to train devices for DoS detection."""
    try:
        result = dos_detection_training()
        return f"Training completed: {result}"
    except Exception as e:
        return f"Error in training task: {str(e)}"

# Define the periodic task schedule
celery_app.conf.beat_schedule = {
    'scan-devices-every-minute': {
        'task': 'scanning',
        'schedule': 60.0,  # Every 60 seconds
    },
    'train-devices-every-5-minutes': {
        'task': 'training',
        'schedule': 60.0,  # Every 300 seconds (5 minutes)
    },
}