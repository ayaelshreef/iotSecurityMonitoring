from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from ..models import Notification

@require_http_methods(["GET"])
def get_notifications(request):
    notifications = Notification.objects.all()[:10]  # Limit to last 10 notifications
    return JsonResponse({
        'notifications': [{
            'id': notification.id,
            'message': notification.message,
            'timestamp': notification.timestamp.isoformat(),
            'is_read': notification.is_read,
        } for notification in notifications]
    })

@csrf_exempt
@require_http_methods(["POST"])
def mark_notification_read(request, notification_id):
    try:
        notification = Notification.objects.get(id=notification_id)
        notification.is_read = True
        notification.save()
        return JsonResponse({'status': 'success'})
    except Notification.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Notification not found'}, status=404)

@csrf_exempt
@require_http_methods(["POST"])
def mark_all_read(request):
    Notification.objects.filter(is_read=False).update(is_read=True)
    return JsonResponse({'status': 'success'})

# def create_notification(message, severity='medium'):
#     """
#     Utility function to create a new notification and broadcast it via WebSocket
#     """
#     notification = Notification.objects.create(
#         message=message,
#         severity=severity
#     )
    
#     # Import here to avoid circular imports
#     from ..consumers import NotificationConsumer
    
#     # Broadcast the notification to all connected clients
#     NotificationConsumer.broadcast_notification({
#         'id': notification.id,
#         'message': notification.message,
#         'timestamp': notification.timestamp.isoformat(),
#         'is_read': notification.is_read,
#         'severity': notification.severity
#     }) 