from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from ..models import Setting

@csrf_exempt
@require_http_methods(["POST"])
def update_training_time(request):
    try:
        setting = Setting.objects.first()
        setting.training_minutes = request.POST.get('training_minutes', 0)
        setting.save()

        return JsonResponse({
            'status': 'success',
            'additional_training_required': setting.training_minutes,
            'remaining_minutes': setting.training_minutes
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })
