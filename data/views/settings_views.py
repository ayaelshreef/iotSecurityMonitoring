from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from ..models import Setting, Device, Notification
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from io import BytesIO

@csrf_exempt
@require_http_methods(["POST"])
def update_training_time(request):
    try:
        setting = Setting.objects.first()
        if not setting:
            setting = Setting.objects.create(training_minutes=60)
            
        new_minutes = int(request.POST.get('training_minutes', 60))
        setting.training_minutes = new_minutes
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

@require_http_methods(["GET"])
def export_reports(request):
    try:
        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()

        # Title
        elements.append(Paragraph('IoT Security Monitoring Report', styles['Title']))
        elements.append(Paragraph(f'Generated: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}', styles['Normal']))
        elements.append(Spacer(1, 12))

        # Get devices
        devices = Device.objects.all()

        for device in devices:
            # Device header
            elements.append(Paragraph(f'Device: {device.name} ({device.ip_address})', styles['Heading1']))
            
            # Basic info
            data = [
                ['Property', 'Value'],
                ['MAC Address', str(device.mac_address or 'Not available')],
                ['Status', 'Active' if device.is_active else 'Inactive'],
                ['Users', str(device.number_of_users)],
                ['Volume', f'{float(device.volume):.2f}'],
                ['Speed', f'{float(device.speed):.2f}'],
                ['Training', 'Yes' if device.is_trained else 'No'],
                ['Training Minutes', str(device.training_minutes)]
            ]
            
            table = Table(data, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 12))

            # Notifications
            elements.append(Paragraph('Suspicious Activities:', styles['Heading2']))
            notifications = Notification.objects.filter(
                message__icontains=device.ip_address
            ).order_by('-timestamp')

            if notifications.exists():
                for notification in notifications:
                    elements.append(Paragraph(
                        f"{notification.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {notification.message}",
                        styles['Normal']
                    ))
                    elements.append(Spacer(1, 6))
            else:
                elements.append(Paragraph('No activities found', styles['Normal']))
            
            elements.append(Spacer(1, 20))

        # Generate PDF
        doc.build(elements)
        pdf = buffer.getvalue()
        buffer.close()

        # Create response
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="iot-security-report.pdf"'
        response.write(pdf)
        return response

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)
