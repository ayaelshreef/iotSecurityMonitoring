from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from ..models import Setting, Device, Notification
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from io import BytesIO
import json
from ..utils import format_timestamp

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

        # Update devices' training status
        devices = Device.objects.all()
        for device in devices:
            if device.training_minutes <= new_minutes:
                device.is_trained = False
            else:
                device.is_trained = True
            device.save()

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
        
        try:
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
            elements = []
            styles = getSampleStyleSheet()
            
            # Create a reference date (January 1st, 2025)
            reference_date = timezone.datetime(2025, 1, 1).date()
            current_time = timezone.now()
            
            try:
                # Combine reference date with current time
                report_timestamp = timezone.datetime.combine(
                    reference_date,
                    current_time.time(),
                    tzinfo=current_time.tzinfo
                )
            except Exception as e:
                print(f"Error creating timestamp: {str(e)}")
                report_timestamp = timezone.now()
            
            # Add custom styles
            styles.add(ParagraphStyle(
                name='CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.HexColor('#507687')
            ))
            styles.add(ParagraphStyle(
                name='SectionHeader',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=20,
                textColor=colors.HexColor('#456a77')
            ))
            styles.add(ParagraphStyle(
                name='SubHeader',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=10,
                textColor=colors.HexColor('#666666')
            ))

            # Title and timestamp
            elements.append(Paragraph('IoT Security Monitoring Report', styles['CustomTitle']))
            elements.append(Paragraph(f'Generated: {format_timestamp(timezone.now())}', styles['Normal']))
            elements.append(Spacer(1, 20))

            # System Overview
            elements.append(Paragraph('System Overview', styles['SectionHeader']))
            total_devices = Device.objects.count()
            active_devices = Device.objects.filter(is_active=True).count()
            trained_devices = Device.objects.filter(is_trained=True).count()
            total_alerts = Notification.objects.filter(type='alert').count()

            overview_data = [
                ['Metric', 'Value'],
                ['Total Devices', str(total_devices)],
                ['Active Devices', str(active_devices)],
                ['Trained Devices', str(trained_devices)],
                ['Total Alerts', str(total_alerts)]
            ]
            
            overview_table = Table(overview_data, colWidths=[200, 300])
            overview_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#507687')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(overview_table)
            elements.append(Spacer(1, 30))

            # Device Details
            elements.append(Paragraph('Device Details', styles['SectionHeader']))
            devices = Device.objects.all().order_by('-is_active', 'name')

            for device in devices:
                # Device header with status indicator
                status_color = '#10B981' if device.is_active else '#6B7280'
                device_header = f'<font color="{status_color}">● </font>{device.name} ({device.ip_address})'
                elements.append(Paragraph(device_header, styles['SubHeader']))
                
                # Device information table
                device_data = [
                    ['Property', 'Value'],
                    ['MAC Address', str(device.mac_address or 'Not available')],
                    ['Status', 'Active' if device.is_active else 'Inactive'],
                    ['Training Status', 'Trained' if device.is_trained else 'In Training'],
                    ['Training Progress', f'{device.training_minutes} minutes'],
                    ['Number of Users', str(device.number_of_users)],
                    ['Data Volume', f'{float(device.volume):.2f} bits/sec'],
                    ['Packet Speed', f'{float(device.speed):.2f} packets/sec'],
                    ['Allowed Protocols', ', '.join(map(str, device.protocols)) or 'None'],
                    ['Connected IPs', ', '.join(device.connected_ips) or 'None']
                ]
                
                device_table = Table(device_data, colWidths=[150, 350])
                device_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#507687')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('TOPPADDING', (0, 1), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(device_table)
                elements.append(Spacer(1, 20))

            # Add page break before Security Alerts section
            elements.append(PageBreak())
            
            # Security Alerts Section on new page
            elements.append(Paragraph('Security Alerts History', styles['SectionHeader']))
            
            # Get all alerts across all devices
            alerts = Notification.objects.filter(
                type='alert'
            ).order_by('-timestamp')

            if alerts.exists():
                # Create alerts table header
                alerts_data = [
                    ['Timestamp', 'Device', 'Parameter', 'Description']
                ]
                
                # Add each alert to the table
                for alert in alerts:
                    try:
                        # Get timestamp from alert model instead of details
                        alert_timestamp = timezone.datetime.combine(
                            reference_date,
                            alert.timestamp.time(),
                            tzinfo=alert.timestamp.tzinfo
                        )
                        timestamp = alert_timestamp.strftime("%Y-%m-%d %H:%M:%S")
                        
                        # Get device information directly from the alert's device
                        device_name = alert.device.name if alert.device else 'Unknown Device'
                        device_ip = alert.device.ip_address if alert.device else 'Unknown IP'
                        device_info = f"{device_name} ({device_ip})"
                        
                        # Parse details if it's a string
                        if isinstance(alert.details, str):
                            details = json.loads(alert.details)
                        else:
                            details = alert.details
                            
                        # Get parameter from details
                        parameter = details.get('parameter', 'Unknown')
                        
                        # Create a detailed description based on the parameter type
                        if parameter == 'Speed':
                            current_value = details.get('current_value', '')
                            trained_value = details.get('trained_value', '')
                            description = f"Packet rate exceeded baseline\nCurrent: {current_value} packets/sec\nBaseline: {trained_value} packets/sec"
                        elif parameter == 'IP':
                            current_ip = details.get('current_value', '')
                            trained_ips = details.get('trained_value', '')
                            description = f"Unauthorized IP detected: {current_ip}\nAllowed IPs: {trained_ips}"
                        elif parameter == 'Volume':
                            current_value = details.get('current_value', '')
                            trained_value = details.get('trained_value', '')
                            description = f"Traffic volume exceeded baseline\nCurrent: {current_value} bits/sec\nBaseline: {trained_value} bits/sec"
                        elif parameter == 'Protocol':
                            current_value = details.get('current_value', '')
                            trained_value = details.get('trained_value', '')
                            description = f"Unauthorized protocol detected\nProtocol: {current_value}\nAllowed: {trained_value}"
                        else:
                            current_value = details.get('current_value', '')
                            trained_value = details.get('trained_value', '')
                            description = f"Anomaly detected\nCurrent: {current_value}\nBaseline: {trained_value}"

                        alerts_data.append([
                            timestamp,
                            device_info,
                            parameter,
                            description
                        ])
                    except Exception as e:
                        print(f"Error processing alert {alert.id}: {str(e)}")
                        continue
                
                if len(alerts_data) > 1:  # If we have alerts beyond the header
                    # Calculate column widths based on content
                    available_width = doc.width
                    col_widths = [
                        available_width * 0.18,  # Timestamp: 18% of width
                        available_width * 0.22,  # Device: 22% of width
                        available_width * 0.15,  # Parameter: 15% of width
                        available_width * 0.45   # Description: 45% of width
                    ]
                    
                    alerts_table = Table(alerts_data, colWidths=col_widths, repeatRows=1)
                    alerts_table.setStyle(TableStyle([
                        # Header style
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#507687')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),  # Center align headers
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('TOPPADDING', (0, 0), (-1, 0), 8),
                        
                        # Content style
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#333333')),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('TOPPADDING', (0, 1), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                        
                        # Column-specific alignment
                        ('ALIGN', (0, 1), (0, -1), 'LEFT'),    # Timestamp
                        ('ALIGN', (1, 1), (1, -1), 'LEFT'),    # Device
                        ('ALIGN', (2, 1), (2, -1), 'LEFT'),    # Parameter
                        ('ALIGN', (3, 1), (3, -1), 'LEFT'),    # Description
                        
                        # Enable text wrapping
                        ('WORDWRAP', (0, 0), (-1, -1), True),
                        
                        # Subtle grid
                        ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#E5E7EB')),
                        ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor('#507687')),
                        
                        # Spacing
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        
                        # Alternating row colors
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F9FAFB')]),
                    ]))
                    
                    # Process each row for text wrapping
                    for i in range(len(alerts_data)):
                        if i > 0:  # Skip header row
                            # Wrap the description text
                            description = alerts_data[i][3]
                            max_chars_per_line = 45  # Slightly reduced for better wrapping
                            words = description.split()
                            lines = []
                            current_line = []
                            
                            for word in words:
                                if len(' '.join(current_line + [word])) <= max_chars_per_line:
                                    current_line.append(word)
                                else:
                                    if current_line:
                                        lines.append(' '.join(current_line))
                                        current_line = [word]
                                    else:
                                        lines.append(word)
                            
                            if current_line:
                                lines.append(' '.join(current_line))
                            
                            alerts_data[i][3] = '\n'.join(lines)
                    
                    elements.append(alerts_table)
                    
                    # Add alert statistics with improved styling
                    elements.append(Spacer(1, 15))
                    alert_stats = Paragraph(
                        f"<font color='#507687'><b>Total Alerts:</b></font> {len(alerts_data) - 1}",
                        styles['Normal']
                    )
                    elements.append(alert_stats)
            else:
                elements.append(Paragraph('No alerts found.', styles['Normal']))
            
            # Build the PDF document with error catching
            try:
                doc.build(elements)
            except Exception as e:
                print(f"Error building PDF: {str(e)}")
                raise

            # Get the value of the BytesIO buffer
            pdf = buffer.getvalue()
            buffer.close()
            
            # Generate the response
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="iot_security_report.pdf"'
            response.write(pdf)
            
            return response
            
        except Exception as e:
            print(f"Error in PDF generation process: {str(e)}")
            raise
            
    except Exception as e:
        print(f"Fatal error in export_reports: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': f"Error generating PDF: {str(e)}"
        }, status=500)
    finally:
        # Ensure buffer is always closed
        if 'buffer' in locals():
            buffer.close()
