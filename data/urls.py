"""
URL configuration for data project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from data.views import packets_views, pages_views, scan_network_views, settings_views
from data.views.attacks_check import dos_views
from .views import notifications_views

urlpatterns = [
    path('admin/', admin.site.urls),
    
    path('', pages_views.home),
    path('packets/<str:ip_address>/', packets_views.packets_view),
    
    path('check/', dos_views.check_dos_attack),
    path('scan/', scan_network_views.scan_network_devices),

    path('fetch-packets/<str:ip_address>/', packets_views.fetch_packets_view),
    path('start-sniffer/', packets_views.start_sniffer_view),
    path('stop-sniffer/', packets_views.stop_sniffer_view),
    
    path('devices/calculate-parameters', dos_views.calculate_parameters),
    
    # Notification API endpoints
    path('api/notifications/', notifications_views.get_notifications),
    path('api/notifications/<int:notification_id>/mark-read/', notifications_views.mark_notification_read),
    path('api/notifications/mark-all-read/', notifications_views.mark_all_read),
    
    # Settings
    path('settings/', pages_views.settings_view, name='settings'),
    path('api/settings/training-time/', settings_views.update_training_time, name='update_training_time'),
    path('api/settings/export-reports/', settings_views.export_reports, name='export_reports'),
    
    # Device management endpoints
    path('api/devices/<int:device_id>/update/', pages_views.update_device, name='update_device'),
    path('api/devices/<int:device_id>/delete/', pages_views.delete_device, name='delete_device'),
]
