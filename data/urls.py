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
from data.views import packets_views, pages_views, scan_network_views
from data.views.attacks_check import dos_views

urlpatterns = [
    path('admin/', admin.site.urls),
    
    path('', pages_views.home),
    path('packets/<str:ip_address>/', packets_views.packets_view),
    
    path('scan/', scan_network_views.scan_network_devices),

    path('fetch-packets/<str:ip_address>/', packets_views.fetch_packets_view),
    path('start-sniffer/', packets_views.start_sniffer_view),
    path('stop-sniffer/', packets_views.stop_sniffer_view),
    
    path('devices/calculate-parameters', dos_views.calculate_parameters),
    # path('check-dos/<str:ip_address>/', dos_views.check_dos_attack),
]
