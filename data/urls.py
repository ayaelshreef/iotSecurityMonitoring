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
from data import views

urlpatterns = [
    path('admin/', admin.site.urls),
    
    path('', views.home),
    # path('<int:id>', views.device),
    
    path('scan/', views.scan_network_devices),

    path('packets/<str:ip_address>/', views.packets_view),
    path('fetch-packets/<str:ip_address>/', views.fetch_packets_view),
    path('display-packets/', views.display_packets_view),
    path('start-sniffer/', views.start_sniffer_view),
    path('stop-sniffer/', views.stop_sniffer_view),
    
    path('packets/<str:ip_address>/volume', views.calculate_bps),
    path('get-volume/<str:ip_address>/', views.get_volume),
]
