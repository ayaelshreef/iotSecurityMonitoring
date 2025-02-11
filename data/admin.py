from django.contrib import admin

from .models import Device, Notification, Packet, Setting
# ,NetworkTraffic, BehavioralPattern, SecurityEvent, Anomaly, DeviceVolume

admin.site.register(Device)
admin.site.register(Packet)
admin.site.register(Notification)
admin.site.register(Setting)