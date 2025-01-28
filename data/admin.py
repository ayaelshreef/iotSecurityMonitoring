from django.contrib import admin

from .models import Device, Notification, Packet
# ,NetworkTraffic, BehavioralPattern, SecurityEvent, Anomaly, DeviceVolume

admin.site.register(Device)
admin.site.register(Packet)
admin.site.register(Notification)
# admin.site.register(NetworkTraffic)
# admin.site.register(BehavioralPattern)
# admin.site.register(SecurityEvent)
# admin.site.register(Anomaly)
# admin.site.register(DeviceVolume)