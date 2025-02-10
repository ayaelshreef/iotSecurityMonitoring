from django.db import models
from django.utils import timezone

# class Device(models.Model):
#     device_type = models.CharField(max_length=255, blank=True, null=True)
#     mac_address = models.CharField(max_length=225)
#     ip_address = models.GenericIPAddressField()
#     firmware_version = models.CharField(max_length=50, blank=True, null=True)
#     security_settings = models.JSONField(blank=True, null=True)
#     last_seen = models.DateTimeField(default=timezone.now, blank=True, null=True)

#     def __str__(self):
#         return f"{self.device_type} ({self.ip_address})"

# class NetworkTraffic(models.Model):
#     device = models.ForeignKey(Device, related_name='traffic', on_delete=models.CASCADE)
#     source_ip = models.GenericIPAddressField()
#     dest_ip = models.GenericIPAddressField()
#     source_port = models.IntegerField()
#     dest_port = models.IntegerField()
#     protocol = models.CharField(max_length=10)
#     bytes_transferred = models.IntegerField()
#     packets_transferred = models.IntegerField()
#     timestamp = models.DateTimeField(default=timezone.now)

# class BehavioralPattern(models.Model):
#     device = models.ForeignKey(Device, related_name='patterns', on_delete=models.CASCADE)
#     normal_traffic_freq = models.IntegerField()
#     average_data_volume = models.IntegerField()
#     common_peers = models.TextField(blank=True, null=True)

# class SecurityEvent(models.Model):
#     device = models.ForeignKey(Device, related_name='events', on_delete=models.CASCADE)
#     event_type = models.CharField(max_length=50)
#     description = models.TextField(blank=True, null=True)
#     timestamp = models.DateTimeField(default=timezone.now)

# class Anomaly(models.Model):
#     device = models.ForeignKey(Device, related_name='anomalies', on_delete=models.CASCADE)
#     anomaly_type = models.CharField(max_length=50)
#     severity = models.CharField(max_length=20)
#     timestamp = models.DateTimeField(default=timezone.now)
#     actions_taken = models.TextField(blank=True, null=True)
    
class Device(models.Model):
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=225, null=True)
    volume = models.DecimalField(max_digits=50, decimal_places=2, default=0.00)
    speed = models.DecimalField(max_digits=50, decimal_places=2, default=0.00)
    # frequency = models.DecimalField(max_digits=50, decimal_places=2, null=True)
    is_active = models.BooleanField(default=True)
    number_of_users = models.IntegerField(default=1)
    training_minutes = models.IntegerField(default=0)
    is_trained = models.BooleanField(default=False)
    traffic_volume = models.DecimalField(max_digits=50, decimal_places=2, default=0.00)
    protocols = models.JSONField(default=dict)  # New field to store protocol counts
    
    def update_protocols(self, new_protocols):
        current_protocols = self.protocols or {}
        for protocol, count in new_protocols.items():
            current_protocols[protocol] = current_protocols.get(protocol, 0) + count
        self.protocols = current_protocols
        self.save()

class Setting(models.Model):
    training_minutes = models.IntegerField(default=60)

class Packet(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    timestamp = models.DateTimeField()
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    protocol = models.IntegerField()
    bytes_transferred = models.IntegerField()
    details = models.TextField()

class Notification(models.Model):
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    details = models.TextField(null=True)
    type = models.CharField(max_length=255, blank=True, null=True)

    # severity = models.CharField(max_length=20, choices=[
    #     ('low', 'Low'),
    #     ('medium', 'Medium'),
    #     ('high', 'High'),
    #     ('critical', 'Critical')
    # ], default='medium')
    
    # class Meta:
    #     ordering = ['-timestamp']

    # def __str__(self):
    #     return f"{self.get_severity_display()} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"