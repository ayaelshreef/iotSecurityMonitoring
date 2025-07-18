from django.db import models
    
class Device(models.Model):
    ip_address = models.GenericIPAddressField()
    name = models.CharField(max_length=255, null=True, blank=True)
    mac_address = models.CharField(max_length=225, null=True)
    volume = models.DecimalField(max_digits=50, decimal_places=2, default=0.00)
    speed = models.DecimalField(max_digits=50, decimal_places=2, default=0.00)
    is_active = models.BooleanField(default=True)
    number_of_users = models.IntegerField(default=1)
    training_minutes = models.IntegerField(default=0)
    is_trained = models.BooleanField(default=False)
    protocols = models.JSONField(default=list)  # Changed from dict to list
    connected_ips = models.JSONField(default=list)  # Changed from dict to list
    
    def update_protocols(self, new_protocols):
        current_protocols = self.protocols or []
        self.protocols = list(set(current_protocols + new_protocols))  # Ensures unique values
        self.save()

    def update_connected_ips(self, new_ips):
        current_ips = self.connected_ips or []
        self.connected_ips = list(set(current_ips + new_ips))  # Ensures unique values
        self.save()

    def save(self, *args, **kwargs):
        if not self.name:
            self.name = self.ip_address
        super().save(*args, **kwargs)

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
    device = models.ForeignKey(Device, on_delete=models.CASCADE, null=True)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    details = models.TextField(null=True)
    type = models.CharField(max_length=255, blank=True, null=True)
    parameter = models.CharField(max_length=255, blank=True, null=True)
