from django.db import models

class Packet(models.Model) :
    ip_address = models.CharField(max_length=10)
    description = models.CharField(max_length=200)
    
    def __str__(self):
        return f'{self.description} for {self.ip_address}'