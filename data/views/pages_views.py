from data.models import Device
from django.shortcuts import render

def home(request) :
    data = Device.objects.all()
    return render(request, 'home.html', {'devices' : data})
