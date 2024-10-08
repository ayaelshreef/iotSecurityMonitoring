from django.http import HttpResponse
from django.shortcuts import render
from .models import Device


def home(request) :
    data = Device.objects.all()
    return render(request, 'home/home.html', {'devices' : data})

def device(request, id) :
    data = Device.objects.get(pk=id)
    return render(request, 'data/data.html', {'device' : data})
