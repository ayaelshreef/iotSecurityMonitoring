from django.http import HttpResponse
from django.shortcuts import render
from .models import Packet


def packets(request) :
    data = Packet.objects.all()
    return render(request, 'data/data.html', {'packets' : data})
