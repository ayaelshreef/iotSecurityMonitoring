@csrf_exempt
@require_http_methods(["POST"])
def add_device(request):
    try:
        data = json.loads(request.body)
        identifier = data.get('identifier', '').strip()

        if not identifier:
            return JsonResponse({
                'status': 'error',
                'message': 'No identifier provided'
            }, status=400)

        # Check if device already exists
        existing_device = Device.objects.filter(
            Q(ip_address=identifier) | Q(mac_address=identifier)
        ).first()

        if existing_device:
            return JsonResponse({
                'status': 'error',
                'message': 'Device already exists'
            }, status=400)

        # Determine if it's a MAC or IP address
        is_mac = bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', identifier))
        
        # Check network connectivity
        if is_mac:
            # For MAC address, use ARP to find the IP
            network_info = check_device_by_mac(identifier)
            if not network_info:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Device not found on network'
                }, status=404)
            ip_address = network_info['ip_address']
            mac_address = identifier
        else:
            # For IP address, check connectivity and get MAC
            network_info = check_device_by_ip(identifier)
            if not network_info:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Device not responding on network'
                }, status=404)
            ip_address = identifier
            mac_address = network_info['mac_address']

        # Create new device
        device = Device.objects.create(
            name=f"Device_{mac_address.replace(':', '')[-6:]}",
            ip_address=ip_address,
            mac_address=mac_address,
            is_active=True,
            manufacturer=network_info.get('manufacturer', 'Unknown'),
            protocols=[],
            connected_ips=[],
            volume=0.0,
            speed=0.0,
            number_of_users=1,
            training_minutes=0,
            is_trained=False
        )

        return JsonResponse({
            'status': 'success',
            'device': {
                'id': device.id,
                'name': device.name,
                'ip_address': device.ip_address,
                'mac_address': device.mac_address,
                'manufacturer': device.manufacturer
            }
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

def check_device_by_mac(mac_address):
    """Check if a device with given MAC address is on the network."""
    try:
        # Create ARP request packet
        arp = ARP(pdst=get_network_range())
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and get response
        result = srp(packet, timeout=3, verbose=0)[0]

        # Look for matching MAC address
        for sent, received in result:
            if received.hwsrc.lower() == mac_address.lower():
                return {
                    'ip_address': received.psrc,
                    'mac_address': received.hwsrc,
                    'manufacturer': get_manufacturer(received.hwsrc)
                }
        return None
    except Exception as e:
        print(f"Error checking device by MAC: {e}")
        return None

def check_device_by_ip(ip_address):
    """Check if a device with given IP address is on the network."""
    try:
        # Create ARP request packet
        arp = ARP(pdst=ip_address)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and get response
        result = srp(packet, timeout=3, verbose=0)[0]

        if result:
            received = result[0][1]
            return {
                'ip_address': received.psrc,
                'mac_address': received.hwsrc,
                'manufacturer': get_manufacturer(received.hwsrc)
            }
        return None
    except Exception as e:
        print(f"Error checking device by IP: {e}")
        return None

def get_network_range():
    """Get the current network range."""
    try:
        # Get network interface IP and netmask
        output = subprocess.check_output(['ipconfig'], text=True)
        ip_pattern = r'IPv4 Address[^:]*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        mask_pattern = r'Subnet Mask[^:]*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        
        ip = re.search(ip_pattern, output).group(1)
        mask = re.search(mask_pattern, output).group(1)
        
        # Convert to CIDR notation
        network = ipaddress.IPv4Network(f'{ip}/{mask}', strict=False)
        return str(network)
    except Exception as e:
        print(f"Error getting network range: {e}")
        return "192.168.1.0/24"  # Default fallback

def get_manufacturer(mac_address):
    """Get the manufacturer name from MAC address."""
    try:
        # Load OUI database
        oui_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'oui.txt')
        if os.path.exists(oui_file):
            oui_dict = load_oui_database(oui_file)
            mac_prefix = ':'.join(mac_address.split(':')[:3]).upper()
            return oui_dict.get(mac_prefix, "Unknown Manufacturer")
        return "Unknown Manufacturer"
    except Exception as e:
        print(f"Error getting manufacturer: {e}")
        return "Unknown Manufacturer" 