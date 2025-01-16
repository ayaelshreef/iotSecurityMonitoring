import pyrebase
from django.conf import settings

config = {
    "apiKey": "AIzaSyCkdIzcvmp3oOfsmmefjUWflvRUL3LpDx0",
    "authDomain": "anomalyze-b9994.firebaseapp.com",
    "projectId": "anomalyze-b9994",
    "storageBucket": "anomalyze-b9994.firebasestorage.app",
    "messagingSenderId": "727225796759",
    "appId": "1:727225796759:web:02fe258fcea27b7075c1d2",
    "databaseURL": "https://anomalyze-b9994-default-rtdb.firebaseio.com",
}
firebase=pyrebase.initialize_app(config)
auth=firebase.auth()
db=firebase.database()

def get_data(path):
    """Retrieve data from a specific path."""
    return db.child(path).get().val()

def set_data(path, data):
    """Set data at a specific path."""
    db.child(path).set(data)

def update_data(path, data):
    """Update data at a specific path."""
    db.child(path).update(data)

def delete_data(path):
    """Delete data at a specific path."""
    db.child(path).remove()

def push_data(path, data):
    """Push data to a list-like structure."""
    return db.child(path).push(data)

def update_or_create_device(mac_address, device_info):
    """
    Check if a device with the given mac_address exists. 
    If it does, update its data; if not, create a new device entry.
    """
    # Check if device exists by looking up mac_address
    device_ref = db.child("devices").order_by_child("mac_address").equal_to(mac_address).get()
    
    # If the device exists, update it
    if device_ref.each():
        for device in device_ref.each():
            device_key = device.key()  # Get the unique key for the device
            db.child("devices").child(device_key).update({
                "ip_address": device_info.get("ip_address"),
                "is_active": device_info.get("is_active", True)  # Default to True if not specified
            })
    else:
        # If the device doesn't exist, create a new entry
        db.child("devices").push({
            "mac_address": mac_address,
            "ip_address": device_info.get("ip_address"),
            "is_active": device_info.get("is_active", True)
        })

def update_devices_activity(processed_mac_addresses):
    """
    Set devices whose mac_address is not in processed_mac_addresses to inactive.
    """
    # Query for all devices
    devices_ref = db.child("devices").get()
    
    # If devices are present, check their mac_address and update `is_active` accordingly
    if devices_ref.each():
        for device in devices_ref.each():
            device_data = device.val()
            device_key = device.key()  # Get the unique key for the device
            
            # Set `is_active=False` for devices not in the processed list
            if device_data["mac_address"] not in processed_mac_addresses:
                db.child("devices").child(device_key).update({
                    "is_active": False
                })

