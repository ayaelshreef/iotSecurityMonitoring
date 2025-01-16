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
firebase=pyrebese.initialize_app(config)
auth=firabase.auth()
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
