import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Add the client to the notifications group
        await self.channel_layer.group_add(
            "notifications",
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Remove the client from the notifications group
        await self.channel_layer.group_discard(
            "notifications",
            self.channel_name
        )

    async def notification_message(self, event):
        # Send notification to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'notification': event['notification']
        }))

    @classmethod
    def broadcast_notification(cls, notification):
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "notifications",
            {
                "type": "notification_message",
                "notification": notification
            }
        ) 