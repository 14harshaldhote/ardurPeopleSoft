from django import forms
from .models import Chat, Message

class ChatForm(forms.ModelForm):
    """
    Form for creating a new chat
    """
    class Meta:
        model = Chat
        fields = ['name', 'type']

class MessageForm(forms.ModelForm):
    """
    Form for sending messages
    """
    class Meta:
        model = Message
        fields = ['content']