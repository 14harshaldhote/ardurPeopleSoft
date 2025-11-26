from dataclasses import dataclass
from typing import Any, Dict, Optional
from django.contrib.auth.models import User
from .services.leave_service import LeaveRequest

@dataclass
class LeaveEvent:
    """Base class for leave events"""
    name: str
    payload: Dict[str, Any]
    actor: User
    timestamp: float

class LeaveCreatedEvent(LeaveEvent):
    def __init__(self, leave_request: LeaveRequest, actor: User):
        self.name = 'leave_created'
        self.actor = actor
        self.payload = {'leave_request': leave_request}

class LeaveApprovedEvent(LeaveEvent):
    def __init__(self, leave_request: LeaveRequest, actor: User):
        self.name = 'leave_approved'
        self.actor = actor
        self.payload = {'leave_request': leave_request}

class LeaveRejectedEvent(LeaveEvent):
    def __init__(self, leave_request: LeaveRequest, actor: User, reason: str):
        self.name = 'leave_rejected'
        self.actor = actor
        self.payload = {'leave_request': leave_request, 'reason': reason}

class EventDispatcher:
    _listeners = []

    @classmethod
    def register(cls, listener):
        cls._listeners.append(listener)

    @classmethod
    def dispatch(cls, event: LeaveEvent):
        for listener in cls._listeners:
            listener.handle(event)
