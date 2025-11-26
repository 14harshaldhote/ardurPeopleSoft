from typing import List, Optional
from django.contrib.auth.models import User
from .events import LeaveEvent, LeaveCreatedEvent, LeaveApprovedEvent, LeaveRejectedEvent

class NotificationRule:
    def evaluate(self, event: LeaveEvent) -> List[User]:
        raise NotImplementedError

class NotifyManagerRule(NotificationRule):
    def evaluate(self, event: LeaveEvent) -> List[User]:
        if isinstance(event, LeaveCreatedEvent):
            leave_request = event.payload['leave_request']
            if leave_request.approver:
                return [leave_request.approver]
        return []

class NotifyRequesterRule(NotificationRule):
    def evaluate(self, event: LeaveEvent) -> List[User]:
        if isinstance(event, (LeaveApprovedEvent, LeaveRejectedEvent)):
            leave_request = event.payload['leave_request']
            return [leave_request.user]
        return []

class RuleEngine:
    def __init__(self):
        self.rules = [NotifyManagerRule(), NotifyRequesterRule()]

    def process(self, event: LeaveEvent) -> List[dict]:
        notifications = []
        for rule in self.rules:
            recipients = rule.evaluate(event)
            for recipient in recipients:
                notifications.append({
                    'recipient': recipient,
                    'event': event
                })
        return notifications
