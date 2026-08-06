from datetime import datetime, timedelta

from app.models.security_event import SecurityEvent


class EventStore:

    def __init__(self):
        self.events: list[SecurityEvent] = []


    def add(self, event: SecurityEvent):

        #Store a new security event.


        self.events.append(event) #Adds the event to the list


    def all(self):

        return self.events


    def get_recent(self, seconds: int):

        cutoff = datetime.now() - timedelta(seconds=seconds)

        return [
            event
            for event in self.events
            if event.timestamp >= cutoff
        ]


    def get_by_user(self, user: str):


        return [
            event
            for event in self.events
            if event.user == user
        ]


    def get_by_ip(self, ip_address: str):


        return [
            event
            for event in self.events
            if event.ip_address == ip_address
        ]


    def get_by_type(self, event_type: str):


        return [
            event
            for event in self.events
            if event.event_type == event_type
        ]