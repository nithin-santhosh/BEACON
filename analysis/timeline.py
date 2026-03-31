from datetime import datetime

class BehaviorTimeline:
    def __init__(self):
        self.events = []

    def add_event(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.events.append((timestamp, message))

    def get_events(self):
        return self.events

    def as_text(self):
        return "\n".join([f"{t} - {m}" for t, m in self.events])
