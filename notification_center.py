from datetime import datetime, timedelta


class NotificationCenter:
    def __init__(self, cooldown_seconds=30, max_notifications=500):
        self.notifications = []
        self.last_alert_times = {}

        self.cooldown_seconds = cooldown_seconds
        self.max_notifications = max_notifications

        self.unread_count = 0
        self.critical_count = 0

    def _generate_id(self):
        return f"NOTIFY-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"

    def _trim_history(self):
        self.notifications = self.notifications[:self.max_notifications]

    def add_notification(self, title, message, level="INFO"):
        key = f"{title}:{level}"
        now = datetime.now()

        # Cooldown anti-spam
        if key in self.last_alert_times:
            diff = now - self.last_alert_times[key]

            if diff < timedelta(seconds=self.cooldown_seconds):
                return None

        self.last_alert_times[key] = now

        notification = {
            "id": self._generate_id(),
            "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "title": title,
            "message": message,
            "level": level,
            "acknowledged": False
        }

        self.notifications.insert(0, notification)

        self.unread_count += 1

        if level == "CRITICAL":
            self.critical_count += 1

        self._trim_history()

        return notification

    def acknowledge_notification(self, notification_id):
        for notification in self.notifications:
            if notification["id"] == notification_id:
                if not notification["acknowledged"]:
                    notification["acknowledged"] = True
                    self.unread_count = max(0, self.unread_count - 1)

                return True

        return False

    def acknowledge_all(self):
        count = 0

        for notification in self.notifications:
            if not notification["acknowledged"]:
                notification["acknowledged"] = True
                count += 1

        self.unread_count = 0

        return count

    def get_notifications(self, limit=100):
        return self.notifications[:limit]

    def get_by_level(self, level, limit=100):
        filtered = [
            n for n in self.notifications
            if n["level"] == level
        ]

        return filtered[:limit]

    def get_unread(self, limit=100):
        unread = [
            n for n in self.notifications
            if not n["acknowledged"]
        ]

        return unread[:limit]

    def clear_notifications(self):
        self.notifications.clear()
        self.last_alert_times.clear()

        self.unread_count = 0
        self.critical_count = 0

    def get_statistics(self):
        levels = {
            "INFO": 0,
            "WARNING": 0,
            "HIGH": 0,
            "CRITICAL": 0
        }

        for notification in self.notifications:
            level = notification["level"]

            if level not in levels:
                levels[level] = 0

            levels[level] += 1

        return {
            "total": len(self.notifications),
            "unread": self.unread_count,
            "critical": self.critical_count,
            "levels": levels
        }