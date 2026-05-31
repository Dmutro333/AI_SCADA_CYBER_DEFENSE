from datetime import datetime


class SessionManager:
    def __init__(self, timeout_seconds=1800):
        self.timeout_seconds = timeout_seconds
        self.login_time = datetime.now()
        self.last_activity = datetime.now()
        self.active = True

    def update_activity(self):
        self.last_activity = datetime.now()
        self.active = True

    def mark_activity(self):
        self.update_activity()

    def is_session_expired(self):
        if not self.active:
            return True

        elapsed = datetime.now() - self.last_activity
        return elapsed.total_seconds() > self.timeout_seconds

    def is_expired(self):
        return self.is_session_expired()

    def get_session_duration(self):
        duration = datetime.now() - self.login_time
        minutes = int(duration.total_seconds() // 60)
        seconds = int(duration.total_seconds() % 60)
        return f"{minutes} хв {seconds} сек"

    def get_duration(self):
        return self.get_session_duration()

    def get_login_time(self):
        return self.login_time.strftime("%Y-%m-%d %H:%M:%S")

    def logout(self):
        self.active = False

    def reset(self):
        self.login_time = datetime.now()
        self.last_activity = datetime.now()
        self.active = True