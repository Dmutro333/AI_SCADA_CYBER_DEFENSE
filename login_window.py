from PyQt5.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QMessageBox, QFrame
)
from PyQt5.QtCore import Qt

from database import check_user, add_event_log, add_audit_record
from scada_window import SCADAWindow


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.scada_window = None

        self.setWindowTitle("AI SCADA Cyber Defense — Login")
        self.setGeometry(500, 250, 420, 360)

        self.setStyleSheet("""
            QWidget {
                background-color: #111827;
                color: white;
                font-family: Arial;
            }
            QLabel {
                font-size: 14px;
            }
            QLineEdit {
                padding: 10px;
                border: 1px solid #374151;
                border-radius: 8px;
                background-color: #1f2937;
                color: white;
                font-size: 14px;
            }
            QPushButton {
                padding: 12px;
                border-radius: 8px;
                background-color: #2563eb;
                color: white;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
            QFrame {
                background-color: #0f172a;
                border-radius: 16px;
                padding: 20px;
            }
        """)

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignCenter)

        frame = QFrame()
        layout = QVBoxLayout(frame)

        title = QLabel("AI SCADA CYBER DEFENSE")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #38bdf8;"
        )

        subtitle = QLabel("Система кіберзахисту критичної інфраструктури")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("font-size: 13px; color: #cbd5e1;")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Логін")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Пароль")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.password_input.returnPressed.connect(self.login)
        self.username_input.returnPressed.connect(self.password_input.setFocus)

        login_button = QPushButton("Увійти в систему")
        login_button.clicked.connect(self.login)

        hint = QLabel(
            "Тестові користувачі:\n"
            "admin / admin123\n"
            "operator / operator123\n"
            "analyst / analyst123"
        )
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet("font-size: 12px; color: #94a3b8;")

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(20)
        layout.addWidget(QLabel("Ім’я користувача:"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password_input)
        layout.addSpacing(10)
        layout.addWidget(login_button)
        layout.addSpacing(15)
        layout.addWidget(hint)

        main_layout.addWidget(frame)
        self.setLayout(main_layout)

    def login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Помилка", "Введіть логін і пароль.")
            return

        try:
            user = check_user(username, password)

            if user:
                username, role, *_ = user

                add_event_log(
                    username,
                    role,
                    "LOGIN",
                    f"Користувач {username} увійшов у систему з роллю {role}",
                    "INFO"
                )

                add_audit_record(
                    username,
                    role,
                    "Authentication",
                    "Успішний вхід у систему",
                    "OK"
                )

                self.scada_window = SCADAWindow(username=username, role=role)
                self.scada_window.show()
                self.close()

            else:
                add_event_log(
                    username,
                    "Unknown",
                    "LOGIN_FAILED",
                    f"Невдала спроба входу для користувача: {username}",
                    "WARNING"
                )

                add_audit_record(
                    username,
                    "Unknown",
                    "Authentication",
                    "Невдала спроба входу",
                    "FAILED"
                )

                self.password_input.clear()

                QMessageBox.critical(
                    self,
                    "Доступ заборонено",
                    "Невірний логін або пароль."
                )


        except Exception as error:

            import traceback

            traceback.print_exc()

            QMessageBox.critical(

                self,

                "Помилка системи",

                f"Не вдалося виконати вхід у систему:\n{error}\n\nДеталі дивись у Run Console."

            )