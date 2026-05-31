import sys
import traceback

from PyQt5.QtWidgets import QApplication, QMessageBox

from app_logger import get_logger, install_global_exception_hook, write_startup_marker, log_exception
from startup_checks import ensure_runtime_environment
from database import init_database
from login_window import LoginWindow
from config import load_thresholds


def main():
    install_global_exception_hook()
    write_startup_marker()
    logger = get_logger("system")

    try:
        ensure_runtime_environment()
        init_database()
        load_thresholds()
    except Exception as exc:
        log_exception("startup", exc)
        # Continue into GUI where possible, because demo should not fail silently.

    app = QApplication(sys.argv)

    try:
        login_window = LoginWindow()
        login_window.show()
        logger.info("Login window shown successfully")
        sys.exit(app.exec_())
    except Exception as exc:
        log_exception("main_gui", exc)
        QMessageBox.critical(
            None,
            "AI SCADA startup error",
            f"Програму не вдалося запустити.\n\n{type(exc).__name__}: {exc}\n\nДеталі записано у logs/errors.log",
        )
        print(traceback.format_exc())
        return 1


if __name__ == "__main__":
    main()
