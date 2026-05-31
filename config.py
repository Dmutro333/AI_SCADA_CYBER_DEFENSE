import json
import os
from datetime import datetime


CONFIG_DIR = "config_data"
CONFIG_PATH = os.path.join(CONFIG_DIR, "thresholds.json")


DEFAULT_THRESHOLDS = {
    "temperature_warning": 555,
    "temperature_critical": 600,

    "pressure_warning": 15.3,
    "pressure_critical": 17,

    "rpm_warning": 3150,
    "rpm_critical": 3300,

    "vibration_warning": 2.5,
    "vibration_critical": 4.0,

    "water_warning": 55,
    "water_critical": 40,

    "load_warning": 90,
    "load_critical": 105
}


THRESHOLDS = DEFAULT_THRESHOLDS.copy()


def _ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)


def _backup_broken_config():
    if os.path.exists(CONFIG_PATH):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_path = os.path.join(CONFIG_DIR, f"thresholds_broken_{timestamp}.json")

        try:
            os.rename(CONFIG_PATH, backup_path)
        except Exception:
            pass


def validate_thresholds(data):
    if not isinstance(data, dict):
        return DEFAULT_THRESHOLDS.copy()

    validated = DEFAULT_THRESHOLDS.copy()

    for key, default_value in DEFAULT_THRESHOLDS.items():
        value = data.get(key, default_value)

        try:
            value = float(value)
        except (TypeError, ValueError):
            value = default_value

        validated[key] = value

    # Логічна перевірка warning < critical
    pairs = [
        ("temperature_warning", "temperature_critical"),
        ("pressure_warning", "pressure_critical"),
        ("rpm_warning", "rpm_critical"),
        ("vibration_warning", "vibration_critical"),
        ("water_critical", "water_warning"),  # для води critical менше warning
        ("load_warning", "load_critical"),
    ]

    for first, second in pairs:
        if first == "water_critical":
            if validated["water_critical"] >= validated["water_warning"]:
                validated["water_critical"] = DEFAULT_THRESHOLDS["water_critical"]
                validated["water_warning"] = DEFAULT_THRESHOLDS["water_warning"]
        else:
            if validated[first] >= validated[second]:
                validated[first] = DEFAULT_THRESHOLDS[first]
                validated[second] = DEFAULT_THRESHOLDS[second]

    return validated


def load_thresholds():
    global THRESHOLDS

    _ensure_config_dir()

    if not os.path.exists(CONFIG_PATH):
        THRESHOLDS = DEFAULT_THRESHOLDS.copy()
        save_thresholds()
        return THRESHOLDS

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            loaded = json.load(file)

        THRESHOLDS = validate_thresholds(loaded)
        save_thresholds()

    except Exception:
        _backup_broken_config()
        THRESHOLDS = DEFAULT_THRESHOLDS.copy()
        save_thresholds()

    return THRESHOLDS


def save_thresholds():
    _ensure_config_dir()

    with open(CONFIG_PATH, "w", encoding="utf-8") as file:
        json.dump(THRESHOLDS, file, indent=4, ensure_ascii=False)


def update_threshold(key, value):
    global THRESHOLDS

    if key not in DEFAULT_THRESHOLDS:
        return False

    try:
        numeric_value = float(value)
    except (TypeError, ValueError):
        return False

    if numeric_value < 0:
        return False

    THRESHOLDS[key] = numeric_value
    THRESHOLDS = validate_thresholds(THRESHOLDS)

    save_thresholds()
    return True


def reset_thresholds():
    global THRESHOLDS

    THRESHOLDS = DEFAULT_THRESHOLDS.copy()
    save_thresholds()

    return THRESHOLDS


def get_thresholds():
    return THRESHOLDS.copy()


def get_config_path():
    return CONFIG_PATH