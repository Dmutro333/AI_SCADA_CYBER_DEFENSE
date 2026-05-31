import os
import joblib

from database import get_connection

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "ai_scada_model.pkl")


class MLModelTrainer:
    def __init__(self):
        os.makedirs(MODEL_DIR, exist_ok=True)

        self.feature_names = [
            "temperature",
            "pressure",
            "turbine_rpm",
            "power_output",
            "vibration",
            "water_level",
            "load_percent"
        ]

    def train_from_database(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT temperature, pressure, turbine_rpm, power_output,
               vibration, water_level, load_percent, system_status
        FROM sensor_data
        WHERE temperature IS NOT NULL
          AND pressure IS NOT NULL
          AND turbine_rpm IS NOT NULL
          AND power_output IS NOT NULL
          AND vibration IS NOT NULL
          AND water_level IS NOT NULL
          AND load_percent IS NOT NULL
          AND system_status IS NOT NULL
        """)

        rows = cursor.fetchall()
        conn.close()

        if len(rows) < 20:
            return {
                "success": False,
                "message": "Недостатньо даних для навчання. Потрібно мінімум 20 записів."
            }

        X = []
        y = []

        for row in rows:
            try:
                features = [float(value) for value in row[:7]]
                label = str(row[7])
                X.append(features)
                y.append(label)
            except Exception:
                continue

        if len(X) < 20:
            return {
                "success": False,
                "message": "Після очищення даних залишилось менше 20 коректних записів."
            }

        unique_classes = sorted(set(y))

        if len(unique_classes) < 2:
            return {
                "success": False,
                "message": (
                    "Недостатньо різних класів для навчання. "
                    "Потрібні хоча б 2 стани, наприклад NORMAL і WARNING/CRITICAL."
                )
            }

        class_counts = {label: y.count(label) for label in unique_classes}

        can_stratify = all(count >= 2 for count in class_counts.values())

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y if can_stratify else None
        )

        model = RandomForestClassifier(
            n_estimators=150,
            max_depth=None,
            random_state=42,
            class_weight="balanced"
        )

        model.fit(X_train, y_train)

        predictions = model.predict(X_test)

        accuracy = accuracy_score(y_test, predictions)
        report = classification_report(y_test, predictions, zero_division=0)
        matrix = confusion_matrix(y_test, predictions, labels=unique_classes).tolist()

        feature_importance = {
            name: round(float(value), 4)
            for name, value in zip(self.feature_names, model.feature_importances_)
        }

        model_package = {
            "model": model,
            "feature_names": self.feature_names,
            "classes": unique_classes,
            "feature_importance": feature_importance
        }

        joblib.dump(model_package, MODEL_PATH)

        return {
            "success": True,
            "records": len(X),
            "train_records": len(X_train),
            "test_records": len(X_test),
            "classes": unique_classes,
            "class_counts": class_counts,
            "accuracy": round(accuracy * 100, 2),
            "model_path": MODEL_PATH,
            "classification_report": report,
            "confusion_matrix": matrix,
            "feature_importance": feature_importance
        }