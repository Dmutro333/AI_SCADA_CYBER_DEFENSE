import os
import joblib


MODEL_PATH = os.path.join("models", "ai_scada_model.pkl")


class MLPredictor:
    def __init__(self):
        self.model = None
        self.feature_names = [
            "temperature",
            "pressure",
            "turbine_rpm",
            "power_output",
            "vibration",
            "water_level",
            "load_percent"
        ]
        self.classes = []
        self.feature_importance = {}

        self.load_model()

    def load_model(self):
        if not os.path.exists(MODEL_PATH):
            self.model = None
            return False

        try:
            loaded_object = joblib.load(MODEL_PATH)

            # Новий формат: пакет із model + metadata
            if isinstance(loaded_object, dict) and "model" in loaded_object:
                self.model = loaded_object["model"]
                self.feature_names = loaded_object.get("feature_names", self.feature_names)
                self.classes = loaded_object.get("classes", [])
                self.feature_importance = loaded_object.get("feature_importance", {})
            else:
                # Старий формат: напряму модель
                self.model = loaded_object

            return True

        except Exception:
            self.model = None
            return False

    def predict(self, sensor_data):
        if self.model is None:
            loaded = self.load_model()

            if not loaded:
                return {
                    "success": False,
                    "prediction": "MODEL_NOT_TRAINED",
                    "confidence": 0,
                    "message": "ML-модель ще не навчена."
                }

        try:
            features = [[
                float(sensor_data.get("temperature", 0)),
                float(sensor_data.get("pressure", 0)),
                float(sensor_data.get("turbine_rpm", 0)),
                float(sensor_data.get("power_output", 0)),
                float(sensor_data.get("vibration", 0)),
                float(sensor_data.get("water_level", 0)),
                float(sensor_data.get("load_percent", 0))
            ]]

            prediction = self.model.predict(features)[0]

            confidence = 0

            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(features)[0]
                confidence = round(max(probabilities) * 100, 2)

            return {
                "success": True,
                "prediction": prediction,
                "confidence": confidence,
                "message": f"ML-модель класифікувала стан як: {prediction}"
            }

        except Exception as error:
            return {
                "success": False,
                "prediction": "PREDICTION_ERROR",
                "confidence": 0,
                "message": f"Помилка ML-прогнозу: {error}"
            }

    def get_model_info(self):
        if self.model is None:
            loaded = self.load_model()

            if not loaded:
                return {
                    "loaded": False,
                    "message": "ML-модель не знайдена."
                }

        return {
            "loaded": True,
            "model_path": MODEL_PATH,
            "classes": self.classes,
            "feature_names": self.feature_names,
            "feature_importance": self.feature_importance
        }