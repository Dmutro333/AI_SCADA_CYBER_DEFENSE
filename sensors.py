import random


class TECSensors:
    def __init__(self):
        self.temperature = 520.0
        self.pressure = 13.5
        self.turbine_rpm = 3000.0
        self.power_output = 250.0
        self.vibration = 1.2
        self.water_level = 75.0
        self.load_percent = 70.0
        self.system_status = "NORMAL"

        self.real_hidden_state = {
            "real_temperature": self.temperature,
            "real_pressure": self.pressure,
            "real_vibration": self.vibration
        }

    def digital_twin_step(self, mode="NORMAL"):
        if mode == "NORMAL":
            self.load_percent += random.uniform(-2, 2)
        elif mode == "WARNING":
            self.load_percent += random.uniform(3, 6)
        elif mode == "CRITICAL":
            self.load_percent += random.uniform(8, 14)
        elif mode == "FAKE_SENSOR_ATTACK":
            return self.simulate_fake_sensor_attack()
        elif mode == "PLC_ATTACK":
            return self.simulate_plc_attack()

        self.load_percent = max(30, min(self.load_percent, 120))

        self.temperature = 430 + self.load_percent * 1.25 + random.uniform(-5, 5)
        self.pressure = 8 + self.load_percent * 0.08 + random.uniform(-0.3, 0.3)
        self.turbine_rpm = 2850 + self.load_percent * 2.2 + random.uniform(-20, 20)
        self.power_output = self.load_percent * 3.4 + random.uniform(-8, 8)
        self.vibration = 0.6 + (self.turbine_rpm - 2800) / 600 + random.uniform(-0.2, 0.2)

        self.water_level += random.uniform(-2.5, 1.5)

        if self.temperature > 570:
            self.water_level -= random.uniform(2, 5)

        self.water_level = max(10, min(self.water_level, 95))

        self.detect_state()

        return self.get_data()

    def detect_state(self):
        critical_conditions = [
            self.temperature > 600,
            self.pressure > 17,
            self.turbine_rpm > 3300,
            self.vibration > 4.0,
            self.water_level < 40,
            self.load_percent > 105
        ]

        warning_conditions = [
            self.temperature > 555,
            self.pressure > 15.3,
            self.turbine_rpm > 3150,
            self.vibration > 2.5,
            self.water_level < 55,
            self.load_percent > 90
        ]

        if any(critical_conditions):
            self.system_status = "CRITICAL"
        elif any(warning_conditions):
            self.system_status = "WARNING"
        else:
            self.system_status = "NORMAL"

    def generate_normal_data(self):
        return self.digital_twin_step("NORMAL")

    def generate_warning_data(self):
        return self.digital_twin_step("WARNING")

    def generate_critical_data(self):
        return self.digital_twin_step("CRITICAL")

    def simulate_fake_sensor_attack(self):
        real_temperature = 610 + random.uniform(-10, 20)
        real_pressure = 18 + random.uniform(-1, 2)
        real_vibration = 4.5 + random.uniform(-0.5, 1.5)

        self.temperature = round(random.uniform(420, 460), 2)
        self.pressure = round(random.uniform(8.5, 10.5), 2)
        self.turbine_rpm = round(random.uniform(2980, 3020), 2)
        self.power_output = round(random.uniform(240, 260), 2)
        self.vibration = round(random.uniform(0.5, 1.0), 2)
        self.water_level = round(random.uniform(85, 95), 2)
        self.load_percent = round(random.uniform(65, 75), 2)
        self.system_status = "FAKE_SENSOR_ATTACK"

        self.real_hidden_state = {
            "real_temperature": round(real_temperature, 2),
            "real_pressure": round(real_pressure, 2),
            "real_vibration": round(real_vibration, 2)
        }

        return self.get_data()

    def simulate_plc_attack(self):
        self.load_percent = round(random.uniform(110, 130), 2)
        self.temperature = round(random.uniform(620, 700), 2)
        self.pressure = round(random.uniform(18, 22), 2)
        self.turbine_rpm = round(random.uniform(3400, 3900), 2)
        self.power_output = round(random.uniform(340, 420), 2)
        self.vibration = round(random.uniform(4.5, 7.5), 2)
        self.water_level = round(random.uniform(20, 38), 2)
        self.system_status = "PLC_ATTACK"

        return self.get_data()

    def simulate_cooling_failure(self):
        self.temperature = round(random.uniform(590, 680), 2)
        self.pressure = round(random.uniform(16, 20), 2)
        self.turbine_rpm = round(random.uniform(3100, 3500), 2)
        self.power_output = round(random.uniform(280, 360), 2)
        self.vibration = round(random.uniform(3.0, 6.0), 2)
        self.water_level = round(random.uniform(15, 35), 2)
        self.load_percent = round(random.uniform(90, 115), 2)
        self.system_status = "COOLING_FAILURE"

        return self.get_data()

    def simulate_overload(self):
        self.load_percent = round(random.uniform(115, 140), 2)
        self.temperature = round(430 + self.load_percent * 1.35 + random.uniform(5, 20), 2)
        self.pressure = round(8 + self.load_percent * 0.09 + random.uniform(0.5, 1.5), 2)
        self.turbine_rpm = round(2850 + self.load_percent * 3.0 + random.uniform(20, 80), 2)
        self.power_output = round(self.load_percent * 3.6 + random.uniform(10, 30), 2)
        self.vibration = round(random.uniform(4.0, 8.0), 2)
        self.water_level = round(random.uniform(25, 45), 2)
        self.system_status = "OVERLOAD"

        return self.get_data()

    def apply_safe_mode(self):
        self.load_percent = round(random.uniform(45, 60), 2)
        self.temperature = round(random.uniform(470, 510), 2)
        self.pressure = round(random.uniform(10.5, 12.5), 2)
        self.turbine_rpm = round(random.uniform(2850, 2950), 2)
        self.power_output = round(random.uniform(150, 210), 2)
        self.vibration = round(random.uniform(0.7, 1.4), 2)
        self.water_level = round(random.uniform(65, 80), 2)
        self.system_status = "SAFE_MODE"

        return self.get_data()

    def emergency_stop(self):
        self.load_percent = 0.0
        self.temperature = round(random.uniform(350, 420), 2)
        self.pressure = round(random.uniform(4.0, 7.0), 2)
        self.turbine_rpm = round(random.uniform(0, 300), 2)
        self.power_output = 0.0
        self.vibration = round(random.uniform(0.1, 0.5), 2)
        self.water_level = round(random.uniform(70, 90), 2)
        self.system_status = "EMERGENCY_STOP"

        return self.get_data()

    def reset_plant(self):
        self.temperature = 500.0
        self.pressure = 12.8
        self.turbine_rpm = 2950.0
        self.power_output = 220.0
        self.vibration = 1.0
        self.water_level = 75.0
        self.load_percent = 60.0
        self.system_status = "NORMAL"

        self.real_hidden_state = {
            "real_temperature": self.temperature,
            "real_pressure": self.pressure,
            "real_vibration": self.vibration
        }

        return self.get_data()

    def get_data(self):
        return {
            "temperature": round(self.temperature, 2),
            "pressure": round(self.pressure, 2),
            "turbine_rpm": round(self.turbine_rpm, 2),
            "power_output": round(self.power_output, 2),
            "vibration": round(self.vibration, 2),
            "water_level": round(self.water_level, 2),
            "load_percent": round(self.load_percent, 2),
            "system_status": self.system_status
        }