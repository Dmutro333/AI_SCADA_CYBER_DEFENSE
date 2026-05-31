import os
from datetime import datetime

ROLES = {
    "Admin": {
        "view_dashboard": True,
        "manage_users": True,
        "launch_attacks": True,
        "shutdown_system": True,
    },

    "Operator": {
        "view_dashboard": True,
        "manage_users": False,
        "launch_attacks": False,
        "shutdown_system": False,
    },

    "Analyst": {
        "view_dashboard": True,
        "manage_users": False,
        "launch_attacks": True,
        "shutdown_system": False,
    }
}

class RBACReportGenerator:
    def __init__(self):
        self.roles = ROLES

    def get_matrix(self):
        rows = []

        for role, permissions in self.roles.items():
            for permission, allowed in permissions.items():
                rows.append({
                    "role": role,
                    "permission": permission,
                    "allowed": allowed
                })

        return rows

    def get_role_permissions(self, role):
        return self.roles.get(role, {})

    def can(self, role, permission):
        return self.roles.get(role, {}).get(permission, False)

    def generate_text_report(self):
        lines = []
        lines.append("=" * 70)
        lines.append("AI SCADA CYBER DEFENSE — RBAC PERMISSION REPORT")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        for role, permissions in self.roles.items():
            lines.append(f"ROLE: {role}")
            lines.append("-" * 40)

            for permission, allowed in permissions.items():
                status = "ALLOW" if allowed else "DENY"
                lines.append(f"{permission}: {status}")

            lines.append("")

        return "\n".join(lines)

    def generate_report(self):
        os.makedirs("reports", exist_ok=True)
        path = os.path.join("reports", f"rbac_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(path, "w", encoding="utf-8") as file:
            file.write(self.generate_text_report())
        return path
