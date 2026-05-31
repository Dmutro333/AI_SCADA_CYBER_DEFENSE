import os
import shutil
import sqlite3
from datetime import datetime


class BackupManager:
    def __init__(self):
        self.db_path = "data/scada.db"
        self.backup_dir = "backups"
        os.makedirs(self.backup_dir, exist_ok=True)

    def create_backup(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"scada_backup_{timestamp}.db"
        backup_path = os.path.join(self.backup_dir, backup_name)

        try:
            if not os.path.exists(self.db_path):
                return {
                    "status": "ERROR",
                    "message": "Основну базу даних не знайдено",
                    "path": None
                }

            source = sqlite3.connect(self.db_path)
            destination = sqlite3.connect(backup_path)

            with destination:
                source.backup(destination)

            source.close()
            destination.close()

            size = os.path.getsize(backup_path)

            return {
                "status": "SUCCESS",
                "message": "Backup успішно створено",
                "filename": backup_name,
                "path": backup_path,
                "size_bytes": size,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "message": str(e),
                "path": None
            }

    def restore_backup(self, backup_filename):
        try:
            backup_path = os.path.join(self.backup_dir, backup_filename)

            if not os.path.exists(backup_path):
                return {
                    "status": "ERROR",
                    "message": "Backup-файл не знайдено"
                }

            shutil.copy2(backup_path, self.db_path)

            return {
                "status": "SUCCESS",
                "message": f"Базу даних відновлено з {backup_filename}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "message": str(e)
            }

    def list_backups(self):
        if not os.path.exists(self.backup_dir):
            return []

        backups = []

        for file in os.listdir(self.backup_dir):
            if file.endswith(".db"):
                path = os.path.join(self.backup_dir, file)

                backups.append({
                    "filename": file,
                    "path": path,
                    "size_bytes": os.path.getsize(path),
                    "created": datetime.fromtimestamp(
                        os.path.getctime(path)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                })

        backups.sort(key=lambda x: x["created"], reverse=True)
        return backups

    def delete_backup(self, backup_filename):
        try:
            path = os.path.join(self.backup_dir, backup_filename)

            if not os.path.exists(path):
                return {
                    "status": "ERROR",
                    "message": "Backup-файл не знайдено"
                }

            os.remove(path)

            return {
                "status": "SUCCESS",
                "message": f"Backup {backup_filename} видалено"
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "message": str(e)
            }

    def backup_project_files(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"project_snapshot_{timestamp}"
        archive_path = os.path.join(self.backup_dir, archive_name)

        try:
            os.makedirs(archive_path, exist_ok=True)

            folders = ["data", "reports", "exports", "config_data"]

            for folder in folders:
                if os.path.exists(folder):
                    dst = os.path.join(archive_path, folder)
                    shutil.copytree(folder, dst, dirs_exist_ok=True)

            return {
                "status": "SUCCESS",
                "message": "Snapshot проєкту створено",
                "path": archive_path,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "message": str(e)
            }