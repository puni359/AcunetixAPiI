import json
import csv
import requests
import asyncio
import logging
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from telegram.ext import ApplicationBuilder

class AcunetixScanner:
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.headers = {
            "X-Auth": self.config["AcunetixAPI"]["APIKey"],
            "Content-Type": "application/json"
        }
        self.base_url = self.config["AcunetixAPI"]["BaseURL"]
        self.telegram_bot = ApplicationBuilder().token(self.config["Telegram"]["BotToken"]).build()

    @staticmethod
    def _load_config(config_path: str) -> dict:
        with open(config_path, 'r') as f:
            return json.load(f)

    def _read_targets(self) -> List[str]:
        with open(self.config["TargetsFile"], 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def create_target(self, address: str) -> str:
        """Создание нового таргета в Acunetix"""
        data = {
            "address": address,
            "description": f"Сканирование цели: {address}"
        }
        response = requests.post(
            f"{self.base_url}/targets",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()["target_id"]

    def start_scan(self, target_id: str) -> str:
        """Запуск сканирования для таргета"""
        data = {"target_id": target_id}
        response = requests.post(
            f"{self.base_url}/scans",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()["scan_id"]

    def get_scan_status(self, scan_id: str) -> Dict:
        """Получение статуса сканирования"""
        response = requests.get(
            f"{self.base_url}/scans/{scan_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    def get_vulnerabilities(self, scan_id: str) -> List[Dict]:
        """Получение списка уязвимостей"""
        response = requests.get(
            f"{self.base_url}/scans/{scan_id}/vulnerabilities",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()["vulnerabilities"]

    async def send_telegram_notification(self, message: str):
        """Отправка уведомления в Telegram"""
        async with self.telegram_bot:
            await self.telegram_bot.bot.send_message(
                chat_id=self.config["Telegram"]["ChatID"],
                text=message
            )

    def export_vulnerabilities(self, vulnerabilities: List[Dict], target: str):
        """Экспорт уязвимостей в CSV файл"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerabilities_{target}_{timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["ID уязвимости", "Уровень опасности", "Название", "Описание"])
            
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get("vuln_id", ""),
                    vuln.get("severity", ""),
                    vuln.get("vt_name", ""),
                    vuln.get("description", "")
                ])

    async def monitor_scan(self, scan_id: str, target: str):
        """Мониторинг процесса сканирования"""
        while True:
            try:
                status = self.get_scan_status(scan_id)
                if status["status"] == "completed":
                    vulnerabilities = self.get_vulnerabilities(scan_id)
                    self.export_vulnerabilities(vulnerabilities, target)
                    
                    severity = status.get("severity", {})
                    message = (
                        f"Сканирование завершено для: {target}\n"
                        f"Найденные уязвимости:\n"
                        f"Критические: {severity.get('high', 0)}\n"
                        f"Средние: {severity.get('medium', 0)}\n"
                        f"Низкие: {severity.get('low', 0)}\n"
                        f"Информационные: {severity.get('info', 0)}"
                    )
                    await self.send_telegram_notification(message)
                    break
                
                await asyncio.sleep(30)
            except Exception as e:
                logging.error(f"Ошибка при мониторинге {scan_id}: {e}")
                await asyncio.sleep(30)

    async def run(self):
        """Основной метод запуска сканирования"""
        targets = self._read_targets()
        tasks = []

        for target in targets:
            try:
                target_id = self.create_target(target)
                scan_id = self.start_scan(target_id)
                tasks.append(self.monitor_scan(scan_id, target))
            except Exception as e:
                logging.error(f"Ошибка при обработке цели {target}: {e}")

        await asyncio.gather(*tasks)

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    scanner = AcunetixScanner()
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
