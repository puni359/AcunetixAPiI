# Acunetix Scanner

This Go program interacts with the Acunetix API to perform automated scanning of multiple targets and provides notifications through Telegram.

## Features

- Reads targets from a text file
- Initiates Acunetix scans for each target
- Monitors scan progress
- Sends notifications via Telegram when scans complete
- Exports vulnerabilities to CSV files

## Setup

1. Install Go (1.16 or later)
2. Configure `config.json` with your settings:
   - Acunetix API URL and API key
   - Telegram bot token and chat ID
3. Add target URLs to `targets.txt` (one per line)

## Configuration

Edit `config.json` with your specific settings:
```json
{
    "AcunetixAPI": {
        "BaseURL": "https://your-acunetix-instance/api/v1",
        "APIKey": "your-api-key",
        "TargetURL": "https://your-target-url"
    },
    "Telegram": {
        "BotToken": "your-telegram-bot-token",
        "ChatID": "your-telegram-chat-id"
    },
    "TargetsFile": "targets.txt"
}
```

## Running the Scanner

```bash
go run main.go
```

## Output

The program will:
1. Create a scan for each target in targets.txt
2. Monitor the progress of each scan
3. Send a Telegram notification when each scan completes
4. Generate a CSV file with vulnerabilities for each completed scan

CSV files will be named: `vulnerabilities_[target]_[timestamp].csv`
# AcunetixAPiI
