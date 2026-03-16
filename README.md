# ZomBot Checker

## Telegram bot to monitor your Project Zomboid server

## Basic explanation:
- It connects via RCON to check server status and players.
- It checks mods updates via RCON + SFTP logs.
- It restarts the server and notifies admins/owner.
- It lets the owner invite admins to monitor the server.

## Important:
- Configure `config.ini` before running the bot.
- Commands only work in private chat.
- Heartbeat interval and modcheck interval are configurable in `config.ini`.
- Languages are in `locales/en.json` and `locales/es.json`.

## Run:
- `pip install -r requirements.txt`
- `python zombot.py`

## Libraries used:
- `paramiko`
