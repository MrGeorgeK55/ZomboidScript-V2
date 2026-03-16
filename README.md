# ZomBot Checker

*A lightweight Telegram bot that monitors and maintains your Project Zomboid server.*

---

## Telegram bot to monitor your Project Zomboid server

**ZomboidScript-V2** is a lightweight automation companion for running a **Project Zomboid server**, designed to make server maintenance easier and more predictable.

Instead of constantly checking logs or worrying about mod updates breaking the server, this tool acts as a small watchdog that keeps an eye on your server and communicates with you through Telegram.

The bot connects to the server using **RCON**, performs regular health checks, and reads server logs to detect when **Workshop mods require updates**. If an update is detected, it can warn players in-game, give them time to finish what they are doing, and safely restart the server so everything stays compatible and stable.

Through Telegram, administrators can monitor the server, see who is online, and run maintenance actions without needing direct access to the server machine.

---

# Usage

1. Generate a bot token with **@BotFather**
2. Edit `config.ini` with your Project Zomboid server information  
   *(Supports rented servers such as Bisect Hosting)*
3. Start the bot and open it in Telegram
4. The first person who runs `/claimowner` becomes the **owner**
5. Optionally invite admins using `/addadmin`
6. The bot will monitor the server and notify admins when something requires attention

---

# Commands (Private Chat Only)

- `/start` — Start the bot (anyone)
- `/help` — Show help (anyone)
- `/whoami` — Show your Telegram info + role (anyone)
- `/redeem CODE` — Redeem an admin invite code (anyone)
- `/claimowner` — Claim owner role (first user only)
- `/addadmin` — Create an invite code (owner)
- `/listadmins` — List owner/admins and pending codes (owner)
- `/status` — Server status summary (admin/owner)
- `/players` — List online players (admin/owner)
- `/lastseen` — Last successful ping time (admin/owner)
- `/servermsg CUSTOMTEXT` — Send in‑game server message (admin/owner)
- `/checkmods` — Manual mod update check (owner)
- `/hardreset` — Save + quit with confirmation (owner)
- `/forcerestart` — Save + quit immediately (owner)
- `/cancel` — Cancel pending confirmation (owner)

---

# Features

### Telegram-based monitoring
Monitor your Project Zomboid server directly from a private Telegram chat.

### Server status and player visibility
Uses **RCON** to check if the server is responding and to list connected players.

### Automatic mod update detection
Runs the built-in mod update check through **RCON** and analyzes server logs through **SFTP** to detect when mods require updates.

### Safe restart workflow
When updates are detected, the bot can warn players and coordinate a safe restart instead of leaving the server running outdated mods.

### Owner and admin roles
Supports an **owner/admin permission model**, allowing trusted admins to monitor the server without exposing full credentials.

### Invite-based admin access
Admins are added through temporary invite codes, keeping the bot private even if the bot account is publicly visible.

### Configurable monitoring intervals
Heartbeat and mod-check intervals can be adjusted in `config.ini`.

### Localization support
Includes **English and Spanish language files** in the `locales/` folder.

### Lightweight and self-hosted
Runs as a simple Python script with minimal dependencies.

### Compatible with hosted servers
Designed to work even on rented servers where only **RCON and SFTP access** are available.

---

# How it works (Simple Overview)

- Connects via **RCON** to check server status and players  
- Checks for **mod updates** using RCON + server logs  
- Sends **Telegram notifications** to admins  
- Can **restart the server safely** when updates are required  
- Allows the owner to **invite admins** to monitor the server

---

# Important Notes

- Configure `config.ini` before running the bot
- Commands only work in **private chat**
- Monitoring intervals are configurable in `config.ini`
- Language files are located in:
  - `locales/en.json`
  - `locales/es.json`

---

# Run

Install dependencies:

```bash
pip install -r requirements.txt
