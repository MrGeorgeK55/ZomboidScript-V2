#!/usr/bin/env python3

import json
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from configparser import ConfigParser
from datetime import datetime, timedelta, timezone

import paramiko


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
RUNTIME_FILE = os.path.join(BASE_DIR, "runtime_state.json")
SECURITY_FILE = os.path.join(BASE_DIR, "security_state.json")
LOCALES_DIR = os.path.join(BASE_DIR, "locales")
DEFAULT_LANGUAGE = "en"

DEFAULT_LOCALE: dict = {}
ACTIVE_LOCALE: dict = {}
ACTIVE_LANGUAGE = DEFAULT_LANGUAGE


DEFAULT_USERS = {
    "owner_id": None,
    "admins": [],
    "pending_codes": [],
    "user_profiles": {}
}

DEFAULT_RUNTIME = {
    "server_status": "unknown",
    "last_successful_ping": None,
    "last_status_change": None,
    "consecutive_failures": 0,
    "last_mod_check": None,
    "last_mod_result": "unknown",
    "last_restart_time": None,
    "last_restart_reason": None,
    "last_known_player_count": None,
    "last_known_players": [],
    "post_restart_watch_active": False,
    "post_restart_watch_id": None,
    "post_restart_started_at": None,
    "post_restart_last_check": None,
    "post_restart_offline_alerted": False
}

DEFAULT_SECURITY = {
    "failed_invite_attempts": {},
    "temporary_blocks": {},
    "rate_limits": {},
    "pending_confirmations": {},
    "last_offline_alert_at": None,
    "last_online_alert_at": None
}


SERVERDATA_RESPONSE_VALUE = 0
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}")


def fatal(message: str, exit_code: int = 1) -> None:
    log(f"FATAL: {message}")
    sys.exit(exit_code)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_utc_iso() -> str:
    return now_utc().replace(microsecond=0).isoformat()


def parse_iso_datetime(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def humanize_time_ago(iso_value: str | None) -> str:
    if not iso_value:
        return t("time_never")

    dt = parse_iso_datetime(iso_value)
    if dt is None:
        return t("time_unknown")

    delta = now_utc() - dt
    seconds = int(delta.total_seconds())

    if seconds < 0:
        return t("time_future")
    if seconds < 10:
        return t("time_seconds_few")
    if seconds < 60:
        return t("time_seconds", seconds=seconds)
    if seconds < 3600:
        return t("time_minutes", minutes=seconds // 60)
    if seconds < 86400:
        return t("time_hours", hours=seconds // 3600)
    return t("time_days", days=seconds // 86400)


def format_last_seen_line(iso_value: str | None) -> str:
    if not iso_value:
        return t("time_never")
    return f"{humanize_time_ago(iso_value)} ({iso_value})"


def load_locale_file(language_code: str) -> dict:
    path = os.path.join(LOCALES_DIR, f"{language_code}.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Locale not found: {path}")
    return ensure_dict(load_json_file(path), f"locale {language_code}")


def init_locales(language_code: str | None) -> None:
    global DEFAULT_LOCALE, ACTIVE_LOCALE, ACTIVE_LANGUAGE
    if not DEFAULT_LOCALE:
        try:
            DEFAULT_LOCALE = load_locale_file(DEFAULT_LANGUAGE)
        except Exception as e:
            log(f"Locale warning: default locale load failed: {e}")
            DEFAULT_LOCALE = {}

    selected = (language_code or DEFAULT_LANGUAGE).strip().lower()
    try:
        ACTIVE_LOCALE = load_locale_file(selected)
        ACTIVE_LANGUAGE = selected
    except Exception as e:
        log(f"Locale warning: failed to load '{selected}', using default. {e}")
        ACTIVE_LOCALE = DEFAULT_LOCALE
        ACTIVE_LANGUAGE = DEFAULT_LANGUAGE


def t(key: str, **kwargs) -> str:
    text = ACTIVE_LOCALE.get(key) or DEFAULT_LOCALE.get(key) or key
    try:
        return text.format(**kwargs)
    except Exception:
        return text


def send_text(bot_token: str, chat_id: int, key: str, **kwargs) -> None:
    telegram_send_message(bot_token, chat_id, t(key, **kwargs))


def load_config(path: str) -> ConfigParser:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    cfg = ConfigParser()
    read_files = cfg.read(path, encoding="utf-8")

    if not read_files:
        raise RuntimeError(f"Could not read config file: {path}")

    return cfg


def require_section(cfg: ConfigParser, section: str) -> None:
    if section not in cfg:
        raise KeyError(f"Missing config section: [{section}]")


def require_option(cfg: ConfigParser, section: str, option: str) -> None:
    if option not in cfg[section]:
        raise KeyError(f"Missing config key: [{section}] {option}")


def validate_config(cfg: ConfigParser) -> None:
    required = {
        "server": ["name", "language"],
        "bot": ["token"],
        "rcon": ["host", "port", "password"],
        "sftp": ["host", "port", "user", "password", "log_path"],
        "heartbeat": ["enabled", "interval_minutes", "offline_fail_threshold"],
        "modcheck": [
            "enabled",
            "interval_minutes",
            "after_check_wait_seconds",
            "save_wait_seconds",
            "log_search_text",
            "countdown_enabled"
        ],
        "security": [
            "unknown_user_rate_limit_per_minute",
            "known_user_rate_limit_per_minute",
            "failed_code_limit",
            "failed_code_window_minutes",
            "temporary_block_minutes",
            "invite_code_expire_minutes",
            "invite_code_length"
        ],
        "restart_watch": [
            "enabled",
            "check_interval_minutes",
            "max_wait_minutes"
        ]
    }

    for section, options in required.items():
        require_section(cfg, section)
        for option in options:
            require_option(cfg, section, option)


def load_json_file(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"JSON file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e


def save_json_file(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def ensure_dict(value, name: str) -> dict:
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be a JSON object")
    return value


def merge_defaults(data: dict, defaults: dict) -> tuple[dict, bool]:
    changed = False
    for key, default_value in defaults.items():
        if key not in data:
            data[key] = default_value
            changed = True
    return data, changed


def load_or_repair_json(path: str, defaults: dict, name: str) -> dict:
    data = load_json_file(path)
    data = ensure_dict(data, name)
    data, changed = merge_defaults(data, defaults)

    if changed:
        log(f"{name}: missing keys detected, repairing file.")
        save_json_file(path, data)

    return data


def load_users() -> dict:
    return load_or_repair_json(USERS_FILE, DEFAULT_USERS, "users.json")


def save_users(users: dict) -> None:
    save_json_file(USERS_FILE, users)


def load_runtime() -> dict:
    return load_or_repair_json(RUNTIME_FILE, DEFAULT_RUNTIME, "runtime_state.json")


def save_runtime(runtime: dict) -> None:
    save_json_file(RUNTIME_FILE, runtime)


def load_security() -> dict:
    return load_or_repair_json(SECURITY_FILE, DEFAULT_SECURITY, "security_state.json")


def save_security(security: dict) -> None:
    save_json_file(SECURITY_FILE, security)


def file_mode_string(path: str) -> str:
    try:
        mode = os.stat(path).st_mode & 0o777
        return oct(mode)
    except Exception:
        return "unknown"


def print_startup_summary(cfg: ConfigParser, users: dict, runtime: dict, security: dict) -> None:
    print()
    print("========== Zombot Startup Summary ==========")
    print(f"Base directory            : {BASE_DIR}")
    print(f"Server name               : {cfg['server']['name']}")
    print(f"Language                  : {cfg['server']['language']}")
    print(f"Bot token                 : {'set' if cfg['bot']['token'].strip() else 'empty'}")
    print()
    print("---- Monitoring ----")
    print(f"Heartbeat enabled         : {cfg.getboolean('heartbeat', 'enabled', fallback=True)}")
    print(f"Heartbeat interval        : {cfg.getint('heartbeat', 'interval_minutes', fallback=1)} min")
    print(f"Offline fail threshold    : {cfg.getint('heartbeat', 'offline_fail_threshold', fallback=3)}")
    print(f"Modcheck enabled          : {cfg.getboolean('modcheck', 'enabled', fallback=True)}")
    print(f"Modcheck interval         : {cfg.getint('modcheck', 'interval_minutes', fallback=30)} min")
    print()
    print("---- Users ----")
    print(f"Owner configured          : {'yes' if users.get('owner_id') is not None else 'no'}")
    print(f"Owner ID                  : {users.get('owner_id')}")
    print(f"Admin count               : {len(users.get('admins', []))}")
    print(f"Pending invite codes      : {len(users.get('pending_codes', []))}")
    print()
    print("---- Runtime ----")
    print(f"Server status             : {runtime.get('server_status')}")
    print(f"Last successful ping      : {runtime.get('last_successful_ping')}")
    print(f"Consecutive failures      : {runtime.get('consecutive_failures')}")
    print(f"Last mod result           : {runtime.get('last_mod_result')}")
    print()
    print("---- Security ----")
    print(f"Temporary blocks          : {len(security.get('temporary_blocks', {}))}")
    print(f"Failed invite entries     : {len(security.get('failed_invite_attempts', {}))}")
    print(f"Rate limit entries        : {len(security.get('rate_limits', {}))}")
    print(f"Pending confirmations     : {len(security.get('pending_confirmations', {}))}")
    print()
    print("---- File permissions ----")
    print(f"config.ini                : {file_mode_string(CONFIG_FILE)}")
    print(f"users.json                : {file_mode_string(USERS_FILE)}")
    print(f"runtime_state.json        : {file_mode_string(RUNTIME_FILE)}")
    print(f"security_state.json       : {file_mode_string(SECURITY_FILE)}")
    print("===========================================")
    print()


def telegram_api_url(bot_token: str, method: str) -> str:
    return f"https://api.telegram.org/bot{bot_token}/{method}"


def telegram_request(bot_token: str, method: str, payload: dict | None = None, timeout: int = 30):
    url = telegram_api_url(bot_token, method)
    payload = payload or {}
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")

    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(body)

    if not parsed.get("ok"):
        raise RuntimeError(f"Telegram API error on {method}: {parsed}")

    return parsed


def telegram_send_message(bot_token: str, chat_id: int, text: str, timeout: int = 30) -> None:
    telegram_request(
        bot_token,
        "sendMessage",
        {
            "chat_id": str(chat_id),
            "text": text
        },
        timeout=timeout
    )


def telegram_get_updates(bot_token: str, offset: int | None = None, timeout: int = 30):
    payload = {"timeout": str(timeout)}
    if offset is not None:
        payload["offset"] = str(offset)
    result = telegram_request(bot_token, "getUpdates", payload, timeout=timeout + 5)
    return result.get("result", [])


def telegram_get_me(bot_token: str) -> dict:
    result = telegram_request(bot_token, "getMe", {}, timeout=20)
    return result["result"]


def telegram_set_my_commands(
    bot_token: str,
    commands: list[dict],
    scope: dict | None = None,
    language_code: str | None = None
) -> None:
    payload: dict = {"commands": json.dumps(commands, ensure_ascii=False)}
    if scope is not None:
        payload["scope"] = json.dumps(scope, ensure_ascii=False)
    if language_code is not None:
        payload["language_code"] = language_code
    telegram_request(bot_token, "setMyCommands", payload, timeout=20)


def build_command_menu() -> list[dict]:
    return [
        {"command": "start", "description": t("cmd_start")},
        {"command": "help", "description": t("cmd_help")},
        {"command": "whoami", "description": t("cmd_whoami")},
        {"command": "redeem", "description": t("cmd_redeem")},
        {"command": "claimowner", "description": t("cmd_claimowner")},
        {"command": "addadmin", "description": t("cmd_addadmin")},
        {"command": "listadmins", "description": t("cmd_listadmins")},
        {"command": "deleteadmin", "description": t("cmd_deleteadmin")},
        {"command": "status", "description": t("cmd_status")},
        {"command": "players", "description": t("cmd_players")},
        {"command": "lastseen", "description": t("cmd_lastseen")},
        {"command": "servermsg", "description": t("cmd_servermsg")},
        {"command": "checkmods", "description": t("cmd_checkmods")},
        {"command": "hardreset", "description": t("cmd_hardreset")},
        {"command": "forcerestart", "description": t("cmd_forcerestart")},
        {"command": "cancel", "description": t("cmd_cancel")}
    ]


def extract_message_info(update: dict):
    message = update.get("message")
    if not message:
        return None

    chat = message.get("chat", {})
    from_user = message.get("from", {})

    text = message.get("text", "")
    chat_id = chat.get("id")
    chat_type = chat.get("type", "")
    user_id = from_user.get("id")
    username = from_user.get("username")
    first_name = from_user.get("first_name", "")
    last_name = from_user.get("last_name", "")

    if chat_id is None or user_id is None:
        return None

    return {
        "chat_id": chat_id,
        "chat_type": chat_type,
        "user_id": user_id,
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "text": text.strip()
    }


def is_owner(user_id: int, users: dict) -> bool:
    return users.get("owner_id") == user_id


def is_admin(user_id: int, users: dict) -> bool:
    return user_id in users.get("admins", [])


def is_authorized(user_id: int, users: dict) -> bool:
    return is_owner(user_id, users) or is_admin(user_id, users)


def get_role(user_id: int, users: dict) -> str:
    if is_owner(user_id, users):
        return "owner"
    if is_admin(user_id, users):
        return "admin"
    return "unknown"


def update_user_profile(users: dict, msg: dict) -> bool:
    profiles = users.setdefault("user_profiles", {})
    user_id = msg["user_id"]
    key = str(user_id)

    entry = profiles.get(key, {})
    username = msg.get("username")
    first_name = msg.get("first_name", "")
    last_name = msg.get("last_name", "")

    new_entry = {
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "updated_at": now_utc_iso()
    }

    if entry != new_entry:
        profiles[key] = new_entry
        return True
    return False


def format_user_label(user_id: int, users: dict) -> str:
    profiles = users.get("user_profiles", {})
    entry = profiles.get(str(user_id), {})

    username = entry.get("username")
    first_name = entry.get("first_name", "")
    last_name = entry.get("last_name", "")
    full_name = f"{first_name} {last_name}".strip()

    if username:
        return f"@{username} ({user_id})"
    if full_name:
        return f"{full_name} ({user_id})"
    return str(user_id)


def command_name(text: str) -> str:
    if not text.startswith("/"):
        return ""

    cmd = text.split()[0].strip()
    if "@" in cmd:
        cmd = cmd.split("@", 1)[0]
    return cmd.lower()


def get_all_recipient_ids(users: dict) -> list[int]:
    recipients = []
    owner_id = users.get("owner_id")
    if owner_id is not None:
        recipients.append(owner_id)
    for admin_id in users.get("admins", []):
        if admin_id not in recipients:
            recipients.append(admin_id)
    return recipients


def notify_all_users(bot_token: str, users: dict, text: str) -> None:
    for recipient_id in get_all_recipient_ids(users):
        try:
            telegram_send_message(bot_token, recipient_id, text)
        except Exception as e:
            log(f"Notify warning recipient_id={recipient_id}: {e}")


def cleanup_pending_codes(users: dict) -> bool:
    changed = False
    now = now_utc()
    cleaned = []

    for entry in users.get("pending_codes", []):
        if entry.get("used") is True:
            changed = True
            continue

        expires_at = parse_iso_datetime(entry.get("expires_at"))
        if expires_at is not None and expires_at < now:
            changed = True
            continue

        cleaned.append(entry)

    users["pending_codes"] = cleaned
    return changed


def generate_invite_code(length: int) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    if length < 4:
        raise ValueError("invite_code_length must be at least 4")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_admin_invite(users: dict, expire_minutes: int, code_length: int) -> dict:
    existing_codes = {entry.get("code") for entry in users.get("pending_codes", [])}

    code = generate_invite_code(code_length)
    while code in existing_codes:
        code = generate_invite_code(code_length)

    created_at = now_utc().replace(microsecond=0)
    expires_at = created_at + timedelta(minutes=expire_minutes)

    entry = {
        "code": code,
        "role": "admin",
        "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "used": False,
        "used_by": None
    }

    users.setdefault("pending_codes", []).append(entry)
    return entry


def find_pending_code(users: dict, code: str):
    target = code.strip().upper()
    for entry in users.get("pending_codes", []):
        if entry.get("code", "").upper() == target:
            return entry
    return None


def is_code_expired(entry: dict) -> bool:
    expires_at = parse_iso_datetime(entry.get("expires_at"))
    if expires_at is None:
        return True
    return expires_at < now_utc()


def cleanup_pending_confirmations(security: dict) -> bool:
    changed = False
    now = now_utc()
    cleaned = {}

    for user_id, entry in security.get("pending_confirmations", {}).items():
        expires_at = parse_iso_datetime(entry.get("expires_at"))
        if expires_at is None or expires_at < now:
            changed = True
            continue
        cleaned[user_id] = entry

    security["pending_confirmations"] = cleaned
    return changed


def set_pending_confirmation(security: dict, user_id: int, action: str, minutes: int = 2) -> None:
    expires_at = now_utc().replace(microsecond=0) + timedelta(minutes=minutes)
    security.setdefault("pending_confirmations", {})[str(user_id)] = {
        "action": action,
        "created_at": now_utc_iso(),
        "expires_at": expires_at.isoformat()
    }


def get_pending_confirmation(security: dict, user_id: int):
    cleanup_pending_confirmations(security)
    return security.get("pending_confirmations", {}).get(str(user_id))


def clear_pending_confirmation(security: dict, user_id: int) -> bool:
    key = str(user_id)
    if key in security.get("pending_confirmations", {}):
        del security["pending_confirmations"][key]
        return True
    return False


def cleanup_temporary_blocks(security: dict) -> bool:
    changed = False
    now = now_utc()
    cleaned = {}

    for user_id, entry in security.get("temporary_blocks", {}).items():
        until = parse_iso_datetime(entry.get("until"))
        if until is None or until < now:
            changed = True
            continue
        cleaned[user_id] = entry

    security["temporary_blocks"] = cleaned
    return changed


def is_temporarily_blocked(user_id: int, security: dict) -> tuple[bool, str | None]:
    cleanup_temporary_blocks(security)
    entry = security.get("temporary_blocks", {}).get(str(user_id))
    if not entry:
        return False, None
    return True, entry.get("until")


def apply_temporary_block(user_id: int, security: dict, minutes: int, reason: str) -> None:
    until = now_utc().replace(microsecond=0) + timedelta(minutes=minutes)
    security.setdefault("temporary_blocks", {})[str(user_id)] = {
        "until": until.isoformat(),
        "reason": reason
    }


def register_failed_invite_attempt(user_id: int, security: dict, cfg: ConfigParser) -> bool:
    now = now_utc()
    window_minutes = cfg.getint("security", "failed_code_window_minutes", fallback=15)
    limit = cfg.getint("security", "failed_code_limit", fallback=3)
    block_minutes = cfg.getint("security", "temporary_block_minutes", fallback=15)

    key = str(user_id)
    attempts = security.setdefault("failed_invite_attempts", {})
    entry = attempts.get(key)

    if entry is None:
        attempts[key] = {
            "count": 1,
            "first_attempt_at": now.replace(microsecond=0).isoformat()
        }
        return False

    first_attempt_at = parse_iso_datetime(entry.get("first_attempt_at"))
    if first_attempt_at is None or first_attempt_at < now - timedelta(minutes=window_minutes):
        attempts[key] = {
            "count": 1,
            "first_attempt_at": now.replace(microsecond=0).isoformat()
        }
        return False

    entry["count"] = int(entry.get("count", 0)) + 1

    if entry["count"] >= limit:
        apply_temporary_block(user_id, security, block_minutes, "too_many_failed_invites")
        attempts.pop(key, None)
        return True

    return False


def clear_failed_invite_attempts(user_id: int, security: dict) -> None:
    security.setdefault("failed_invite_attempts", {}).pop(str(user_id), None)


def check_rate_limit(user_id: int, users: dict, security: dict, cfg: ConfigParser) -> tuple[bool, str | None]:
    now = now_utc()
    known = is_authorized(user_id, users)

    limit = cfg.getint(
        "security",
        "known_user_rate_limit_per_minute" if known else "unknown_user_rate_limit_per_minute",
        fallback=20 if known else 8
    )

    key = str(user_id)
    rate_limits = security.setdefault("rate_limits", {})
    entry = rate_limits.get(key)

    if entry is None:
        rate_limits[key] = {
            "window_start": now.replace(microsecond=0).isoformat(),
            "count": 1
        }
        return True, None

    window_start = parse_iso_datetime(entry.get("window_start"))
    if window_start is None or window_start < now - timedelta(minutes=1):
        rate_limits[key] = {
            "window_start": now.replace(microsecond=0).isoformat(),
            "count": 1
        }
        return True, None

    entry["count"] = int(entry.get("count", 0)) + 1
    if entry["count"] > limit:
        return False, t("rate_limit_exceeded")

    return True, None


def parse_player_list(text: str) -> tuple[int, list[str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return 0, []

    count = 0
    players = []

    match = re.search(r"Players connected \((\d+)\):", lines[0])
    if match:
        count = int(match.group(1))

    for line in lines[1:]:
        if line.startswith("-"):
            players.append(line[1:].strip())

    return count, players


def parse_modcheck_result(log_text: str, search_text: str) -> bool:
    return search_text in log_text


def tail_lines(text: str, count: int = 20) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-count:])


class RCONClient:
    def __init__(self, host: str, port: int, password: str, timeout: int = 10):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.sock = None
        self.request_id = 100

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _next_id(self) -> int:
        self.request_id += 1
        return self.request_id

    def _send_packet(self, packet_id: int, packet_type: int, body: str):
        if self.sock is None:
            raise RuntimeError("Socket is not connected")

        body_bytes = body.encode("utf-8")
        payload = struct.pack("<ii", packet_id, packet_type) + body_bytes + b"\x00\x00"
        packet = struct.pack("<i", len(payload)) + payload
        self.sock.sendall(packet)

    def _recv_exact(self, size: int) -> bytes:
        if self.sock is None:
            raise RuntimeError("Socket is not connected")

        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Connection closed while receiving data")
            data += chunk
        return data

    def _recv_packet(self):
        raw_len = self._recv_exact(4)
        (length,) = struct.unpack("<i", raw_len)

        payload = self._recv_exact(length)
        packet_id, packet_type = struct.unpack("<ii", payload[:8])
        body = payload[8:-2].decode("utf-8", errors="replace")

        return packet_id, packet_type, body

    def authenticate(self):
        auth_id = self._next_id()
        self._send_packet(auth_id, SERVERDATA_AUTH, self.password)

        packets = []
        for _ in range(2):
            try:
                packets.append(self._recv_packet())
            except socket.timeout:
                break

        for packet_id, packet_type, _body in packets:
            if packet_type == SERVERDATA_AUTH_RESPONSE:
                if packet_id == -1:
                    raise PermissionError("RCON authentication failed")
                if packet_id == auth_id:
                    return True

        for packet_id, _packet_type, _body in packets:
            if packet_id == -1:
                raise PermissionError("RCON authentication failed")

        raise RuntimeError("Did not receive a clear auth response from the server")

    def command(self, command_text: str) -> str:
        cmd_id = self._next_id()
        self._send_packet(cmd_id, SERVERDATA_EXECCOMMAND, command_text)

        for _ in range(3):
            packet_id, _packet_type, body = self._recv_packet()
            if packet_id == cmd_id:
                return body.strip()

        return ""


def run_rcon_command(cfg: ConfigParser, command_text: str) -> str:
    host = cfg["rcon"]["host"]
    port = cfg.getint("rcon", "port", fallback=27015)
    password = cfg["rcon"]["password"]
    timeout = 10

    client = RCONClient(host, port, password, timeout=timeout)

    try:
        client.connect()
        client.authenticate()
        return client.command(command_text)
    finally:
        client.close()


def sftp_read_tail(
    host: str,
    port: int,
    username: str,
    password: str,
    remote_path: str,
    tail_bytes: int = 65536,
    timeout: int = 15
):
    transport = paramiko.Transport((host, port))
    transport.banner_timeout = timeout
    transport.connect(username=username, password=password)

    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        with sftp.open(remote_path, "rb") as f:
            file_size = f.stat().st_size
            start = max(0, file_size - tail_bytes)
            f.seek(start)
            data = f.read()

        return data.decode("utf-8", errors="replace"), file_size, start
    finally:
        sftp.close()
        transport.close()


def update_runtime_ping_success(count: int, players: list[str]) -> None:
    runtime = load_runtime()
    previous_status = runtime.get("server_status", "unknown")

    runtime["last_successful_ping"] = now_utc_iso()
    runtime["consecutive_failures"] = 0
    runtime["last_known_player_count"] = count
    runtime["last_known_players"] = players

    if previous_status != "online":
        runtime["server_status"] = "online"
        runtime["last_status_change"] = now_utc_iso()

    save_runtime(runtime)


def start_post_restart_watch(bot_token: str, users: dict, cfg: ConfigParser, reason: str) -> None:
    enabled = cfg.getboolean("restart_watch", "enabled", fallback=True)
    if not enabled:
        return

    watch_id = secrets.token_hex(4)
    runtime = load_runtime()
    runtime["post_restart_watch_active"] = True
    runtime["post_restart_watch_id"] = watch_id
    runtime["post_restart_started_at"] = now_utc_iso()
    runtime["post_restart_last_check"] = None
    runtime["post_restart_offline_alerted"] = False
    runtime["server_status"] = "restarting"
    runtime["last_status_change"] = now_utc_iso()
    runtime["last_restart_reason"] = reason
    save_runtime(runtime)

    thread = threading.Thread(
        target=post_restart_watch_loop,
        args=(bot_token, cfg, watch_id),
        daemon=True
    )
    thread.start()


def post_restart_watch_loop(bot_token: str, cfg: ConfigParser, watch_id: str) -> None:
    interval_minutes = cfg.getint("restart_watch", "check_interval_minutes", fallback=1)
    max_wait_minutes = cfg.getint("restart_watch", "max_wait_minutes", fallback=10)
    deadline = time.monotonic() + max(1, max_wait_minutes) * 60

    while True:
        runtime = load_runtime()
        if (
            not runtime.get("post_restart_watch_active")
            or runtime.get("post_restart_watch_id") != watch_id
        ):
            return

        runtime["post_restart_last_check"] = now_utc_iso()
        save_runtime(runtime)

        try:
            response = run_rcon_command(cfg, "players")
            count, players = parse_player_list(response)
            update_runtime_ping_success(count, players)

            runtime = load_runtime()
            runtime["post_restart_watch_active"] = False
            runtime["post_restart_watch_id"] = None
            runtime["post_restart_last_check"] = now_utc_iso()
            runtime["post_restart_offline_alerted"] = False
            save_runtime(runtime)

            security = load_security()
            security["last_online_alert_at"] = now_utc_iso()
            save_security(security)

            users = load_users()
            notify_all_users(bot_token, users, t("restart_watch_online"))
            log("Post-restart watch: server back online")
            return
        except Exception as e:
            log(f"Post-restart watch check failed: {e}")

        if time.monotonic() >= deadline:
            runtime = load_runtime()
            if (
                runtime.get("post_restart_watch_id") == watch_id
                and not runtime.get("post_restart_offline_alerted")
            ):
                runtime["post_restart_offline_alerted"] = True
                runtime["server_status"] = "offline"
                runtime["last_status_change"] = now_utc_iso()
                save_runtime(runtime)

                security = load_security()
                security["last_offline_alert_at"] = now_utc_iso()
                save_security(security)

                users = load_users()
                notify_all_users(bot_token, users, t("restart_watch_offline"))
                log("Post-restart watch: server still offline after max wait")

        time.sleep(max(1, interval_minutes * 60))


def heartbeat_success(bot_token: str, users: dict, count: int, players: list[str]) -> None:
    runtime = load_runtime()
    previous_status = runtime.get("server_status", "unknown")
    was_watch_active = runtime.get("post_restart_watch_active", False)

    update_runtime_ping_success(count, players)

    if was_watch_active:
        runtime = load_runtime()
        runtime["post_restart_watch_active"] = False
        runtime["post_restart_watch_id"] = None
        runtime["post_restart_last_check"] = now_utc_iso()
        runtime["post_restart_offline_alerted"] = False
        save_runtime(runtime)

        security = load_security()
        security["last_online_alert_at"] = now_utc_iso()
        save_security(security)

        notify_all_users(bot_token, users, t("restart_watch_online"))
        log("Post-restart watch: server back online (heartbeat)")
        return

    if previous_status != "online":
        security = load_security()
        security["last_online_alert_at"] = now_utc_iso()
        save_security(security)

        notify_all_users(bot_token, users, t("online_alert"))
        log("Heartbeat transition: offline/unknown -> online")


def heartbeat_failure(bot_token: str, users: dict, cfg: ConfigParser, error_text: str) -> None:
    runtime = load_runtime()
    previous_status = runtime.get("server_status", "unknown")
    threshold = cfg.getint("heartbeat", "offline_fail_threshold", fallback=3)

    runtime["consecutive_failures"] = int(runtime.get("consecutive_failures", 0)) + 1

    if runtime.get("post_restart_watch_active"):
        save_runtime(runtime)
        return

    if runtime["consecutive_failures"] >= threshold and previous_status != "offline":
        runtime["server_status"] = "offline"
        runtime["last_status_change"] = now_utc_iso()
        save_runtime(runtime)

        security = load_security()
        security["last_offline_alert_at"] = now_utc_iso()
        save_security(security)

        notify_all_users(
            bot_token,
            users,
            t(
                "offline_alert",
                failures=runtime["consecutive_failures"]
            )
        )
        log(f"Heartbeat transition: {previous_status} -> offline ({error_text})")
        return

    save_runtime(runtime)


def perform_heartbeat_check(bot_token: str, users: dict, cfg: ConfigParser) -> None:
    try:
        response = run_rcon_command(cfg, "players")
        count, players = parse_player_list(response)
        heartbeat_success(bot_token, users, count, players)
        log(f"Heartbeat OK players={count}")
    except Exception as e:
        heartbeat_failure(bot_token, users, cfg, str(e))
        log(f"Heartbeat failed: {e}")


def heartbeat_loop(cfg: ConfigParser) -> None:
    bot_token = cfg["bot"]["token"].strip()
    enabled = cfg.getboolean("heartbeat", "enabled", fallback=True)
    interval_minutes = cfg.getint("heartbeat", "interval_minutes", fallback=1)

    if not enabled:
        log("Heartbeat loop disabled by config.")
        return

    log(f"Heartbeat loop started. Interval: {interval_minutes} min")

    while True:
        try:
            users = load_users()
            if users.get("owner_id") is not None:
                perform_heartbeat_check(bot_token, users, cfg)
        except Exception as e:
            log(f"Heartbeat loop warning: {e}")

        time.sleep(max(1, interval_minutes * 60))


def send_rcon_server_message(cfg: ConfigParser, message: str) -> str:
    return run_rcon_command(cfg, f'servermsg "{message}"')


def save_and_quit_server(cfg: ConfigParser) -> tuple[str, str]:
    save_response = run_rcon_command(cfg, "save")
    time.sleep(cfg.getint("modcheck", "save_wait_seconds", fallback=5))
    quit_response = run_rcon_command(cfg, "quit")
    return save_response, quit_response


def get_current_players(cfg: ConfigParser) -> tuple[int, list[str], str]:
    response = run_rcon_command(cfg, "players")
    count, players = parse_player_list(response)
    update_runtime_ping_success(count, players)
    return count, players, response


def perform_modcheck(cfg: ConfigParser) -> tuple[bool, str]:
    response = run_rcon_command(cfg, "checkModsNeedUpdate")
    time.sleep(cfg.getint("modcheck", "after_check_wait_seconds", fallback=5))

    log_text, file_size, offset = sftp_read_tail(
        host=cfg["sftp"]["host"],
        port=cfg.getint("sftp", "port", fallback=2022),
        username=cfg["sftp"]["user"],
        password=cfg["sftp"]["password"],
        remote_path=cfg["sftp"]["log_path"],
        tail_bytes=65536,
        timeout=15
    )

    runtime = load_runtime()
    runtime["last_mod_check"] = now_utc_iso()

    search_text = cfg.get("modcheck", "log_search_text", fallback="CheckModsNeedUpdate: Mods need update")
    needs_update = parse_modcheck_result(log_text, search_text)
    runtime["last_mod_result"] = "update_needed" if needs_update else "no_update"
    save_runtime(runtime)

    log(f"Modcheck RCON response: {response}")
    log(f"Modcheck SFTP read size={file_size} offset={offset}")
    log(f"Modcheck tail preview:\n{tail_lines(log_text, 10)}")

    return needs_update, response


def perform_restart_sequence(bot_token: str, users: dict, cfg: ConfigParser, initiated_by: str) -> None:
    count, players, _ = get_current_players(cfg)
    countdown_enabled = cfg.getboolean("modcheck", "countdown_enabled", fallback=True)

    if count == 0:
        notify_all_users(bot_token, users, t("restart_no_players"))
        save_response, quit_response = save_and_quit_server(cfg)

        runtime = load_runtime()
        runtime["last_restart_time"] = now_utc_iso()
        runtime["last_restart_reason"] = initiated_by
        save_runtime(runtime)

        notify_all_users(
            bot_token,
            users,
            t("restart_done", save=save_response, quit=quit_response)
        )
        start_post_restart_watch(bot_token, users, cfg, initiated_by)
        return

    if countdown_enabled:
        countdown_messages = [
            (t("countdown_mods_update"), 10),
            (t("countdown_5min"), 60),
            (t("countdown_4min"), 60),
            (t("countdown_3min"), 60),
            (t("countdown_2min"), 60),
            (t("countdown_1min"), 30),
            (t("countdown_30sec"), 30),
        ]

        notify_all_users(
            bot_token,
            users,
            t("restart_countdown_start", count=count)
        )

        for index, (message, wait_seconds) in enumerate(countdown_messages):
            try:
                send_rcon_server_message(cfg, message)
            except Exception as e:
                log(f"Countdown message warning: {e}")

            if index >= 2:
                try:
                    current_count, _players, _ = get_current_players(cfg)
                    if current_count == 0:
                        notify_all_users(
                            bot_token,
                            users,
                            t("restart_all_left")
                        )
                        break
                except Exception as e:
                    log(f"Countdown players check warning: {e}")

            time.sleep(wait_seconds)

    save_response, quit_response = save_and_quit_server(cfg)

    runtime = load_runtime()
    runtime["last_restart_time"] = now_utc_iso()
    runtime["last_restart_reason"] = initiated_by
    save_runtime(runtime)

    notify_all_users(
        bot_token,
        users,
        t("restart_done", save=save_response, quit=quit_response)
    )
    start_post_restart_watch(bot_token, users, cfg, initiated_by)


def modcheck_loop(cfg: ConfigParser) -> None:
    bot_token = cfg["bot"]["token"].strip()
    enabled = cfg.getboolean("modcheck", "enabled", fallback=True)
    interval_minutes = cfg.getint("modcheck", "interval_minutes", fallback=30)

    if not enabled:
        log("Modcheck loop disabled by config.")
        return

    log(f"Modcheck loop started. Interval: {interval_minutes} min")

    while True:
        try:
            users = load_users()
            if users.get("owner_id") is not None:
                needs_update, _response = perform_modcheck(cfg)

                if needs_update:
                    notify_all_users(bot_token, users, t("modcheck_update_alert"))
                    perform_restart_sequence(bot_token, users, cfg, "mods_update")
        except Exception as e:
            log(f"Modcheck loop warning: {e}")

        time.sleep(max(1, interval_minutes * 60))


def handle_start(bot_token: str, chat_id: int, user_id: int, users: dict) -> None:
    if users.get("owner_id") is None:
        send_text(bot_token, chat_id, "start_no_owner")
        return

    if is_authorized(user_id, users):
        send_text(bot_token, chat_id, "start_authorized", role=get_role(user_id, users))
        return

    send_text(bot_token, chat_id, "not_authorized")


def handle_help(bot_token: str, chat_id: int, user_id: int, users: dict) -> None:
    if users.get("owner_id") is None:
        send_text(bot_token, chat_id, "help_no_owner")
        return

    role = get_role(user_id, users)

    if role == "owner":
        send_text(bot_token, chat_id, "help_owner")
        return

    if role == "admin":
        send_text(bot_token, chat_id, "help_admin")
        return

    send_text(bot_token, chat_id, "help_unknown")


def handle_whoami(bot_token: str, chat_id: int, user_id: int, username: str | None, first_name: str, last_name: str, users: dict) -> None:
    full_name = f"{first_name} {last_name}".strip()
    send_text(
        bot_token,
        chat_id,
        "whoami_text",
        user_id=user_id,
        username=username,
        full_name=full_name,
        role=get_role(user_id, users)
    )


def handle_claimowner(bot_token: str, chat_id: int, user_id: int, users: dict) -> None:
    if users.get("owner_id") is not None:
        if is_owner(user_id, users):
            send_text(bot_token, chat_id, "claimowner_already_owner")
        else:
            send_text(bot_token, chat_id, "claimowner_already_taken")
        return

    users["owner_id"] = user_id
    save_users(users)
    send_text(bot_token, chat_id, "claimowner_success")
    log(f"Owner claimed by Telegram user_id={user_id}")


def handle_addadmin(bot_token: str, chat_id: int, user_id: int, users: dict, cfg: ConfigParser, bot_username: str) -> None:
    if not is_owner(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    expire_minutes = cfg.getint("security", "invite_code_expire_minutes", fallback=15)
    code_length = cfg.getint("security", "invite_code_length", fallback=8)

    if cleanup_pending_codes(users):
        save_users(users)

    entry = create_admin_invite(users, expire_minutes, code_length)
    save_users(users)

    server_name = cfg["server"]["name"]

    send_text(bot_token, chat_id, "addadmin_intro")
    send_text(
        bot_token,
        chat_id,
        "addadmin_invite",
        server_name=server_name,
        bot_username=bot_username
    )
    send_text(bot_token, chat_id, "addadmin_redeem", code=entry["code"])

    log(f"Admin invite created by owner user_id={user_id} code={entry['code']}")


def handle_redeem(bot_token: str, chat_id: int, user_id: int, users: dict, security: dict, cfg: ConfigParser, text: str) -> None:
    blocked, until = is_temporarily_blocked(user_id, security)
    if blocked:
        save_security(security)
        send_text(bot_token, chat_id, "blocked_temp", until=until)
        return

    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        send_text(bot_token, chat_id, "redeem_usage")
        return

    if is_owner(user_id, users):
        send_text(bot_token, chat_id, "redeem_owner_already")
        return

    if is_admin(user_id, users):
        send_text(bot_token, chat_id, "redeem_admin_already")
        return

    code = parts[1].strip().upper()

    if cleanup_pending_codes(users):
        save_users(users)

    entry = find_pending_code(users, code)

    invalid = False
    if entry is None:
        invalid = True
    elif entry.get("used") is True:
        invalid = True
    elif is_code_expired(entry):
        invalid = True
    elif entry.get("role") != "admin":
        invalid = True

    if invalid:
        blocked_now = register_failed_invite_attempt(user_id, security, cfg)
        save_security(security)

        if blocked_now:
            blocked, until = is_temporarily_blocked(user_id, security)
            send_text(bot_token, chat_id, "redeem_blocked", until=until)
            return

        send_text(bot_token, chat_id, "redeem_invalid")
        return

    admins = users.setdefault("admins", [])
    if user_id not in admins:
        admins.append(user_id)

    entry["used"] = True
    entry["used_by"] = user_id

    cleanup_pending_codes(users)
    save_users(users)

    clear_failed_invite_attempts(user_id, security)
    save_security(security)

    send_text(bot_token, chat_id, "redeem_success")
    log(f"Admin redeemed invite user_id={user_id} code={code}")


def handle_listadmins(bot_token: str, chat_id: int, user_id: int, users: dict) -> None:
    if not is_owner(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    admins = users.get("admins", [])
    pending = users.get("pending_codes", [])

    owner_id = users.get("owner_id")
    owner_label = format_user_label(owner_id, users) if owner_id is not None else t("listadmins_unknown")

    lines = [
        t("listadmins_header"),
        t("listadmins_owner", label=owner_label),
        t("listadmins_admins_count", count=len(admins))
    ]

    if admins:
        lines.append("")
        lines.append(t("listadmins_admin_list"))
        for admin_id in admins:
            lines.append(f"- {format_user_label(admin_id, users)}")

    lines.append("")
    lines.append(t("listadmins_pending", count=len(pending)))

    if pending:
        for entry in pending:
            lines.append(
                t(
                    "listadmins_pending_entry",
                    code=entry.get("code"),
                    role=entry.get("role"),
                    expires_at=entry.get("expires_at")
                )
            )

    telegram_send_message(bot_token, chat_id, "\n".join(lines))


def handle_deleteadmin(bot_token: str, chat_id: int, user_id: int, users: dict, text: str) -> None:
    if not is_owner(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        send_text(bot_token, chat_id, "deleteadmin_usage")
        return

    target_raw = parts[1].strip()
    if not target_raw.isdigit():
        send_text(bot_token, chat_id, "deleteadmin_invalid")
        return

    target_id = int(target_raw)
    if target_id == users.get("owner_id"):
        send_text(bot_token, chat_id, "deleteadmin_owner_block")
        return

    admins = users.get("admins", [])
    if target_id not in admins:
        send_text(bot_token, chat_id, "deleteadmin_not_found")
        return

    admins.remove(target_id)
    users["admins"] = admins
    save_users(users)

    send_text(bot_token, chat_id, "deleteadmin_success", label=format_user_label(target_id, users))


def handle_status(bot_token: str, chat_id: int, user_id: int, users: dict, cfg: ConfigParser) -> None:
    if not is_authorized(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    runtime = load_runtime()

    text = "\n".join(
        [
            t("status_header", server_name=cfg["server"]["name"]),
            "",
            t("status_server", status=runtime.get("server_status", "unknown")),
            t("status_last_ping", value=format_last_seen_line(runtime.get("last_successful_ping"))),
            t("status_failures", count=runtime.get("consecutive_failures", 0)),
            t("status_last_mod_check", value=format_last_seen_line(runtime.get("last_mod_check"))),
            t("status_last_mod_result", value=runtime.get("last_mod_result", "unknown")),
            t("status_last_restart_time", value=format_last_seen_line(runtime.get("last_restart_time"))),
            t("status_last_restart_reason", value=runtime.get("last_restart_reason") or t("status_reason_none")),
            t("status_players_last", count=runtime.get("last_known_player_count")),
        ]
    )

    telegram_send_message(bot_token, chat_id, text)


def handle_lastseen(bot_token: str, chat_id: int, user_id: int, users: dict) -> None:
    if not is_authorized(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    runtime = load_runtime()
    send_text(
        bot_token,
        chat_id,
        "lastseen_text",
        value=format_last_seen_line(runtime.get("last_successful_ping"))
    )


def handle_players(bot_token: str, chat_id: int, user_id: int, users: dict, cfg: ConfigParser) -> None:
    if not is_authorized(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    try:
        count, players, _response = get_current_players(cfg)

        lines = [t("players_header", count=count)]
        if players:
            lines.append("")
            lines.append(t("players_list"))
            for name in players:
                lines.append(f"- {name}")

        telegram_send_message(bot_token, chat_id, "\n".join(lines))

    except Exception as e:
        send_text(bot_token, chat_id, "players_rcon_error", error=e)
        log(f"RCON players error: {e}")


def handle_servermsg(bot_token: str, chat_id: int, user_id: int, users: dict, cfg: ConfigParser, text: str) -> None:
    if not is_authorized(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        send_text(bot_token, chat_id, "servermsg_usage")
        return

    message = parts[1].strip()

    try:
        response = send_rcon_server_message(cfg, message)
        send_text(bot_token, chat_id, "servermsg_sent", response=response or "ok")
    except Exception as e:
        send_text(bot_token, chat_id, "servermsg_error", error=e)
        log(f"Servermsg error: {e}")


def handle_checkmods(bot_token: str, chat_id: int, user_id: int, users: dict, cfg: ConfigParser) -> None:
    if not is_authorized(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    try:
        needs_update, _response = perform_modcheck(cfg)

        if needs_update:
            send_text(bot_token, chat_id, "checkmods_needs_update")
        else:
            send_text(bot_token, chat_id, "checkmods_no_update")

    except Exception as e:
        send_text(bot_token, chat_id, "checkmods_error", error=e)
        log(f"Manual checkmods error: {e}")


def handle_hard_reset(bot_token: str, chat_id: int, user_id: int, users: dict, security: dict) -> None:
    if not is_owner(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    set_pending_confirmation(security, user_id, "reset_users", minutes=2)
    save_security(security)

    send_text(bot_token, chat_id, "hardreset_confirm")


def handle_force_restart(bot_token: str, chat_id: int, user_id: int, users: dict, cfg: ConfigParser) -> None:
    if not is_owner(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    try:
        send_text(bot_token, chat_id, "forcerestart_executing")
        save_response = run_rcon_command(cfg, "save")
        time.sleep(5)
        quit_response = run_rcon_command(cfg, "quit")

        runtime = load_runtime()
        runtime["last_restart_time"] = now_utc_iso()
        runtime["last_restart_reason"] = "force_restart"
        save_runtime(runtime)

        send_text(
            bot_token,
            chat_id,
            "forcerestart_success",
            save=save_response,
            quit=quit_response
        )
        log(f"ForceRestart executed by owner user_id={user_id}")
        start_post_restart_watch(bot_token, users, cfg, "force_restart")

    except Exception as e:
        send_text(bot_token, chat_id, "forcerestart_error", error=e)
        log(f"ForceRestart error: {e}")


def handle_cancel(bot_token: str, chat_id: int, user_id: int, users: dict, security: dict) -> None:
    if not is_authorized(user_id, users):
        send_text(bot_token, chat_id, "not_authorized")
        return

    cleanup_pending_confirmations(security)

    if clear_pending_confirmation(security, user_id):
        save_security(security)
        send_text(bot_token, chat_id, "cancel_done")
    else:
        send_text(bot_token, chat_id, "cancel_none")


def handle_pending_confirmation_text(bot_token: str, msg: dict, users: dict, cfg: ConfigParser, security: dict) -> bool:
    user_id = msg["user_id"]
    chat_id = msg["chat_id"]
    text = msg["text"].strip().lower()

    if not is_owner(user_id, users):
        return False

    cleanup_pending_confirmations(security)
    pending = get_pending_confirmation(security, user_id)

    if pending is None:
        return False

    if text != "yes":
        send_text(bot_token, chat_id, "hardreset_pending")
        return True

    action = pending.get("action")
    clear_pending_confirmation(security, user_id)
    save_security(security)

    if action != "reset_users":
        send_text(bot_token, chat_id, "hardreset_unknown_action")
        return True

    try:
        send_text(bot_token, chat_id, "hardreset_executing")

        users_data = load_users()
        owner_id = users_data.get("owner_id")
        users_data["admins"] = []
        users_data["pending_codes"] = []
        users_data["owner_id"] = owner_id
        save_users(users_data)

        send_text(bot_token, chat_id, "hardreset_success")
        log(f"User reset executed by owner user_id={user_id}")

    except Exception as e:
        send_text(bot_token, chat_id, "hardreset_error", error=e)
        log(f"User reset error: {e}")

    return True


def handle_text_command(bot_token: str, msg: dict, users: dict, cfg: ConfigParser, security: dict, bot_username: str) -> None:
    chat_id = msg["chat_id"]
    chat_type = msg.get("chat_type", "")
    user_id = msg["user_id"]
    username = msg["username"]
    first_name = msg["first_name"]
    last_name = msg["last_name"]
    text = msg["text"]

    if update_user_profile(users, msg):
        save_users(users)

    if chat_type != "private":
        if text.startswith("/"):
            send_text(bot_token, chat_id, "dm_only")
        return

    blocked, until = is_temporarily_blocked(user_id, security)
    if blocked and command_name(text) != "/redeem":
        save_security(security)
        send_text(bot_token, chat_id, "blocked_temp", until=until)
        return

    allowed, rate_message = check_rate_limit(user_id, users, security, cfg)
    save_security(security)
    if not allowed:
        telegram_send_message(bot_token, chat_id, rate_message or t("rate_limit_exceeded_short"))
        return

    if not text.startswith("/"):
        if handle_pending_confirmation_text(bot_token, msg, users, cfg, security):
            return

        if is_authorized(user_id, users):
            send_text(bot_token, chat_id, "unknown_command")
        else:
            send_text(bot_token, chat_id, "not_authorized")
        return

    cmd = command_name(text)

    if cmd == "/start":
        handle_start(bot_token, chat_id, user_id, users)
        return

    if cmd == "/help":
        handle_help(bot_token, chat_id, user_id, users)
        return

    if cmd == "/whoami":
        handle_whoami(bot_token, chat_id, user_id, username, first_name, last_name, users)
        return

    if cmd == "/claimowner":
        handle_claimowner(bot_token, chat_id, user_id, users)
        return

    if cmd == "/addadmin":
        handle_addadmin(bot_token, chat_id, user_id, users, cfg, bot_username)
        return

    if cmd == "/redeem":
        handle_redeem(bot_token, chat_id, user_id, users, security, cfg, text)
        return

    if cmd == "/listadmins":
        handle_listadmins(bot_token, chat_id, user_id, users)
        return

    if cmd == "/deleteadmin":
        handle_deleteadmin(bot_token, chat_id, user_id, users, text)
        return

    if cmd == "/status":
        handle_status(bot_token, chat_id, user_id, users, cfg)
        return

    if cmd == "/players":
        handle_players(bot_token, chat_id, user_id, users, cfg)
        return

    if cmd == "/lastseen":
        handle_lastseen(bot_token, chat_id, user_id, users)
        return

    if cmd == "/servermsg":
        handle_servermsg(bot_token, chat_id, user_id, users, cfg, text)
        return

    if cmd == "/checkmods":
        handle_checkmods(bot_token, chat_id, user_id, users, cfg)
        return

    if cmd in {"/hardreset", "/hard-reset"}:
        handle_hard_reset(bot_token, chat_id, user_id, users, security)
        return

    if cmd == "/forcerestart":
        handle_force_restart(bot_token, chat_id, user_id, users, cfg)
        return

    if cmd == "/cancel":
        handle_cancel(bot_token, chat_id, user_id, users, security)
        return

    if is_authorized(user_id, users):
        send_text(bot_token, chat_id, "command_not_implemented")
    else:
        send_text(bot_token, chat_id, "not_authorized")


def run_polling_loop(cfg: ConfigParser) -> None:
    bot_token = cfg["bot"]["token"].strip()

    if not bot_token:
        raise RuntimeError("Telegram bot token is empty")

    me = telegram_get_me(bot_token)
    bot_username = me.get("username", "")
    if not bot_username:
        raise RuntimeError("Could not determine bot username via Telegram getMe")

    try:
        commands = build_command_menu()
        telegram_set_my_commands(
            bot_token,
            commands,
            scope={"type": "all_private_chats"}
        )
        log("Telegram command menu updated (private chats).")
    except Exception as e:
        log(f"Command menu update warning: {e}")

    log(f"Telegram polling started as @{bot_username}")

    timeout = 25
    offset = None

    while True:
        try:
            updates = telegram_get_updates(bot_token, offset=offset, timeout=timeout)

            for update in updates:
                update_id = update["update_id"]
                offset = update_id + 1

                msg = extract_message_info(update)
                if msg is None:
                    continue

                users = load_users()
                security = load_security()

                log(
                    "Incoming message "
                    f"user_id={msg['user_id']} "
                    f"chat_id={msg['chat_id']} "
                    f"text={msg['text']!r}"
                )

                handle_text_command(
                    bot_token=bot_token,
                    msg=msg,
                    users=users,
                    cfg=cfg,
                    security=security,
                    bot_username=bot_username
                )

        except KeyboardInterrupt:
            log("KeyboardInterrupt received, exiting.")
            break
        except Exception as e:
            log(f"Polling warning: {e}")
            time.sleep(3)


def main() -> None:
    log("Starting Zombot")

    try:
        cfg = load_config(CONFIG_FILE)
        validate_config(cfg)

        init_locales(cfg.get("server", "language", fallback=DEFAULT_LANGUAGE))

        users = load_users()
        runtime = load_runtime()
        security = load_security()

        print_startup_summary(cfg, users, runtime, security)

        heartbeat_thread = threading.Thread(target=heartbeat_loop, args=(cfg,), daemon=True)
        heartbeat_thread.start()

        modcheck_thread = threading.Thread(target=modcheck_loop, args=(cfg,), daemon=True)
        modcheck_thread.start()

        run_polling_loop(cfg)

    except Exception as e:
        fatal(str(e))


if __name__ == "__main__":
    main()
