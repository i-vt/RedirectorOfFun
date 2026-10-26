"""Telegram inbound worker: approve/deny submissions by replying to the bot.

Commands (only honored from TELEGRAM_CHAT_ID):
    approve <id>   approve submission #id
    deny <id>      deny submission #id
    pending        list pending submissions
    help           command summary
"""
import json
import logging
import time
import urllib.request

from django.conf import settings

from . import services
from .models import BotState, Submission

logger = logging.getLogger(__name__)

HELP_TEXT = (
    "RoF control bot\n"
    "approve <id> - approve submission\n"
    "deny <id> - deny submission\n"
    "approve <id> remember - approve and auto-approve matching submissions\n"
    "pending - list pending submissions\n"
    "help - this message"
)


def _api(method, payload=None, timeout=15):
    token = settings.TELEGRAM_BOT_TOKEN
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured.")
    data = json.dumps(payload or {}).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=data, headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode())
    if not body.get("ok"):
        raise RuntimeError(f"Telegram API error: {body.get('description', 'unknown')}")
    return body.get("result", {})


def send_message(text, reply_markup=None):
    chat_id = settings.TELEGRAM_CHAT_ID
    if not chat_id:
        raise RuntimeError("TELEGRAM_CHAT_ID is not configured.")
    payload = {"chat_id": chat_id, "text": text[:3900]}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return _api("sendMessage", payload)


def decision_keyboard(submission_id):
    return {"inline_keyboard": [[
        {"text": "Approve", "callback_data": f"s:{submission_id}:approve"},
        {"text": "Deny", "callback_data": f"s:{submission_id}:deny"},
        {"text": "Pending", "callback_data": "cmd:pending"},
    ]]}


def answer_callback(callback_id, text=""):
    return _api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:200]})


def fetch_updates(offset, long_poll_seconds=25):
    return _api("getUpdates", {
        "offset": offset, "timeout": long_poll_seconds,
        "allowed_updates": ["message", "callback_query"],
    }, timeout=long_poll_seconds + 10)


def _pending_summary():
    pending = Submission.objects.select_related("link").filter(status="pending")[:10]
    if not pending:
        return "No pending submissions."
    lines = []
    for sub in pending:
        hostname = (sub.decoded_json or {}).get("hostname", "-")
        lines.append(f"#{sub.pk} {sub.link.path} (hostname: {hostname})")
    total = Submission.objects.filter(status="pending").count()
    suffix = f"\n…and {total - len(pending)} more." if total > len(pending) else ""
    return "Pending:\n" + "\n".join(lines) + suffix


def handle_command(text):
    """Execute one bot command; returns the reply text."""
    parts = (text or "").strip().split()
    if not parts:
        return HELP_TEXT
    command = parts[0].lower()
    if command in {"help", "start"}:
        return HELP_TEXT
    if command == "pending":
        return _pending_summary()
    if command in {"approve", "deny"}:
        if len(parts) < 2 or not parts[1].lstrip("#").isdigit():
            return f"Usage: {command} <submission id> [remember]"
        submission_id = int(parts[1].lstrip("#"))
        # "approve 42 remember" (or trailing +) learns the decision as an
        # auto-rule for future matching submissions on the same link.
        remember = any(p in {"remember", "r", "+"} for p in parts[2:])
        submission = Submission.objects.select_related("link").filter(pk=submission_id).first()
        if submission is None:
            return f"Submission #{submission_id} not found."
        verdict = "approve" if command == "approve" else "deny"
        decided = services.decide_submission(submission, verdict, via="telegram",
                                             remember=remember)
        if decided is None:
            return f"Submission #{submission_id} was already {submission.status}."
        suffix = " Decision learned for future matches." if remember else ""
        return (f"Submission #{submission_id} {submission.status}. "
                f"{submission.link.path} now serves: {submission.link.get_on_deny_display() if submission.status == 'denied' else 'content released on next visit'}.{suffix}")
    return "Unknown command. Send 'help'."


def process_updates(updates, chat_id):
    """Process a batch of getUpdates results; returns the new offset."""
    offset = None
    for update in updates:
        offset = update["update_id"] + 1
        try:
            if "callback_query" in update:
                _handle_callback(update["callback_query"], chat_id)
                continue
            message = update.get("message") or {}
            sender = str(message.get("chat", {}).get("id", ""))
            if chat_id and sender != str(chat_id):
                logger.info("ignored telegram message from chat %s", sender)
                continue
            reply = handle_command(message.get("text", ""))
            send_message(reply)
        except Exception:
            logger.exception("failed to process telegram update %s", update.get("update_id"))
    return offset


def _handle_callback(query, chat_id):
    sender = str((query.get("message") or {}).get("chat", {}).get("id", ""))
    if chat_id and sender != str(chat_id):
        answer_callback(query.get("id", ""), "Not authorized.")
        return
    data = query.get("data", "")
    callback_id = query.get("id", "")
    if data.startswith("cmd:"):
        answer_callback(callback_id, "OK")
        send_message(handle_command(data[4:]))
        return
    parts = data.split(":")
    if len(parts) == 3 and parts[0] == "s" and parts[2] in {"approve", "deny"}:
        submission_id = int(parts[1])
        submission = Submission.objects.select_related("link").filter(pk=submission_id).first()
        if submission is None:
            answer_callback(callback_id, "Submission not found.")
            return
        decided = services.decide_submission(submission, parts[2], via="telegram")
        if decided is None:
            answer_callback(callback_id, f"Already {submission.status}.")
            return
        answer_callback(callback_id, f"Submission #{submission_id} {submission.status}.")
        send_message(f"Submission #{submission_id} {submission.status} via inline button "
                     f"({submission.link.path}).")
        return
    answer_callback(callback_id, "Unknown action.")


def run_forever(poll_sleep=1.0, once=False):
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        logger.error("Telegram bot is not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID).")
        return False
    state, _ = BotState.objects.get_or_create(key="telegram-offset", defaults={"offset": 0})
    failures = 0
    while True:
        try:
            updates = fetch_updates(state.offset)
            failures = 0
        except Exception as exc:
            failures += 1
            wait = min(2 ** failures * 5, 300)
            logger.warning("getUpdates failed (%s); retrying in %ss", exc, wait)
            time.sleep(wait)
            continue
        try:
            new_offset = process_updates(updates, settings.TELEGRAM_CHAT_ID)
        except Exception:
            logger.exception("update processing failed")
            new_offset = None
        if new_offset:
            state.offset = new_offset
            state.save(update_fields=["offset"])
        if once:
            return True
        time.sleep(poll_sleep)
