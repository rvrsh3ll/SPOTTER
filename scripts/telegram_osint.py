#!/usr/bin/env python3
"""
telegram_osint.py — Telegram bot OSINT client for SPOTTER.

WHAT IT IS FOR
--------------
Queries Telegram-based OSINT bots to enrich social media profiles and
phone number lookups with data from Russian/CIS platforms:

  - @VkHistoryRobot    — VK profile history, deleted posts, cached pages
  - @AllOSINTrobot     — Multi-platform OSINT queries
  - @osintbot          — General people search
  - @MailRuBot         — Mail.ru account lookup (custom)

The operator creates a Telegram bot via @BotFather and sets TELEGRAM_BOT_TOKEN.
This module uses the Telegram Bot API to send queries to target bots and
parse their responses.

ARCHITECTURE
------------
The module uses the raw Telegram Bot API via requests (no python-telegram-bot
dependency needed). The flow is:

  1. Send a message to the target bot (e.g. /start, then the query)
  2. Poll getUpdates for the bot's response
  3. Parse the response text for structured data

OPSEC
-----
All Telegram API calls go through the proxy envelope. The bot token is
a secret that identifies the operator's Telegram account — it must be
stored in the SOPS-encrypted secrets tier, never in .env.

SANDBOX CONSTRAINTS
-------------------
Runs inside the n8n Python task runner. Only stdlib + requests available.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote as _url_quote

import requests


TELEGRAM_API_BASE = "https://api.telegram.org"
_DEFAULT_TIMEOUT = 30
_DEFAULT_POLL_TIMEOUT = 15
_DEFAULT_MAX_WAIT = 60


class TelegramOSINTError(Exception):
    """A Telegram bot query failure the caller should record, not raise through."""


class TelegramOSINTClient:
    """Query Telegram OSINT bots for enrichment data.

    Requires a bot token from @BotFather. The bot must be started (/start)
    before it can send queries to other bots.
    """

    def __init__(
        self,
        bot_token: str = "",
        proxy_url: str = "",
        timeout: Optional[int] = None,
        poll_timeout: int = _DEFAULT_POLL_TIMEOUT,
        max_wait: int = _DEFAULT_MAX_WAIT,
    ):
        self.bot_token = (bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
        self.proxy_url = (proxy_url or "").strip()
        self.proxies = (
            {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None
        )
        self.timeout = timeout or _DEFAULT_TIMEOUT
        self.poll_timeout = poll_timeout
        self.max_wait = max_wait

        self.errors: List[str] = []
        self._api_base = f"{TELEGRAM_API_BASE}/bot{self.bot_token}" if self.bot_token else ""
        self._chat_ids: Dict[str, int] = {}  # bot username -> chat_id

    def _note(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def _api_call(self, method: str, params: Optional[dict] = None) -> Optional[dict]:
        """Make a Telegram Bot API call."""
        if not self._api_base:
            self._note("telegram: no bot token configured")
            return None
        url = f"{self._api_base}/{method}"
        try:
            r = requests.post(url, json=params or {},
                              proxies=self.proxies, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                if data.get("ok"):
                    return data.get("result")
                self._note(f"telegram: API error: {data.get('description', 'unknown')}")
                return None
            elif r.status_code == 401:
                self._note("telegram: bot token invalid (HTTP 401)")
                return None
            elif r.status_code == 429:
                retry_after = r.json().get("parameters", {}).get("retry_after", 30)
                self._note(f"telegram: rate limited, retry after {retry_after}s")
                return None
            else:
                self._note(f"telegram: HTTP {r.status_code}")
                return None
        except requests.exceptions.ProxyError as e:
            self._note(f"telegram: proxy unreachable: {e}")
            return None
        except Exception as e:
            self._note(f"telegram: request failed: {e}")
            return None

    def _send_message(self, chat_id: int, text: str) -> bool:
        """Send a message to a chat."""
        result = self._api_call("sendMessage", {
            "chat_id": chat_id,
            "text": text,
        })
        return result is not None

    def _get_updates(self, offset: int = 0, timeout: int = 0) -> List[dict]:
        """Poll for incoming messages."""
        result = self._api_call("getUpdates", {
            "offset": offset,
            "timeout": timeout,
            "allowed_updates": ["message"],
        })
        return result or []

    def _wait_for_response(self, from_chat_username: str, max_wait: Optional[int] = None) -> Optional[str]:
        """Wait for a response message from a specific bot.

        Polls getUpdates until a message from the target bot arrives or
        the timeout expires.
        """
        max_wait = max_wait or self.max_wait
        deadline = time.time() + max_wait
        offset = 0

        while time.time() < deadline:
            updates = self._get_updates(offset=offset, timeout=min(5, int(deadline - time.time())))
            for update in updates:
                offset = update.get("update_id", 0) + 1
                msg = update.get("message", {})
                chat = msg.get("chat", {})
                from_user = msg.get("from", {})
                text = msg.get("text", "")

                # Match response from the target bot
                if from_user.get("username", "").lower() == from_chat_username.lower():
                    return text

            if not updates:
                time.sleep(1)

        self._note(f"telegram: no response from @{from_chat_username} within {max_wait}s")
        return None

    def _resolve_bot_chat_id(self, bot_username: str) -> Optional[int]:
        """Get or establish a chat with a target bot."""
        uname = bot_username.lstrip("@").lower()
        if uname in self._chat_ids:
            return self._chat_ids[uname]

        # Send /start to initiate the conversation
        # We need to find the chat_id from the response
        # First, try sending a message by username (requires the bot to accept messages)
        result = self._api_call("sendMessage", {
            "chat": f"@{uname}",
            "text": "/start",
        })
        if result and result.get("chat", {}).get("id"):
            chat_id = result["chat"]["id"]
            self._chat_ids[uname] = chat_id
            return chat_id

        # Fallback: check recent updates for a chat from this bot
        updates = self._get_updates(timeout=2)
        for update in updates:
            msg = update.get("message", {})
            from_user = msg.get("from", {})
            if from_user.get("username", "").lower() == uname:
                chat_id = msg.get("chat", {}).get("id")
                if chat_id:
                    self._chat_ids[uname] = chat_id
                    return chat_id

        self._note(f"telegram: could not resolve chat for @{uname}")
        return None

    # ── VK History ───────────────────────────────────────────────────────────

    def query_vk_history(self, vk_url_or_id: str) -> Optional[Dict[str, Any]]:
        """Query @VkHistoryRobot for VK profile history.

        Accepts a VK profile URL (vk.com/username) or numeric ID.
        Returns cached/deleted posts, profile changes, etc.
        """
        if not vk_url_or_id:
            return None

        # Extract VK username or ID from URL
        vk_id = vk_url_or_id.strip()
        url_match = re.search(r"vk\.com/(?:id)?(\w+)", vk_id)
        if url_match:
            vk_id = url_match.group(1)

        chat_id = self._resolve_bot_chat_id("VkHistoryRobot")
        if not chat_id:
            return None

        # Send the VK identifier to the bot
        if not self._send_message(chat_id, vk_id):
            return None

        # Wait for response
        response = self._wait_for_response("VkHistoryRobot")
        if not response:
            return None

        # Parse the response
        return {
            "query": vk_id,
            "response": response[:5000],
            "source": "VkHistoryRobot",
            "platform": "vk.com",
        }

    # ── AllOSINT ─────────────────────────────────────────────────────────────

    def query_allosint(self, query: str, query_type: str = "username") -> Optional[Dict[str, Any]]:
        """Query @AllOSINTrobot for multi-platform OSINT.

        query_type: username | phone | email | name
        """
        if not query:
            return None

        chat_id = self._resolve_bot_chat_id("AllOSINTrobot")
        if not chat_id:
            return None

        # Format query based on type
        if query_type == "phone":
            msg = f"/phone {query}"
        elif query_type == "email":
            msg = f"/email {query}"
        elif query_type == "name":
            msg = f"/name {query}"
        else:
            msg = f"/username {query}"

        if not self._send_message(chat_id, msg):
            return None

        response = self._wait_for_response("AllOSINTrobot")
        if not response:
            return None

        return {
            "query": query,
            "query_type": query_type,
            "response": response[:5000],
            "source": "AllOSINTrobot",
        }

    # ── Mail.ru ──────────────────────────────────────────────────────────────

    def query_mailru(self, email_or_id: str) -> Optional[Dict[str, Any]]:
        """Query a Mail.ru account lookup bot.

        Accepts a Mail.ru email address or account ID.
        """
        if not email_or_id:
            return None

        # This is a placeholder for a custom bot integration
        # The actual bot would need to be set up by the operator
        self._note("telegram: MailRu bot integration not yet configured")
        return None

    # ── Aggregate query ──────────────────────────────────────────────────────

    def query_all(
        self,
        vk_profiles: Optional[List[str]] = None,
        usernames: Optional[List[str]] = None,
        phones: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run all applicable Telegram bot queries.

        VK profiles → VkHistoryRobot
        Usernames → AllOSINTrobot
        Phones → AllOSINTrobot /phone
        Emails → AllOSINTrobot /email
        """
        results: Dict[str, Any] = {
            "vk_history": [],
            "allosint": [],
        }

        vk_profiles = vk_profiles or []
        usernames = usernames or []
        phones = phones or []
        emails = emails or []

        # VK history lookups
        for vk_url in vk_profiles[:5]:
            vk_result = self.query_vk_history(vk_url)
            if vk_result:
                results["vk_history"].append(vk_result)

        # AllOSINT queries
        for uname in usernames[:5]:
            ao_result = self.query_allosint(uname, query_type="username")
            if ao_result:
                results["allosint"].append(ao_result)

        for phone in phones[:3]:
            ao_result = self.query_allosint(phone, query_type="phone")
            if ao_result:
                results["allosint"].append(ao_result)

        for email in emails[:3]:
            ao_result = self.query_allosint(email, query_type="email")
            if ao_result:
                results["allosint"].append(ao_result)

        return {
            "results": results,
            "errors": self.errors,
        }
