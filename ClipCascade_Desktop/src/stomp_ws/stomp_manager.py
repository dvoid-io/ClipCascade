import json
import logging
from threading import Event, Lock, Thread


from interfaces.ws_interface import WSInterface
from stomp_ws.client import Client
from core.config import Config
from utils.cipher_manager import CipherManager
from clipboard.clipboard_manager import ClipboardManager
from utils.notification_manager import NotificationManager
from utils.request_manager import RequestManager
from utils.ssl_helper import websocket_sslopt_for_config
from core.constants import *

if PLATFORM.startswith(LINUX) and LINUX_USE_CLI_UI:
    from cli.tray import TaskbarPanel
else:
    from gui.tray import TaskbarPanel


class STOMPManager(WSInterface):
    def __init__(self, config: Config, is_login_phase=True):
        self.config = config
        self.clipboard_manager = ClipboardManager(self.config)
        self.cipher_manager = CipherManager(self.config)
        self.notification_manager = NotificationManager(self.config)
        self.sys_tray: TaskbarPanel = None
        self.first_conn_lost = True
        self.is_login_phase = is_login_phase
        self.client = None
        self.is_connected = False
        self.disconnected = False
        self.is_auto_reconnecting = False
        # Auto-reconnect loop: at most one runs at a time (see _on_close).
        self._reconnect_lock = Lock()
        self._reconnect_thread = None
        self._reconnect_wake = Event()  # set to make the loop re-check its exit condition

    def set_tray_ref(self, sys_tray: TaskbarPanel):
        """
        Sets the system tray reference.
        """
        self.sys_tray = sys_tray
        self.clipboard_manager.set_tray_ref(sys_tray)

    def get_total_timeout(self):
        """
        Returns the total timeout value in milliseconds.
        Upper bound on how long a disconnect() can take to settle: the reconnect loop
        wakes immediately, but a connect attempt already in flight may run for
        WEBSOCKET_TIMEOUT; the RECONNECT_WS_TIMER term keeps the tray countdown generous.
        """
        return (RECONNECT_WS_TIMER * 1000) + WEBSOCKET_TIMEOUT

    def get_stats(self):
        return None

    def _drop_client(self):
        """
        Closes the current Client, if any, without firing _on_close.
        A Client whose run_forever thread is still alive (a hung connect, a dead
        socket) would otherwise report a stale close against the replacement.
        """
        client, self.client = self.client, None
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass

    def connect(self) -> tuple[bool, str]:
        try:
            if self.is_connected:
                return True, ""
            if self.disconnected:
                return False, "Websocket disconnected"
            self._drop_client()
            self.client = Client(
                self.config.data["websocket_url"],
                headers={
                    "Cookie": RequestManager.format_cookie(
                        self.config.data["cookie"]
                    )
                },
                on_close_callback=self._on_close,
                sslopt=websocket_sslopt_for_config(self.config),
            )
            self.client.connect(
                timeout=WEBSOCKET_TIMEOUT,
                connectCallback=lambda _: self.client.subscribe(  # receive event
                    destination=SUBSCRIPTION_DESTINATION,
                    callback=self._receive,
                ),
            )
            if self.disconnected:
                self.disconnect()
                return False, "Websocket disconnected"

            # logging.info("Websocket connected")
            self.is_connected = True
            self.is_auto_reconnecting = False
            if not self.first_conn_lost:
                self.first_conn_lost = True
                self.notification_manager.notify(
                    title=f"{APP_NAME}: WebSocket Connection Restored 🔗",
                    message="Connection re-established",
                )

            # send event
            self.clipboard_manager.on_copy(self.send)
            return True, "Websocket connected"
        except Exception as e:
            msg = f"Failed to connect websocket: {e}"
            logging.error(msg)
            self._drop_client()
            return False, msg

    def _on_close(self):
        # Runs on the closing socket's run_forever thread: for the live connection when it
        # drops, and again for every attempt that fails inside run_forever (websocket-client
        # tears down and fires on_close on a failed handshake too). Never block here.
        with self._reconnect_lock:
            self.is_connected = False
            if self.is_login_phase or self.disconnected:
                return
            if self._reconnect_thread is not None:
                return  # a loop is already running; it re-checks is_connected
            self.is_auto_reconnecting = True
            if self.first_conn_lost:
                self.notification_manager.notify(
                    title=f"{APP_NAME}: WebSocket Connection Lost ⛓️‍💥",
                    message="Check your internet connection. Retrying...",
                )
                self.first_conn_lost = False
            self._reconnect_wake.clear()
            self._reconnect_thread = Thread(
                target=self._reconnect_loop, name="STOMPReconnectThread", daemon=True
            )
            self._reconnect_thread.start()

    def _reconnect_loop(self):
        """
        Retries connect() with a doubling delay (RECONNECT_WS_TIMER .. RECONNECT_WS_TIMER_MAX)
        until connected or disconnect() is called. Exactly one loop exists at a time;
        the exit check and _on_close share a lock so a drop can never fall between them.
        """
        delay = RECONNECT_WS_TIMER
        while True:
            with self._reconnect_lock:
                if self.disconnected or self.is_connected:
                    self._reconnect_thread = None
                    self.is_auto_reconnecting = False
                    return
            if self._reconnect_wake.wait(delay):
                self._reconnect_wake.clear()  # disconnect() asked for a re-check
                continue
            ok, _ = self.connect()
            if not ok:
                delay = min(delay * 2, RECONNECT_WS_TIMER_MAX)

    def send(self, payload: str, payload_type: str = "text"):
        try:
            if self.is_connected:
                if self.clipboard_manager.has_clipboard_changed(payload):
                    if self.config.data["cipher_enabled"]:
                        payload = CipherManager.encode_to_json_string(
                            **self.cipher_manager.encrypt(payload)
                        )
                    body = json.dumps({"payload": payload, "type": payload_type})
                    self.client.send(destination=SEND_DESTINATION, body=body)
        except Exception as e:
            logging.error(f"Failed to send data: {e}")

    def _receive(self, frame: any) -> str:
        try:
            if self.is_connected:
                body = json.loads(frame.body)
                payload = body["payload"]
                payload_type = body.get("type", "text")
                if self.config.data["cipher_enabled"]:
                    payload = self.cipher_manager.decrypt(
                        **CipherManager.decode_from_json_string(payload)
                    )

                if self.clipboard_manager.has_clipboard_changed(payload):
                    self.clipboard_manager.base64_to_clipboard(
                        base64_string=payload, type_=payload_type
                    )
        except json.decoder.JSONDecodeError:
            logging.error(
                "If cipher is enabled, please make sure it is enabled on all devices"
            )
        except Exception as e:
            logging.error(f"Failed to receive data: {e}")

    def manual_reconnect(self):
        if not self.is_auto_reconnecting:
            self.disconnected = False
            self.connect()

    def disconnect(self):
        try:
            self.clipboard_manager.previous_clipboard_hash = 0
            self.disconnected = True
            self.first_conn_lost = True
            self._reconnect_wake.set()  # stop a pending auto-reconnect right away
            self._drop_client()
            self.is_connected = False
            logging.info("Websocket disconnected")
            self.clipboard_manager.stop()
        except Exception as e:
            logging.error(f"Failed to disconnect websocket: {e}")
