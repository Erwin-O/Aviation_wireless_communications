import json
import os
import threading
import uuid
from typing import Callable, Optional, Union

import paho.mqtt.client as paho


Payload = Union[dict, str, bytes, bytearray]


class MQTTClient:
    """
    Thin wrapper around paho.mqtt.client.Client with Callback API VERSION2.

    Exposes:
      - connect()
      - loop_start() / loop_stop()
      - subscribe()
      - publish()
      - disconnect()
      - is_connected()
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        on_message: Optional[Callable] = None,
        on_connect: Optional[Callable] = None,
        on_disconnect: Optional[Callable] = None,
        enable_logger: bool = True,
        clean_session: bool = True,
    ):
        if not client_id:
            client_id = f"av-{os.getpid()}-{uuid.uuid4().hex[:8]}"

        self.client_id = client_id
        self._connected = False

        self._client = paho.Client(
            client_id=client_id,
            protocol=paho.MQTTv311,
            clean_session=clean_session,
            callback_api_version=paho.CallbackAPIVersion.VERSION2,
        )

        if enable_logger:
            self._client.enable_logger()

        # User callbacks (VERSION2 signatures)
        self._user_on_message = on_message
        self._user_on_connect = on_connect
        self._user_on_disconnect = on_disconnect

        # Wire internal callbacks (VERSION2)
        self._client.on_connect = self._on_connect_v2
        self._client.on_disconnect = self._on_disconnect_v2
        self._client.on_message = self._on_message_v2

        self._thread: Optional[threading.Thread] = None

    # -------------------------
    # Internal callbacks (V2)
    # -------------------------
    def _rc_int(self, reason_code):
        """
        Paho v2 passes a ReasonCode object (not an int).
        Convert safely to an integer.
        """
        # Most common: ReasonCode has .value
        if hasattr(reason_code, "value"):
            return int(reason_code.value)
        # Sometimes it might already be int-like
        try:
            return int(reason_code)
        except Exception:
            return -1

    def _on_connect_v2(self, client, userdata, flags, reason_code, properties):
        rc = self._rc_int(reason_code)

        if rc == 0:
            self._connected = True
            print(f"[MQTT] Connected (client_id={self.client_id})")
        else:
            print(f"[MQTT] Connect failed (client_id={self.client_id}) rc={rc} reason_code={reason_code!r}")

        if self._user_on_connect:
            self._user_on_connect(client, userdata, flags, reason_code, properties)

    def _on_disconnect_v2(self, client, userdata, disconnect_flags, reason_code, properties):
        rc = self._rc_int(reason_code)

        self._connected = False
        print(f"[MQTT] Disconnected (client_id={self.client_id}) rc={rc} reason_code={reason_code!r}")

        if self._user_on_disconnect:
            self._user_on_disconnect(client, userdata, disconnect_flags, reason_code, properties)

    def _on_message_v2(self, client, userdata, msg):
        if self._user_on_message:
            self._user_on_message(client, userdata, msg)

    # -------------------------
    # Public API
    # -------------------------
    def connect(self, host: str = "127.0.0.1", port: int = 1883, keepalive: int = 60):
        self._client.connect(host, port, keepalive)

    def loop_start(self):
        # Use Paho's thread, not our own.
        self._client.loop_start()

    def loop_stop(self):
        # Stop thread + network loop cleanly.
        self._client.loop_stop()
        # Ensure TCP disconnect
        self._client.disconnect()

    def disconnect(self):
        self._client.disconnect()

    def publish(self, topic: str, payload: Payload, qos: int = 0, retain: bool = False):
        if isinstance(payload, (bytes, bytearray)):
            data = bytes(payload)
        elif isinstance(payload, str):
            data = payload.encode("utf-8")
        else:
            data = json.dumps(payload).encode("utf-8")

        self._client.publish(topic, data, qos=qos, retain=retain)

    def subscribe(self, topic: str, qos: int = 0):
        self._client.subscribe(topic, qos=qos)

    def is_connected(self) -> bool:
        return self._connected

    def set_handlers(self, on_message=None, on_connect=None, on_disconnect=None):
        if on_message is not None:
            self._user_on_message = on_message
        if on_connect is not None:
            self._user_on_connect = on_connect
        if on_disconnect is not None:
            self._user_on_disconnect = on_disconnect
