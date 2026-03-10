import tempfile
import time
import unittest
from typing import Optional

from atlas import beacon_chat

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except Exception:  # pragma: no cover - test skips when PyNaCl is unavailable
    HAS_NACL = False


class TestRelayPingSecurity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db_path = beacon_chat.DB_PATH
        beacon_chat.DB_PATH = f"{self._tmp.name}/beacon_atlas_test.db"
        beacon_chat.ATLAS_RATE_LIMITER._entries.clear()
        beacon_chat.ATLAS_RATE_LIMITER._last_cleanup = 0.0
        beacon_chat.init_db()
        beacon_chat.app.config["TESTING"] = True
        self.client = beacon_chat.app.test_client()

    def tearDown(self) -> None:
        beacon_chat.DB_PATH = self._orig_db_path
        self._tmp.cleanup()

    def _insert_existing_agent(
        self,
        agent_id: Optional[str] = None,
        relay_token: str = "relay_valid_token",
        token_expires: Optional[float] = None,
        pubkey_hex: str = "11" * 32,
    ) -> str:
        now = time.time()
        if token_expires is None:
            token_expires = now + 3600
        if agent_id is None:
            agent_id = beacon_chat.agent_id_from_pubkey_hex(pubkey_hex)
        with beacon_chat.app.app_context():
            db = beacon_chat.get_db()
            db.execute(
                """
                INSERT INTO relay_agents (
                    agent_id, pubkey_hex, model_id, provider, capabilities, webhook_url,
                    relay_token, token_expires, name, status, beat_count, registered_at,
                    last_heartbeat, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    pubkey_hex,
                    "test-model",
                    "beacon",
                    "[]",
                    "",
                    relay_token,
                    token_expires,
                    "Existing Agent",
                    "active",
                    1,
                    now,
                    now,
                    "{}",
                ),
            )
            db.commit()
        return agent_id

    def _ping_payload(self, **overrides):
        payload = {
            "nonce": f"ping-{time.time_ns()}",
            "ts": time.time(),
        }
        payload.update(overrides)
        return payload

    def test_relay_ping_rejects_unsigned_new_agent(self) -> None:
        pubkey_hex = "00" * 32
        response = self.client.post(
            "/relay/ping",
            json=self._ping_payload(
                agent_id=beacon_chat.agent_id_from_pubkey_hex(pubkey_hex),
                name="Unsigned Agent",
                pubkey_hex=pubkey_hex,
            ),
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("signature required", payload["error"])

    def test_relay_ping_rejects_non_hex_pubkey(self) -> None:
        response = self.client.post(
            "/relay/ping",
            json=self._ping_payload(
                agent_id="bcn_badpubkey01",
                name="Bad Pubkey Agent",
                pubkey_hex="zzzz",
                signature="00",
            ),
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("64 hex chars", payload["error"])

    def test_relay_ping_existing_agent_requires_relay_token(self) -> None:
        agent_id = self._insert_existing_agent()
        response = self.client.post(
            "/relay/ping",
            json=self._ping_payload(
                agent_id=agent_id,
                name="Existing Agent",
            ),
        )
        self.assertEqual(response.status_code, 401)
        payload = response.get_json()
        self.assertIn("relay_token required", payload["error"])

    def test_relay_ping_existing_agent_rejects_invalid_relay_token(self) -> None:
        agent_id = self._insert_existing_agent()
        response = self.client.post(
            "/relay/ping",
            json=self._ping_payload(
                agent_id=agent_id,
                name="Existing Agent",
                relay_token="relay_wrong_token",
            ),
        )
        self.assertEqual(response.status_code, 403)
        payload = response.get_json()
        self.assertIn("Invalid relay_token", payload["error"])

    def test_relay_ping_existing_agent_accepts_valid_relay_token(self) -> None:
        agent_id = self._insert_existing_agent()
        response = self.client.post(
            "/relay/ping",
            json=self._ping_payload(
                agent_id=agent_id,
                name="Existing Agent",
                relay_token="relay_valid_token",
            ),
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["agent_id"], agent_id)

    def test_relay_ping_existing_agent_rejects_nonce_replay(self) -> None:
        agent_id = self._insert_existing_agent()
        payload = self._ping_payload(
            agent_id=agent_id,
            name="Existing Agent",
            relay_token="relay_valid_token",
            nonce="fixed-existing-nonce",
        )
        first = self.client.post("/relay/ping", json=payload)
        second = self.client.post("/relay/ping", json=payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)
        self.assertIn("nonce replay detected", second.get_json()["error"])

    @unittest.skipUnless(HAS_NACL, "pynacl not installed")
    def test_relay_ping_new_agent_rejects_pubkey_agent_id_mismatch(self) -> None:
        signing_key = SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        derived_id = beacon_chat.agent_id_from_pubkey_hex(pubkey_hex)
        payload = self._ping_payload(
            agent_id="bcn_victim0001",
            name="Impersonation Attempt",
            pubkey_hex=pubkey_hex,
            signature=signing_key.sign(b"bcn_victim0001").signature.hex(),
        )
        response = self.client.post("/relay/ping", json=payload)
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("agent_id mismatch", body["error"])
        self.assertEqual(body["expected"], derived_id)

    @unittest.skipUnless(HAS_NACL, "pynacl not installed")
    def test_relay_ping_new_agent_rejects_nonce_replay(self) -> None:
        signing_key = SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        agent_id = beacon_chat.agent_id_from_pubkey_hex(pubkey_hex)
        payload = self._ping_payload(
            agent_id=agent_id,
            name="Signed Agent",
            pubkey_hex=pubkey_hex,
            nonce="fixed-new-agent-nonce",
        )
        payload["signature"] = signing_key.sign(agent_id.encode("utf-8")).signature.hex()
        first = self.client.post("/relay/ping", json=payload)
        with beacon_chat.app.app_context():
            db = beacon_chat.get_db()
            db.execute("DELETE FROM relay_agents WHERE agent_id = ?", (agent_id,))
            db.commit()
        second = self.client.post("/relay/ping", json=payload)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 409)
        self.assertIn("nonce replay detected", second.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
