import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from app import main


class SecureNotesSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.error_client = TestClient(main.app, raise_server_exceptions=False)

    def login(self, username, password):
        response = self.client.post(
            "/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["token"]

    def test_authentication_and_token_integrity(self):
        self.assertEqual(self.client.get("/notes").status_code, 401)
        token = self.login("alice", "alicepass")
        self.assertIn(".", token)
        tampered_token = token[:-1] + ("A" if token[-1] != "A" else "B")
        response = self.client.get(
            "/notes", headers={"Authorization": f"Bearer {tampered_token}"}
        )
        self.assertEqual(response.status_code, 401)
        malformed = self.client.get(
            "/notes", headers={"Authorization": "Bearer %%%.%%%"}
        )
        self.assertEqual(malformed.status_code, 401)

    def test_expired_token_is_rejected(self):
        with patch.object(main.time, "time", return_value=1000):
            token = main.create_token(2)
        with patch.object(main.time, "time", return_value=1000 + main.TOKEN_TTL_SECONDS + 1):
            response = self.client.get(
                "/notes", headers={"Authorization": f"Bearer {token}"}
            )
        self.assertEqual(response.status_code, 401)

    def test_note_ownership_is_enforced(self):
        alice_token = self.login("alice", "alicepass")
        own_note = self.client.get(
            "/notes/1", headers={"Authorization": f"Bearer {alice_token}"}
        )
        other_note = self.client.get(
            "/notes/2", headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(own_note.status_code, 200)
        self.assertEqual(other_note.status_code, 404)

    def test_admin_access_fails_closed(self):
        alice_token = self.login("alice", "alicepass")
        denied = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {alice_token}"}
        )
        allowed = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {self.login('admin', 'admin123')}"},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        self.assertNotIn("password", allowed.json()[0])

    def test_login_rejects_injection_and_uses_generic_errors(self):
        injection = self.client.post(
            "/login",
            json={"username": "' OR '1'='1", "password": "admin123"},
        )
        unknown = self.client.post(
            "/login", json={"username": str(uuid4()), "password": "wrong"}
        )
        self.assertEqual(injection.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(injection.json(), unknown.json())

    def test_passwords_are_hashed_and_normal_operations_work(self):
        stored_passwords = [row["password"] for row in main.db.execute("SELECT password FROM users")]
        self.assertTrue(all("$" in password for password in stored_passwords))

        username = f"test-{uuid4().hex}"
        registered = self.client.post(
            "/register", json={"username": username, "password": "testpass"}
        )
        self.assertEqual(registered.status_code, 200)
        token = self.login(username, "testpass")
        created = self.client.post(
            "/notes",
            headers={"Authorization": f"Bearer {token}"},
            json={"title": "Test", "body": "Private"},
        )
        self.assertEqual(created.status_code, 200)
        listed = self.client.get(
            "/notes", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()[0]["title"], "Test")

    def test_cors_does_not_allow_untrusted_origin(self):
        response = self.client.options(
            "/notes",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), "*")

    def test_unexpected_errors_do_not_leak_details(self):
        with patch("app.main.current_user", side_effect=RuntimeError("secret detail")):
            response = self.error_client.get(
                "/notes", headers={"Authorization": "Bearer invalid"}
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"error": "Internal server error"})


if __name__ == "__main__":
    unittest.main()