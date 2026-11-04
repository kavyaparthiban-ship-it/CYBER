import unittest
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.demo import build_demo_pcap
from backend.app import database
from backend.app.main import app


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.original_data_dir, cls.original_db_path = database.DATA_DIR, database.DB_PATH
        database.DATA_DIR = Path(cls.temp_dir.name)
        database.DB_PATH = database.DATA_DIR / "test.sqlite3"
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()
        response = cls.client.post(
            "/api/auth/signup",
            json={"email": "analyst@example.test", "password": "correct-horse-42"},
        )
        if response.status_code != 200:
            raise RuntimeError(f"Unable to create API test account: {response.text}")

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)
        database.DATA_DIR, database.DB_PATH = cls.original_data_dir, cls.original_db_path
        cls.temp_dir.cleanup()

    def test_health_and_ml_limitation(self):
        self.assertEqual(self.client.get("/api/health").json()["status"], "ok")
        self.assertEqual(self.client.get("/api/auth/me").json()["user"]["email"], "analyst@example.test")
        ml = self.client.get("/api/ml/status").json()
        self.assertFalse(ml["implemented"])
        self.assertFalse(ml["available"])

    def test_signup_validation_login_and_logout(self):
        duplicate = self.client.post(
            "/api/auth/signup",
            json={"email": "analyst@example.test", "password": "correct-horse-42"},
        )
        self.assertEqual(duplicate.status_code, 409)

        weak_password = self.client.post(
            "/api/auth/signup",
            json={"email": "new@example.test", "password": "short"},
        )
        self.assertEqual(weak_password.status_code, 422)

        wrong_password = self.client.post(
            "/api/auth/login",
            json={"email": "analyst@example.test", "password": "incorrect-password"},
        )
        self.assertEqual(wrong_password.status_code, 401)

        logout = self.client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        self.assertEqual(self.client.get("/api/analysis/history").status_code, 401)

        login = self.client.post(
            "/api/auth/login",
            json={"email": "ANALYST@example.test", "password": "correct-horse-42"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").json()["user"]["email"], "analyst@example.test")

    def test_demo_analysis_history_detail_and_report(self):
        response = self.client.post("/api/analyze/demo")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertTrue(result["demo"])
        self.assertEqual(result["capture"]["packet_count"], 4)
        self.assertEqual(result["capture"]["ike_count"], 1)
        self.assertEqual(result["capture"]["esp_count"], 1)
        self.assertEqual(result["capture"]["ah_count"], 1)
        self.assertFalse(result["ml"]["implemented"])
        report = self.client.get(f'/api/analysis/{result["id"]}/report')
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.headers["content-type"], "application/pdf")
        self.assertTrue(report.content.startswith(b"%PDF-"))
        detail = self.client.get(f'/api/analysis/{result["id"]}').json()
        self.assertEqual(detail["id"], result["id"])
        self.assertTrue(any(row["id"] == result["id"] for row in self.client.get("/api/analysis/history").json()))
        self.assertGreaterEqual(self.client.get("/api/dashboard/statistics").json()["analyses"], 1)

    def test_analyses_are_isolated_between_accounts(self):
        result = self.client.post("/api/analyze/demo").json()
        other_client = TestClient(app)
        signup = other_client.post(
            "/api/auth/signup",
            json={"email": "other@example.test", "password": "another-password-99"},
        )
        self.assertEqual(signup.status_code, 200)
        self.assertEqual(other_client.get("/api/analysis/history").json(), [])
        self.assertEqual(other_client.get(f'/api/analysis/{result["id"]}').status_code, 404)
        self.assertEqual(other_client.get(f'/api/analysis/{result["id"]}/report').status_code, 404)
        other_client.close()

    def test_uploaded_capture_and_invalid_inputs(self):
        response = self.client.post(
            "/api/analyze?filename=upload.pcap",
            content=build_demo_pcap(),
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["demo"])
        self.assertEqual(self.client.post("/api/analyze?filename=empty.pcap", content=b"").status_code, 422)
        self.assertEqual(self.client.post("/api/analyze?filename=not-pcap.pcap", content=b"bad").status_code, 422)
        self.assertEqual(self.client.post("/api/analyze?filename=unsupported.pcapng", content=b"").status_code, 415)

    def test_synthetic_sample_download(self):
        response = self.client.get("/api/sample")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, build_demo_pcap())
        self.assertIn("synthetic.pcap", response.headers["content-disposition"])


if __name__ == "__main__":
    unittest.main()
