import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app


EXPECTED_ROUTES = {
    "RC-6001": "RECOMMEND_APPROVE",
    "RC-6002": "RECOMMEND_DENY",
    "RC-6003": "NEED_MORE_INFORMATION",
    "RC-6004": "MANUAL_REVIEW",
    "RC-6005": "DUPLICATE_OR_PROCESSED",
    "RC-6006": "RECOMMEND_APPROVE",
    "RC-6007": "RECOMMEND_APPROVE",
    "RC-6008": "RECOMMEND_APPROVE",
    "RC-6009": "RECOMMEND_DENY",
    "RC-6010": "DUPLICATE_OR_PROCESSED",
    "RC-6011": "RECOMMEND_DENY",
    "RC-6012": "MANUAL_REVIEW",
    "RC-6013": "RECOMMEND_DENY",
    "RC-6014": "NEED_MORE_INFORMATION",
    "RC-6015": "DUPLICATE_OR_PROCESSED",
    "RC-6016": "RECOMMEND_APPROVE",
}


class ReturnDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": str(Path(self.temp_dir.name) / "test.sqlite3"),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def headers(self, role):
        return {"X-Role": role}

    def test_all_cases_receive_expected_server_route(self):
        for case_id, expected in EXPECTED_ROUTES.items():
            response = self.client.post(
                f"/api/cases/{case_id}/analyze", headers=self.headers("manager")
            )
            self.assertEqual(response.status_code, 200, case_id)
            self.assertEqual(response.json["analysis"]["route"], expected, case_id)

    def test_client_cannot_read_or_change_manager_recommendation(self):
        self.client.post(
            "/api/cases/RC-6001/analyze", headers=self.headers("manager")
        )
        response = self.client.get(
            "/api/cases/RC-6001", headers=self.headers("client")
        )
        self.assertNotIn("analysis", response.json)
        self.assertNotIn("manager_decision", response.json)
        self.assertNotIn("history", response.json)
        denied = self.client.post(
            "/api/cases/RC-6001/decision",
            headers=self.headers("client"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        self.assertEqual(denied.status_code, 403)

    def test_client_gets_safe_final_message_without_internal_details(self):
        self.client.post(
            "/api/cases/RC-6001/analyze", headers=self.headers("manager")
        )
        self.client.post(
            "/api/cases/RC-6001/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        response = self.client.get(
            "/api/cases/RC-6001", headers=self.headers("client")
        )
        self.assertIn("Менеджер подтвердил возврат", response.json["client_message"])
        self.assertNotIn("RA-6001", response.json["client_message"])
        self.assertNotIn("analysis", response.json)
        self.assertNotIn("manager_decision", response.json)

    def test_external_model_is_called_but_cannot_replace_server_route(self):
        response_body = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"route_suggestion":"RECOMMEND_DENY",'
                            '"client_draft":"Черновик для проверки",'
                            '"manager_draft":"Заметка для проверки"}'
                        )
                    }
                }
            ]
        }

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps(response_body).encode("utf-8")

        app_with_ai = create_app(
            {
                "TESTING": True,
                "DATABASE": str(Path(self.temp_dir.name) / "model.sqlite3"),
                "OPENAI_API_KEY": "test-key-not-written-to-db",
            }
        )
        with patch("app.urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
            response = app_with_ai.test_client().post(
                "/api/cases/RC-6001/analyze", headers=self.headers("manager")
            )
        self.assertEqual(response.status_code, 200)
        urlopen.assert_called_once()
        analysis = response.json["analysis"]
        self.assertEqual(analysis["route"], "RECOMMEND_APPROVE")
        self.assertEqual(analysis["model_suggestion"]["route"], "RECOMMEND_DENY")
        self.assertFalse(analysis["model_suggestion"]["matched"])
        self.assertEqual(analysis["model_drafts"]["client"], "Черновик для проверки")
        connection = sqlite3.connect(Path(self.temp_dir.name) / "model.sqlite3")
        try:
            audit_rows = connection.execute(
                "SELECT details_json FROM audit_log"
            ).fetchall()
        finally:
            connection.close()
        self.assertNotIn(
            "test-key-not-written-to-db",
            json.dumps(audit_rows, ensure_ascii=False),
        )

    def test_only_confirmed_server_approval_creates_authorization(self):
        self.client.post(
            "/api/cases/RC-6002/analyze", headers=self.headers("manager")
        )
        response = self.client.post(
            "/api/cases/RC-6002/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        self.assertEqual(response.json["status"], "DENIED")
        self.assertIsNone(response.json["authorization_reference"])

        self.client.post(
            "/api/cases/RC-6001/analyze", headers=self.headers("manager")
        )
        response = self.client.post(
            "/api/cases/RC-6001/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        self.assertEqual(response.json["status"], "RETURN_AUTHORIZED")
        self.assertEqual(response.json["authorization_reference"], "RA-6001")

    def test_duplicate_case_cannot_get_second_authorization(self):
        self.client.post(
            "/api/cases/RC-6005/analyze", headers=self.headers("manager")
        )
        response = self.client.post(
            "/api/cases/RC-6005/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        self.assertEqual(response.json["status"], "DUPLICATE_PROCESSED")
        self.assertIsNone(response.json["authorization_reference"])

    def test_analysis_and_decision_transitions_are_one_way(self):
        response = self.client.post(
            "/api/cases/RC-6001/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        self.assertEqual(response.status_code, 409)
        self.client.post(
            "/api/cases/RC-6001/analyze", headers=self.headers("manager")
        )
        self.client.post(
            "/api/cases/RC-6001/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        repeated = self.client.post(
            "/api/cases/RC-6001/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        self.assertEqual(repeated.status_code, 409)

    def test_kitchen_case_requests_only_missing_kit_and_logs_stop_reason(self):
        response = self.client.post(
            "/api/cases/RC-6014/analyze", headers=self.headers("manager")
        )
        result = response.json["analysis"]
        expected_question = "Подтвердите, пожалуйста, что в комплекте есть все принадлежности и документы?"
        self.assertEqual(result["route"], "NEED_MORE_INFORMATION")
        self.assertEqual(result["missing_information"], [expected_question])
        self.assertEqual(result["client_draft"], expected_question)
        self.assertEqual(result["history"][0]["reason_code"], "USE_INSTRUCTIONS")
        self.assertIn("по другой причине", result["reason"])

        audit = self.client.get("/api/audit", headers=self.headers("manager")).json["events"]
        analysis_event = next(event for event in audit if event["event_type"] == "analysis_created")
        self.assertIn(expected_question, analysis_event["details"]["stop_reason"])

        decision = self.client.post(
            "/api/cases/RC-6014/decision",
            headers=self.headers("manager"),
            json={"action": "REQUEST_INFORMATION"},
        )
        self.assertEqual(decision.json["status"], "WAITING_FOR_CUSTOMER")
        client_view = self.client.get(
            "/api/cases/RC-6014", headers=self.headers("client")
        ).json
        self.assertEqual(client_view["client_message"], expected_question)
        self.assertNotIn("analysis", client_view)
        self.assertNotIn("manager_decision", client_view)

    def test_order_fact_lists_every_item_in_multi_item_order(self):
        result = self.client.post(
            "/api/cases/RC-6016/analyze", headers=self.headers("manager")
        ).json["analysis"]
        order_fact = next(fact for fact in result["facts"] if fact["label"] == "Заказ и товары")
        self.assertIn("полка «Линия»", order_fact["value"])
        self.assertIn("креплений «Линия»", order_fact["value"])

    def test_reset_command_clears_decisions_and_reimports_starter_queue(self):
        self.client.post(
            "/api/cases/RC-6001/analyze", headers=self.headers("manager")
        )
        self.client.post(
            "/api/cases/RC-6001/decision",
            headers=self.headers("manager"),
            json={"action": "CONFIRM_RECOMMENDATION"},
        )
        result = self.app.test_cli_runner().invoke(args=["reset-data"])
        self.assertEqual(result.exit_code, 0, result.output)
        cases = self.client.get(
            "/api/cases", headers=self.headers("manager")
        ).json["cases"]
        self.assertEqual(len(cases), 16)
        self.assertTrue(all(case["status"] == "OPEN" for case in cases))


if __name__ == "__main__":
    unittest.main()
