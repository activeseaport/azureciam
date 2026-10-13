import unittest
from unittest.mock import MagicMock, patch

from ciam_auth import CiamConfig
from ui.web_app import create_app


class SignupDisplayNameTests(unittest.TestCase):
    def setUp(self):
        self.auth_client = MagicMock()
        self.auth_client.signup_start.return_value.needs_redirect = False
        with patch("ui.web_app.NativeAuthClient", return_value=self.auth_client):
            app = create_app(CiamConfig("test", "test-client"))
        app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = app.test_client()

    def signup(self, display_name):
        return self.client.post(
            "/signup",
            data={
                "username": "person@example.com",
                "password": "StrongPassword1!",
                "confirm_password": "StrongPassword1!",
                "displayName": display_name,
            },
        )

    def test_form_contains_display_name(self):
        response = self.client.get("/signup")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="idisplayNameInput"', response.data)
        self.assertIn(b'name="displayName"', response.data)
        self.assertIn(b'class="ext-input ext-text-box" required', response.data)
        self.assertIn(b'maxlength="120"', response.data)

    def test_error_flash_hides_details_and_shows_generic_message(self):
        with self.client.session_transaction() as session:
            session["_flashes"] = [("error", "Sensitive provider detail")]

        response = self.client.get("/signin")

        self.assertIn(b"We couldn't complete your request. Please try again.", response.data)
        self.assertIn(b'class="flash-detail" aria-hidden="true">Sensitive provider detail', response.data)

    def test_riskassessment_images_are_served(self):
        response = self.client.get(
            "/images/KYS_WO_HL_Horizontal.png"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/png")
        response.close()

    def test_create_code_page_renders(self):
        response = self.client.get("/create/code")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'action="/create/code"', response.data)

    def test_display_name_is_trimmed_and_sent_as_attribute(self):
        response = self.signup("  Test Person  ")
        self.assertEqual(response.location, "/signup/verify")
        self.auth_client.signup_start.assert_called_once_with(
            "person@example.com",
            "StrongPassword1!",
            attributes={"displayName": "Test Person"},
        )

    def test_display_name_is_required(self):
        response = self.signup("  ")
        self.assertEqual(response.location, "/signup")
        self.auth_client.signup_start.assert_not_called()

    def test_display_name_accepts_120_characters(self):
        response = self.signup("A" * 120)
        self.assertEqual(response.location, "/signup/verify")
        self.assertEqual(
            self.auth_client.signup_start.call_args.kwargs["attributes"],
            {"displayName": "A" * 120},
        )

    def test_display_name_rejects_more_than_120_characters(self):
        response = self.signup("A" * 121)
        self.assertEqual(response.location, "/signup")
        self.auth_client.signup_start.assert_not_called()


if __name__ == "__main__":
    unittest.main()