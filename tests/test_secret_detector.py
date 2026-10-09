
import unittest

from analyzer.repository_analyzer import detect_hardcoded_secrets


class TestSecretDetector(unittest.TestCase):

    def test_html_password_input_is_not_a_secret(self):
        content = '<input type="password" placeholder="password">'

        findings = detect_hardcoded_secrets(content)

        self.assertEqual(findings, [])

    def test_placeholder_credential_is_ignored(self):
        content = 'api_key = "your_api_key"'

        findings = detect_hardcoded_secrets(content)

        self.assertEqual(findings, [])

    def test_hardcoded_credential_is_flagged(self):
        content = 'password = "sample-secret-value"'

        findings = detect_hardcoded_secrets(content)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["type"],
            "Potential Hardcoded Secret"
        )
        self.assertEqual(findings[0]["keyword"], "password")
        self.assertEqual(findings[0]["line"], 1)
        self.assertNotIn("sample-secret-value", str(findings))

    def test_comment_is_ignored(self):
        content = '# password = "sample-secret-value"'

        findings = detect_hardcoded_secrets(content)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()