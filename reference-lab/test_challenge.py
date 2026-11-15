"""Check the proposed Cloudflare rule and the standalone loopback origin."""

import json
from pathlib import Path
import unittest

from test_lab import Links, NginxLabTestCase


HERE = Path(__file__).resolve().parent


class ChallengeRuleTests(unittest.TestCase):
    def test_rule_limits_match_to_two_read_only_routes_at_one_placeholder_host(self):
        rule = json.loads((HERE / "challenge-rule.json").read_text(encoding="utf-8"))
        # Review the actual provider expression. A local match emulator could
        # hide drift or disagree with how Cloudflare normalizes requests.
        self.assertEqual(
            rule["expression"],
            '(lower(http.host) eq "challenge-lab.example.org"'
            ' and http.request.method in {"GET" "HEAD"}'
            ' and http.request.uri.path in {"/reading-room" "/reading-room/complete"})',
        )
        self.assertEqual(rule["action"], "managed_challenge")
        self.assertIs(rule["enabled"], False)


class ChallengeOriginTests(NginxLabTestCase):
    routes_file = HERE / "challenge-routes.conf"
    startup_path = "/reading-room"

    def test_reading_room_and_first_party_completion(self):
        status, headers, body = self.request("GET", "/reading-room")
        self.assert_page(status, headers, body)
        self.assertIn(b"open from 9 a.m. to 5 p.m.", body)
        links = Links()
        links.feed(body.decode("utf-8"))
        self.assertEqual(links.destinations, ["/reading-room/complete"])
        status, headers, body = self.request("GET", links.destinations[0])
        self.assert_page(status, headers, body)
        self.assertIn(b"reading room is on the ground floor", body)
        links = Links()
        links.feed(body.decode("utf-8"))
        self.assertEqual(links.destinations, [])

    def assert_page(self, status, headers, body):
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Location", headers)
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("cf-mitigated", {name.lower() for name in headers})
        self.assertLess(len(body), 1024)

    def test_head_and_query_use_the_same_routes(self):
        for path in ("/reading-room", "/reading-room/complete"):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assert_page(status, headers, body)
                self.assertEqual(self.request("GET", f"{path}?example=ignored")[2], body)
                status, head_headers, head_body = self.request("HEAD", path)
                self.assertEqual((status, head_body), (200, b""))
                self.assertEqual(head_headers["Content-Length"], headers["Content-Length"])

    def test_origin_rejects_other_routes_and_methods(self):
        for path in (
            "/", "/normal", "/accepted", "/reading-room/", "/reading-room-copy",
            "/reading-room/complete/", "/Reading-room", "/%72eading-room",
            "/other/../reading-room", "/reading-room//complete", "/tls.key",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)
        for path in ("/reading-room", "/reading-room/complete"):
            with self.subTest(path=path):
                status, headers, _ = self.request("POST", path)
                self.assertEqual(status, 405)
                self.assertEqual(headers["Allow"], "GET, HEAD")


if __name__ == "__main__":
    unittest.main(catchbreak=True)
