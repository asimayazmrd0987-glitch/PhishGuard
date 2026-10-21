import unittest
from meeting_capture.capture import slugify, utc_now_iso


class CaptureHelperTests(unittest.TestCase):
    def test_slugify_normal_name(self):
        self.assertEqual(slugify("Weekly Team Meeting!"), "weekly-team-meeting")

    def test_slugify_empty_name(self):
        self.assertEqual(slugify("  !!!  "), "meeting")

    def test_slugify_limits_length(self):
        self.assertLessEqual(len(slugify("A" * 200)), 48)

    def test_utc_now_iso_has_timezone(self):
        stamp = utc_now_iso()
        self.assertIn("T", stamp)
        self.assertTrue(stamp.endswith("+00:00") or "+" in stamp[10:] or stamp.endswith("Z"))


if __name__ == "__main__":
    unittest.main()
