import io
import unittest
from contextlib import redirect_stdout

import dork_tool


class DorkToolTests(unittest.TestCase):
    def test_list_categories_prints_known_categories(self):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = dork_tool.main(["--list-categories"])

        self.assertEqual(exit_code, 0)
        printed = output.getvalue().strip().splitlines()
        self.assertIn("social_media", printed)
        self.assertIn("email_phone", printed)
        self.assertIn("data_breaches", printed)

    def test_dry_run_generates_expected_queries(self):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = dork_tool.main(
                [
                    "--target",
                    "Jane Doe",
                    "--aliases",
                    "Jan Doe,J. Doe",
                    "--usernames",
                    "janedoe99,j_doe",
                    "--socials",
                    "twitter:janedoe,github:janedoe99",
                    "--org",
                    "Acme Corp",
                    "--location",
                    "New York",
                    "--categories",
                    "social_media,email_phone,data_breaches",
                    "--max-total",
                    "80",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        lines = output.getvalue().strip().splitlines()
        self.assertGreater(len(lines), 0)
        self.assertLessEqual(len(lines), 80)
        self.assertTrue(any("site:twitter.com" in q for q in lines))
        self.assertTrue(any("leak" in q or "breach" in q for q in lines))

    def test_invalid_category_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            dork_tool.main(["--target", "Jane Doe", "--categories", "unknown"])
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
