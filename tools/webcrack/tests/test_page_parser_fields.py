#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for login-field detection, including the type-based fallback.

Run from the repository root:
    python3 -m unittest discover -s tools/webcrack/tests -v
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from bs4 import BeautifulSoup as BS

from src.core.page_parser import PageParser

CONFIG = {
    "parser": {
        "username_keywords": ["user", "name", "account", "mail"],
        "password_keywords": ["pass", "pwd"],
        "default_value": "test",
    }
}


def parser_for(html):
    p = PageParser.__new__(PageParser)
    p.config = CONFIG
    p.captcha_input_name = None
    p.captcha_value = None
    p.form_content = BS("<root>" + html + "</root>", "lxml")
    p.username_field = ""
    p.password_field = ""
    p.form_data = {}
    return p


class GuessFieldsByTypeTest(unittest.TestCase):
    def test_keyword_hit_does_not_need_fallback(self):
        p = parser_for('<form><input name="username"><input type="password" name="password"></form>')
        p._parse_form_parameters()
        self.assertEqual(p.username_field, "username")
        self.assertEqual(p.password_field, "password")

    def test_obfuscated_names_fall_back_to_input_types(self):
        p = parser_for('<form method="post" action="/login"><input name="u"><input type="password" name="p"></form>')
        p._parse_form_parameters()
        self.assertEqual(p.username_field, "u")
        self.assertEqual(p.password_field, "p")
        self.assertIn("u", p.form_data)
        self.assertIn("p", p.form_data)

    def test_hidden_and_submit_inputs_are_not_account_fields(self):
        p = parser_for('<form><input type="hidden" name="csrf"><input type="submit" name="go">'
                       '<input type="password" name="key"></form>')
        user, pwd = p._guess_fields_by_type(p.form_content)
        self.assertEqual(user, "")
        self.assertEqual(pwd, "")

    def test_text_field_before_password_is_the_account(self):
        p = parser_for('<form><input type="hidden" name="csrf"><input name="login">'
                       '<input type="password" name="secret"><input type="submit"></form>')
        user, pwd = p._guess_fields_by_type(p.form_content)
        self.assertEqual(user, "login")
        self.assertEqual(pwd, "secret")

    def test_no_password_input_raises(self):
        p = parser_for('<form><input name="u"><input name="p"></form>')
        with self.assertRaises(Exception):
            p._parse_form_parameters()


if __name__ == "__main__":
    unittest.main()
