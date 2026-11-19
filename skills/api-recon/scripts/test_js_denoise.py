#!/usr/bin/env python3
"""P6 夹具：JS 去噪/端点提取/与 1.5.0 结果去重/手动与自动一致性。"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import js_denoise_extract as m  # noqa: E402


OBFUSCATED_JS = r"""
/* webpack chunk: noise */
//# sourceMappingURL=app.js.map
const a="data:image/png;base64,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const b="QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="; // 40+ base64 noise
// 真正的接口字面量
fetch("/api/web/user/list", {method:"GET"});
axios.post('/api/web/role_permissions', {pageSize: 20, keyword: "x"});
var routeMap={MONITOR:{name:"监控",link:"/monitor/index"}};
"""


class DenoiseTests(unittest.TestCase):
    def test_strip_noise_keeps_endpoints(self):
        cleaned = m.strip_js_noise(OBFUSCATED_JS)
        self.assertIn('"/api/web/user/list"', cleaned)
        self.assertNotIn("sourceMappingURL", cleaned)
        self.assertNotIn("webpack chunk", cleaned)
        self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", cleaned)

    def test_extract_endpoints_from_obfuscated_js(self):
        eps = m.extract_endpoints(OBFUSCATED_JS)
        self.assertIn("/api/web/user/list", eps)
        self.assertIn("/api/web/role_permissions", eps)
        self.assertNotIn("/monitor/index", eps)  # 前端路由不是 API 端点

    def test_extract_params_and_route_map(self):
        params = m.extract_params(OBFUSCATED_JS)
        self.assertIn("pageSize", params)
        self.assertIn("keyword", params)
        routes = m.extract_route_map(OBFUSCATED_JS)
        self.assertEqual(routes.get("MONITOR"), "/monitor/index")

    def test_dedupe_against_1_5_0_dir_enum(self):
        # 1.5.0 目录枚举已拿到 /api/web/user/list（带查询串），自动路不该重复报。
        eps = m.extract_endpoints(OBFUSCATED_JS)
        existing = {m.normalize_path("https://target.example/api/web/user/list?page=1")}
        added = m.dedupe_against_existing(eps, existing)
        self.assertNotIn("/api/web/user/list", added)
        self.assertIn("/api/web/role_permissions", added)

    def test_manual_and_auto_outputs_identical(self):
        # 同目标手动（直接调函数）与自动（CLI）两路产出逐字节一致。
        eps = m.extract_endpoints(OBFUSCATED_JS)
        params = m.extract_params(OBFUSCATED_JS)
        routes = m.extract_route_map(OBFUSCATED_JS)
        manual = m.build_result(eps, params, routes, set())

        with tempfile.TemporaryDirectory() as d:
            js_path = os.path.join(d, "bundle.js")
            with open(js_path, "w", encoding="utf-8") as f:
                f.write(OBFUSCATED_JS)
            out_path = os.path.join(d, "auto.json")
            subprocess.run(
                [sys.executable, os.path.join(os.path.dirname(__file__), "js_denoise_extract.py"),
                 js_path, "--out", out_path],
                check=True, capture_output=True,
            )
            with open(out_path, encoding="utf-8") as f:
                auto = json.load(f)
        self.assertEqual(manual, auto)

    def test_normalize_path(self):
        self.assertEqual(m.normalize_path("https://h/a/api/x?id=1"), "/a/api/x")
        self.assertEqual(m.normalize_path("/api/user/{id}/"), "/api/user/{}")
        self.assertEqual(m.normalize_path("/api/user/:id"), "/api/user/{}")


if __name__ == "__main__":
    unittest.main()
