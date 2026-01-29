import unittest

from ghost_sniffer import Phase4VulnerabilityCartograph


class Phase4VulnerabilityCartographTests(unittest.TestCase):
    def test_report_summary_and_ranking(self):
        cartograph = Phase4VulnerabilityCartograph(lambda *_: None)
        networks = [
            {"ssid": "OpenNet", "bssid": "aa:bb:cc:dd:ee:01", "channel": 1, "rssi": -40, "encryption": "Open"},
            {"ssid": "SecureNet", "bssid": "aa:bb:cc:dd:ee:02", "channel": 6, "rssi": -80, "encryption": "WPA3"},
        ]
        analyses = [
            {"network": networks[0], "risk_score": 9.1, "vulnerabilities": [{"severity": "Critical"}], "security_recommendations": []},
            {"network": networks[1], "risk_score": 3.0, "vulnerabilities": [{"severity": "Medium"}], "security_recommendations": []},
        ]
        exploits = [
            {"compromised": True, "exploits_attempted": [], "exploits_successful": [], "time_taken": 1},
            {"compromised": False, "exploits_attempted": [], "exploits_successful": [], "time_taken": 1},
        ]

        report = cartograph.generate_report(networks, analyses, exploits)
        summary = report["summary"]

        self.assertEqual(summary["total_networks"], 2)
        self.assertEqual(summary["vulnerable_networks"], 1)
        self.assertEqual(summary["compromised_networks"], 1)
        self.assertEqual(summary["critical_vulnerabilities"], 1)

        # Ensure highest risk is rank 1
        self.assertEqual(report["targets"][0]["network"]["ssid"], "OpenNet")


if __name__ == "__main__":
    unittest.main()
