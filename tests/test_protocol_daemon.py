import unittest

from ghost_sniffer import Phase2ProtocolDaemon


class Phase2ProtocolDaemonTests(unittest.TestCase):
    def setUp(self):
        self.daemon = Phase2ProtocolDaemon(lambda *_: None)

    def test_open_network_is_critical(self):
        networks = [{"ssid": "CafeWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "rssi": -40, "encryption": "Open"}]
        results = self.daemon.analyze_networks(networks)
        self.assertEqual(len(results), 1)
        vuln_types = [v["type"] for v in results[0]["vulnerabilities"]]
        self.assertIn("No Encryption", vuln_types)
        self.assertGreaterEqual(results[0]["risk_score"], 9.0)

    def test_wep_network_is_critical(self):
        networks = [{"ssid": "LegacyNet", "bssid": "11:22:33:44:55:66", "channel": 1, "rssi": -60, "encryption": "WEP"}]
        results = self.daemon.analyze_networks(networks)
        vuln_types = [v["type"] for v in results[0]["vulnerabilities"]]
        self.assertIn("Deprecated Encryption", vuln_types)
        self.assertGreaterEqual(results[0]["risk_score"], 8.0)

    def test_wpa2_adds_wps_and_krack(self):
        networks = [{"ssid": "HomeWiFi", "bssid": "aa:aa:aa:aa:aa:aa", "channel": 11, "rssi": -65, "encryption": "WPA2"}]
        results = self.daemon.analyze_networks(networks)
        vuln_types = [v["type"] for v in results[0]["vulnerabilities"]]
        self.assertIn("WPS PIN Vulnerability", vuln_types)
        self.assertIn("KRACK Vulnerability (WPA2)", vuln_types)

    def test_weak_ssid_pattern(self):
        networks = [{"ssid": "default-router", "bssid": "00:00:00:00:00:01", "channel": 3, "rssi": -70, "encryption": "WPA2"}]
        results = self.daemon.analyze_networks(networks)
        vuln_types = [v["type"] for v in results[0]["vulnerabilities"]]
        self.assertIn("Weak SSID Pattern", vuln_types)


if __name__ == "__main__":
    unittest.main()
