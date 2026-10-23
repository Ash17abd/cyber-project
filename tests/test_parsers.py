"""Unit tests for File Ingestion and Parsers."""

import unittest
from modules.upload import FileIngestionEngine
from modules.utils import SampleDataGenerator

class TestParsers(unittest.TestCase):

    def test_apache_log_parser(self):
        log_text = SampleDataGenerator.generate_apache_attack_logs()
        df = FileIngestionEngine.parse_apache_nginx(log_text)
        self.assertFalse(df.empty)
        self.assertIn("source_ip", df.columns)
        self.assertIn("details", df.columns)
        self.assertGreater(len(df), 5)

    def test_json_log_parser(self):
        json_text = SampleDataGenerator.generate_json_firewall_logs()
        df = FileIngestionEngine.parse_json_logs(json_text)
        self.assertFalse(df.empty)
        self.assertIn("source_ip", df.columns)
        self.assertEqual(len(df), 8)

    def test_csv_with_location_columns(self):
        csv_data = (
            "Source IP,Destination IP,Country,City,Latitude,Longitude,ISP,Event\n"
            "185.220.101.5,10.0.0.1,Netherlands,Amsterdam,52.3676,4.9041,Zappie Host,BruteForce\n"
            "203.0.113.19,10.0.0.2,Germany,Frankfurt,50.1109,8.6821,Hetzner,PortScan\n"
        )
        res = FileIngestionEngine.ingest_file("threat_intel_feed.csv", csv_data.encode('utf-8'))
        df = res["events_df"]
        self.assertFalse(df.empty)
        self.assertEqual(df.iloc[0]["source_ip"], "185.220.101.5")
        self.assertEqual(df.iloc[0]["country"], "Netherlands")
        self.assertEqual(df.iloc[0]["city"], "Amsterdam")
        self.assertEqual(df.iloc[0]["latitude"], 52.3676)
        self.assertEqual(df.iloc[0]["longitude"], 4.9041)

    def test_resilient_ip_column_matching(self):
        # Test headers with spaces, capitals, and alternative names
        csv_data = (
            "Source IP Address,Target IP,Message\n"
            "45.33.32.156,192.168.1.1,Suspicious port probe\n"
        )
        res = FileIngestionEngine.ingest_file("custom_firewall.csv", csv_data.encode('utf-8'))
        df = res["events_df"]
        self.assertEqual(df.iloc[0]["source_ip"], "45.33.32.156")
        self.assertEqual(df.iloc[0]["destination_ip"], "192.168.1.1")

if __name__ == "__main__":
    unittest.main()
