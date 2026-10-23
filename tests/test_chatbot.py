"""Unit tests for AI SOC Autonomous Agent & Chatbot Engine."""

import unittest
import pandas as pd
from modules.chatbot import SOCChatbot

class TestSOCChatbot(unittest.TestCase):

    def setUp(self):
        self.threats = [
            {
                "threat_name": "SQL Injection",
                "severity": "Critical",
                "confidence": 95.0,
                "source_ip": "198.51.100.45",
                "destination_ip": "10.0.0.1",
                "timestamp": "2026-09-19T10:00:00",
                "evidence": "UNION SELECT null, username, password FROM users",
                "mitre_id": "T1190",
                "mitre_technique": "Exploit Public-Facing Application",
                "kill_chain_stage": "Exploitation"
            },
            {
                "threat_name": "Brute Force Attack",
                "severity": "High",
                "confidence": 90.0,
                "source_ip": "185.220.101.5",
                "destination_ip": "10.0.0.1",
                "timestamp": "2026-09-19T10:10:00",
                "evidence": "7 consecutive failed logins",
                "mitre_id": "T1110",
                "mitre_technique": "Brute Force",
                "kill_chain_stage": "Exploitation"
            }
        ]
        self.risk_data = {
            "score": 88.5,
            "level": "Critical",
            "breakdown": {"Critical": 1, "High": 1, "Medium": 0, "Low": 0, "Info": 0},
            "recommendations": [
                "🚨 P0 IMMEDIATE: Isolate hostile IP 198.51.100.45",
                "🛡️ P2 HIGH: Apply WAF SQL injection blocking rule"
            ]
        }
        self.malware_data = [{
            "family": "Ransomware",
            "likelihood": "85%",
            "likelihood_value": 85,
            "severity": "Critical",
            "description": "Ransomware pre-encryption indicators",
            "indicators": ["vssadmin shadow deletion"],
            "mitigation": "Disconnect backup storage"
        }]
        self.uploaded_files = [{
            "filename": "apache_attack_access.log",
            "file_type": "Apache Access Log",
            "records_count": 120,
            "file_size": 4096,
            "file_hash": "a1b2c3d4e5f6"
        }]
        self.combined_df = pd.DataFrame([
            {
                "timestamp": "2026-09-19T10:00:00",
                "source_ip": "198.51.100.45",
                "destination_ip": "10.0.0.1",
                "url": "/login.php?user=admin' UNION SELECT password",
                "details": "SQL Injection probe",
                "raw_log": "GET /login.php?user=admin' UNION SELECT password HTTP/1.1"
            }
        ])

    def test_greeting_intent(self):
        resp = SOCChatbot.respond("Hello! What can you do?", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Cyber Sentinel", resp)
        self.assertIn("88.5/100", resp)

    def test_ip_lookup_intent(self):
        resp = SOCChatbot.respond("Why is 198.51.100.45 suspicious?", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("198.51.100.45", resp)
        self.assertIn("SQL Injection", resp)
        self.assertIn("iptables", resp)

    def test_agent_action_block_ip(self):
        resp = SOCChatbot.respond("block ip 198.51.100.45", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("IP Quarantine Executed", resp)
        self.assertIn("iptables", resp)
        self.assertIn("198.51.100.45", resp)

    def test_agent_action_sigma_rule(self):
        resp = SOCChatbot.respond("generate sigma rule for SQL Injection", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Sigma Detection Rule", resp)
        self.assertIn("UNION", resp)
        self.assertIn("yaml", resp)

    def test_agent_action_search_logs(self):
        resp = SOCChatbot.respond("search logs for UNION", self.threats, self.risk_data, self.malware_data, self.uploaded_files, combined_df=self.combined_df)
        self.assertIn("Telemetry Search Results", resp)
        self.assertIn("198.51.100.45", resp)

    def test_agent_action_draft_email(self):
        resp = SOCChatbot.respond("draft email to CISO", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Executive Incident Response Notification", resp)
        self.assertIn("Subject", resp)

    def test_general_knowledge_zero_trust(self):
        resp = SOCChatbot.respond("Explain Zero Trust Architecture", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Zero Trust Architecture", resp)
        self.assertIn("NIST SP 800-207", resp)

    def test_general_knowledge_nmap(self):
        resp = SOCChatbot.respond("Give me an nmap cheat sheet", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Nmap", resp)
        self.assertIn("-sS", resp)

    def test_emoji_prefixed_queries(self):
        # 1. Search logs with emoji
        resp_search = SOCChatbot.respond("🔍 Search logs for UNION", self.threats, self.risk_data, self.malware_data, self.uploaded_files, combined_df=self.combined_df)
        self.assertIn("Telemetry Search Results", resp_search)
        self.assertIn("UNION", resp_search)

        # 2. Block IP with emoji
        resp_block = SOCChatbot.respond("🛑 Block IP 198.51.100.45", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("IP Quarantine Executed", resp_block)
        self.assertIn("198.51.100.45", resp_block)

        # 3. Who is attacking us
        resp_attackers = SOCChatbot.respond("🔍 Who is attacking us?", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Hostile Adversary Source IPs Identified", resp_attackers)
        self.assertIn("198.51.100.45", resp_attackers)

        # 4. Malware indicators
        resp_malware = SOCChatbot.respond("🧬 Explain detected malware indicators", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Detected Malware Indicators", resp_malware)
        self.assertIn("Ransomware", resp_malware)

        # 5. MITRE techniques
        mitre_data = {"tactics_count": {"Initial Access": 1}, "techniques_observed": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "detections": 1}]}
        resp_mitre = SOCChatbot.respond("🎯 Which MITRE techniques were used?", self.threats, self.risk_data, self.malware_data, self.uploaded_files, mitre_data=mitre_data)
        self.assertIn("MITRE ATT&CK Framework Telemetry Mapping", resp_mitre)
        self.assertIn("T1190", resp_mitre)

        # 6. Kill chain status
        kill_chain_data = {"progression_percentage": 57, "max_active_stage": "Exploitation", "stage_counts": {"Exploitation": 2}}
        resp_kc = SOCChatbot.respond("⚡ What is our Cyber Kill Chain status?", self.threats, self.risk_data, self.malware_data, self.uploaded_files, kill_chain_data=kill_chain_data)
        self.assertIn("Active Cyber Kill Chain Intrusion Status", resp_kc)
        self.assertIn("57%", resp_kc)

    def test_location_query(self):
        resp = SOCChatbot.respond("Where are the attacks coming from?", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Geographic Origin", resp)
        self.assertIn("198.51.100.45", resp)
        self.assertIn("Russia", resp)

    def test_deployment_query(self):
        resp = SOCChatbot.respond("How do I deploy on Streamlit and Vercel?", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Streamlit", resp)
        self.assertIn("Vercel", resp)

    def test_total_threats_query(self):
        resp = SOCChatbot.respond("How many threats are detected?", self.threats, self.risk_data, self.malware_data, self.uploaded_files)
        self.assertIn("Total Identified Incidents", resp)
        self.assertIn("2 threats", resp)

if __name__ == "__main__":
    unittest.main()
