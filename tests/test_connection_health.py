import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from connection_health import ConnectionHealth

class ConnectionHealthTests(unittest.TestCase):
    def test_first_failure_does_not_invent_a_known_outage(self):
        h=ConnectionHealth();s=h.observe(False)
        self.assertIsNone(s['vpn_ok']);self.assertTrue(s['degraded'])
    def test_transient_failure_keeps_last_success_but_reports_degradation(self):
        h=ConnectionHealth();h.observe(True);s=h.observe(False)
        self.assertTrue(s['vpn_ok']);self.assertTrue(s['degraded'])
        s=h.observe(True);self.assertFalse(s['degraded']);self.assertEqual(s['consecutive_failures'],0)
    def test_sustained_outage_is_not_hidden(self):
        h=ConnectionHealth();h.observe(True)
        for _ in range(3):s=h.observe(False)
        self.assertFalse(s['vpn_ok']);self.assertEqual(s['consecutive_failures'],3)
        self.assertTrue(h.observe(True)['vpn_ok'])
    def test_alternating_results_never_accumulate_into_sustained_failure(self):
        h=ConnectionHealth()
        for _ in range(5):
            h.observe(True);h.observe(False)
        self.assertEqual(h.failures,1);self.assertTrue(h.healthy)
