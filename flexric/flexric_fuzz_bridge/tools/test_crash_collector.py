import os, tempfile, unittest
import crash_collector as cc

ASSERT_LINE = ("nearRT-RIC: /home/x/flexric/src/lib/e2ap/e2ap_msg_dec_asn.c:2375: "
               "e2ap_dec_e42_setup_request: Assertion `ran_list->criticality == "
               "Criticality_reject' failed.")

class TestCollector(unittest.TestCase):
    def test_assertion_signature_normalizes_to_basename(self):
        sig = cc.assertion_signature(ASSERT_LINE)
        self.assertEqual(sig, "e2ap_msg_dec_asn.c:2375: e2ap_dec_e42_setup_request: "
                              "Assertion `ran_list->criticality == Criticality_reject' failed")

    def test_non_assertion_line_returns_none(self):
        self.assertIsNone(cc.assertion_signature("just a log line"))

    def test_backtrace_signature_uses_top_flexric_frame(self):
        block = ["=== FATAL signal SIGSEGV backtrace ===",
                 "/lib/x.so(+0x1)[0x1]",
                 "/home/x/flexric/build-cov/examples/ric/nearRT-RIC(e2ap_dec_x+0x4c)[0xdead]",
                 "=== end backtrace ==="]
        sig = cc.backtrace_signature(block, "SIGSEGV")
        self.assertTrue(sig.startswith("SIGSEGV in e2ap_dec_x"))

    def test_dedup_only_new_signatures_write_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "unique_crashes_timeseries.csv")
            dd = cc.CrashDedup(p, t0=1000.0)
            self.assertTrue(dd.observe("sigA", now=1000.0))   # new -> row 1
            self.assertFalse(dd.observe("sigA", now=1100.0))  # dup -> no row
            self.assertTrue(dd.observe("sigB", now=1130.0))   # new -> row 2
            rows = open(p).read().strip().splitlines()
            self.assertEqual(rows[0], "elapsed_min,timestamp,cumulative_unique,signature")
            self.assertEqual(len(rows), 3)                    # header + 2
            self.assertTrue(rows[1].startswith("0,"))
            self.assertIn(',1,"sigA"', rows[1])
            self.assertIn(',2,"sigB"', rows[2])
            # Verify timestamp is bare (not quoted) and signature is always quoted
            import re
            self.assertIsNotNone(re.match(r'^0,\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},1,"sigA"$', rows[1]))
            self.assertIsNotNone(re.match(r'^\d+,\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},2,"sigB"$', rows[2]))

if __name__ == "__main__":
    unittest.main()
