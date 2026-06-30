import os, tempfile, unittest
import coverage_sampler as cs

class TestSampler(unittest.TestCase):
    def test_parse_summary_picks_branches_as_edges(self):
        js = '{"line_total":6300,"line_covered":4204,"branch_total":5000,"branch_covered":1729}'
        edges, lines = cs.parse_gcovr_summary(js)
        self.assertEqual(edges, 1729)   # branches -> edges
        self.assertEqual(lines, 4204)

    def test_parse_summary_missing_keys_is_zero(self):
        edges, lines = cs.parse_gcovr_summary('{}')
        self.assertEqual((edges, lines), (0, 0))

    def test_append_row_writes_header_then_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "coverage_timeseries.csv")
            cs.append_row(p, 0, 1729, 4204)
            cs.append_row(p, 30, 2776, 6233)
            lines = open(p).read().strip().splitlines()
            self.assertEqual(lines[0], "elapsed_min,covered_edges,covered_lines")
            self.assertEqual(lines[1], "0,1729,4204")
            self.assertEqual(lines[2], "30,2776,6233")

if __name__ == "__main__":
    unittest.main()
