"""Regression checks without elevation or external network calls.

Run: python -m unittest discover -s tools/nettrace -p test_nettrace.py
"""
import contextlib
import io
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import nettrace as nt


class NettraceTests(unittest.TestCase):
    def test_process_name_failure_retried_and_pid_reuse_expires(self):
        resolver = nt.ProcResolver()
        with patch.object(nt.time, "monotonic", return_value=10) as clock, \
                patch.object(resolver, "_query", side_effect=[None, "RocketLeague", "other"]) as query:
            self.assertIsNone(resolver.name(123))
            self.assertIsNone(resolver.name(123))
            self.assertEqual(query.call_count, 1)
            clock.return_value = 10.6
            self.assertEqual(resolver.name(123), "RocketLeague")
            clock.return_value = 13
            self.assertEqual(resolver.name(123), "other")

    def test_failed_lookup_unknown_then_retried(self):
        mt = nt.MTClient("http://unused/lookup", True)
        response = types.SimpleNamespace(raise_for_status=lambda: None,
            json=lambda: {"results": [{"query": "8.8.8.8", "rule_hits": [], "ipset_hits": []}]})
        with patch.object(nt.time, "monotonic", return_value=10) as clock, \
                patch.object(nt.requests, "post", side_effect=[TimeoutError(), response]) as post:
            mt.annotate(["8.8.8.8"])
            self.assertEqual(mt.tag("8.8.8.8"), ("[MT:?]", False))
            self.assertIsNone(mt.is_covered("8.8.8.8"))
            mt.annotate(["8.8.8.8"])
            self.assertEqual(post.call_count, 1)
            clock.return_value = 16
            mt.annotate(["8.8.8.8"])
            self.assertEqual(mt.tag("8.8.8.8"), ("[MT:--]", False))
            self.assertIs(mt.is_covered("8.8.8.8"), False)

    def test_current_etw_loss_statistics(self):
        cap = nt.Capture.__new__(nt.Capture)
        cap._etw = types.SimpleNamespace(query=lambda: types.SimpleNamespace(EventsLost=7))
        self.assertEqual(cap.events_lost(), 7)
        cap._etw.query = lambda: (_ for _ in ()).throw(OSError())
        self.assertIsNone(cap.events_lost())

    def test_udp_send_and_receive_normalize_remote_endpoint(self):
        cap = nt.Capture.__new__(nt.Capture)
        cap.q = nt.Queue()
        cap._ids = {42, 43}
        cap.debug = False
        cap.swap_ports = False
        cap._on_event((42, dict(PID=123, daddr="8.8.8.8", dport=8097, size=10)))
        cap._on_event((43, dict(PID=123, saddr="1.1.1.1", sport=8098, size=20)))
        self.assertEqual(cap.q.get_nowait(), ("UDP", 123, "8.8.8.8", 8097, 10))
        self.assertEqual(cap.q.get_nowait(), ("UDP", 123, "1.1.1.1", 8098, 20))

    def test_stop_failure_is_not_reported_success(self):
        cap = types.SimpleNamespace(stop=lambda: False)
        self.assertFalse(nt._stop_capture(cap, timeout=1))

    def test_output_deadline_and_late_mt_annotation(self):
        mt = nt.MTClient("http://unused/lookup", True)
        geo = types.SimpleNamespace(enabled=False, _cache={})
        enricher = nt.Enricher(geo, None, None, mt, hold=5)
        entry = dict(ip="8.8.8.8", ready=True, detail="", hits=1, ts="12:00:00",
                     pname="RocketLeague", proto="UDP", port=8097, pid=123,
                     mt_tag="[MT:?]", mt_hit=False, country="", is_new=True)
        try:
            with patch.object(nt.time, "time", return_value=10) as clock:
                enricher.add(entry)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    enricher.flush()
                self.assertEqual(output.getvalue(), "")
                clock.return_value = 16
                with contextlib.redirect_stdout(output):
                    enricher.flush()
                self.assertIn("[MT:?]", output.getvalue())
                mt._cache["8.8.8.8"] = dict(groups="RL", in_ipset=True, has_hits=True)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    enricher._print(entry)
                self.assertIn("[MT:RL]", output.getvalue())
        finally:
            enricher.shutdown()

    def test_unknown_coverage_not_a_push_candidate_or_reported_missing(self):
        records = {"8.8.8.8": dict(count=2, covered=None),
                   "1.1.1.1": dict(count=2, covered=False)}
        subnets, _ = nt.aggregate(records, "32")
        self.assertEqual(set(subnets), {"1.1.1.1/32"})
        mt = nt.MTClient("http://unused/lookup", True)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            nt._summary({("UDP", 123, "8.8.8.8", 8097): 2}, mt,
                        types.SimpleNamespace(_cache={}))
        self.assertIn("coverage unknown", output.getvalue())
        self.assertNotIn("NOT in MagiTrickle", output.getvalue())
        self.assertNotIn("all non-RU", output.getvalue())

    def test_slow_lookup_does_not_block_capture_and_stop_flush_is_saved(self):
        lookup_started = threading.Event()
        release_lookup = threading.Event()
        emitted = []
        real_emit = nt._emit

        class Capture:
            def __init__(self, q, *args):
                self.q = q
            def start(self):
                def send():
                    time.sleep(0.02)
                    self.q.put(("UDP", 123, "8.8.8.8", 8097, 10))
                self.sender = threading.Thread(target=send)
                self.sender.start()
            def events_lost(self):
                return 0
            def stop(self):
                self.sender.join(timeout=1)
                self.q.put(("UDP", 123, "1.1.1.1", 8098, 10))

        def annotate(mt, ips):
            lookup_started.set()
            if not release_lookup.wait(2):
                raise AssertionError("capture processing blocked on MT")
            for ip in ips:
                mt._cache[ip] = dict(groups="RL", in_ipset=True, has_hits=True)

        def emit(*args):
            emitted.append(args[2])
            release_lookup.set()
            real_emit(*args)

        args = nt.build_parser().parse_args(["--mt-url", "http://unused/lookup", "--no-geo"])
        args.duration = 0.05
        with tempfile.TemporaryDirectory() as tmp:
            args.tsv = str(Path(tmp) / "capture.tsv")
            with patch.object(nt, "Capture", Capture), \
                    patch.object(nt.MTClient, "annotate", annotate), \
                    patch.object(nt, "_emit", emit), \
                    patch.object(nt, "ProcResolver", return_value=types.SimpleNamespace(name=lambda pid: "RocketLeague")), \
                    contextlib.redirect_stdout(io.StringIO()):
                nt.run(args)
            self.assertTrue(lookup_started.is_set())
            self.assertEqual(emitted, ["8.8.8.8", "1.1.1.1"])
            log = Path(args.tsv).read_text(encoding="utf-8")
            self.assertIn("8.8.8.8", log)
            self.assertIn("1.1.1.1", log)


if __name__ == "__main__":
    unittest.main()
