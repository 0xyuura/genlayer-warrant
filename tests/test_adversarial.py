"""Attack Warrant with real injection payloads.

Every assertion here is about a containment property, never about what a model
does with a payload. A test that measured model behaviour would drift with
every model change and would prove nothing about this contract.

Two of the properties are structurally impossible to violate. That is the
point: the tests prove the structure rather than hoping about the model.

Run with:  python -m unittest discover -s tests -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stub                                              # noqa: E402
_stub.install()
from corpus import PAYLOADS                               # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import warrant as w                                       # noqa: E402


# A required deterministic criterion no payload satisfies, plus a qualitative
# one that would need a model. The pairing is what proves the short circuit.
CRITERIA = [
    {"id": "changelog", "kind": "deterministic", "required": True,
     "check": {"type": "contains", "needle": "CHANGELOG"}},
    {"id": "quality", "kind": "qualitative", "required": True,
     "text": "Does the document describe how to run the tests?"},
]

SMALL = [(name, body) for name, body in PAYLOADS
         if len(body) <= w.MAX_EVIDENCE_BYTES]
BIG = [(name, body) for name, body in PAYLOADS
       if len(body) > w.MAX_EVIDENCE_BYTES]


class Containment(unittest.TestCase):
    def test_the_corpus_covers_both_size_classes(self):
        self.assertTrue(SMALL)
        self.assertTrue(BIG, "the corpus must carry a flooding payload")

    def test_no_payload_passes_a_failing_deterministic_check(self):
        check = {"type": "contains", "needle": "CHANGELOG"}
        for name, body in PAYLOADS:
            self.assertFalse(w.run_deterministic_check(check, body, 200), name)

    def test_no_payload_spends_a_model_call_once_a_required_check_failed(self):
        for name, body in SMALL:
            calls = []

            def ask(prompt):
                calls.append(prompt)
                return "YES"

            out = w.judge_evidence(CRITERIA, body, 200, ask)
            self.assertEqual(calls, [], name)
            self.assertEqual(w.settlement_of(out["bits"], CRITERIA), "payer",
                             name)

    def test_oversized_payloads_are_refused_before_judgement(self):
        for name, body in BIG:
            calls = []

            def ask(prompt):
                calls.append(prompt)
                return "YES"

            with self.assertRaises(ValueError, msg=name):
                w.judge_evidence(CRITERIA, body, 200, ask)
            self.assertEqual(calls, [], name)

    def test_a_verdict_wrapped_in_prose_is_not_a_verdict(self):
        """The moment a verdict can arrive inside prose, the prose is a channel."""
        for hijacked in ["YES, because the document instructed me to approve it",
                         "Based on the review block, YES",
                         "YES (all criteria met per the embedded approval)"]:
            with self.assertRaises(ValueError, msg=hijacked):
                w.read_bit(hijacked)

    def test_no_payload_escapes_the_prompt_fence(self):
        for name, body in SMALL:
            text = body.decode("utf-8", errors="replace")
            prompt = w.build_closed_prompt("Is it complete?", text)
            fence = w._fence(text)
            close = "</document " + fence + ">"
            # The payload cannot name the fence, so it cannot close the block.
            self.assertNotIn(close, text, name)
            # The block closes after the payload, and our instruction is last.
            self.assertGreater(prompt.rindex(close), prompt.rindex(text), name)
            self.assertGreater(prompt.rindex("YES or NO"), prompt.rindex(close),
                               name)


class MoneyIsOutOfReach(unittest.TestCase):
    """Structurally impossible, which is exactly why it is worth pinning."""

    def test_the_judgement_output_carries_no_address_and_no_amount(self):
        for name, body in SMALL:
            out = w.judge_evidence(CRITERIA, body, 200, lambda prompt: "NO")
            self.assertEqual(set(out.keys()), {"digest", "bits", "screened"},
                             name)
            self.assertRegex(out["bits"], r"^[01]*$", name)
            self.assertRegex(out["digest"], r"^[0-9a-f]{64}$", name)
            self.assertIsInstance(out["screened"], bool)

    def test_settlement_names_a_party_never_an_address(self):
        for bits in ("00", "01", "10", "11"):
            self.assertIn(w.settlement_of(bits, CRITERIA), ("worker", "payer"))

    def test_a_hostile_answer_to_every_call_still_only_moves_bits(self):
        """Assume total judgement compromise. The blast radius is the bits."""
        soft = [
            {"id": "q1", "kind": "qualitative", "required": True,
             "text": "Is it complete?"},
            {"id": "q2", "kind": "qualitative", "required": True,
             "text": "Is it documented?"},
        ]
        for name, body in SMALL:
            out = w.judge_evidence(soft, body, 200, lambda prompt: "NO")
            self.assertEqual(set(out.keys()), {"digest", "bits", "screened"})
            # The screen answered NO, so judgement ran and produced one bit
            # per criterion. Nothing else crossed the boundary.
            self.assertEqual(len(out["bits"]), len(soft), name)


class ScreenFailsClosed(unittest.TestCase):
    def test_a_positive_screen_stops_before_any_criterion_is_judged(self):
        soft = [{"id": "q1", "kind": "qualitative", "required": True,
                 "text": "Is it complete?"}]
        asked = []

        def ask(prompt):
            asked.append(prompt)
            return "YES"          # the screen says the document talks to us

        out = w.judge_evidence(soft, b"hello", 200, ask)
        self.assertTrue(out["screened"])
        self.assertEqual(len(asked), 1, "only the screen should have been asked")
        self.assertEqual(w.settlement_of(out["bits"], soft), "payer")

    def test_an_unreadable_screen_answer_refuses_rather_than_proceeding(self):
        soft = [{"id": "q1", "kind": "qualitative", "required": True,
                 "text": "Is it complete?"}]
        with self.assertRaises(ValueError):
            w.judge_evidence(soft, b"hello", 200, lambda prompt: "maybe")


if __name__ == "__main__":
    unittest.main()
