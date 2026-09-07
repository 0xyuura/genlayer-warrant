"""Structural assertions about the contract itself.

The contract class only runs inside GenVM, so these tests do not exercise it.
They assert the properties the whole claim rests on, which are properties of
shape rather than of behaviour:

  * no method that moves money reads a model,
  * exactly one method is nondeterministic,
  * everything that votes is reachable at module level,
  * settlement pushes nothing and withdrawal clears before it sends.

A shape test is worth having precisely because these are the invariants a
later edit is most likely to break quietly.

Run with:  python -m unittest discover -s tests -v
"""

import inspect
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _stub                                              # noqa: E402
_stub.install()

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import warrant as w                                       # noqa: E402


MONEY_METHODS = ("settle", "withdraw", "release", "reclaim")
MODEL_MARKERS = ("exec_prompt", "run_nondet_unsafe", "nondet")

VOTING_FUNCTIONS = (
    "parse_criteria", "canonical_criteria", "criteria_digest",
    "run_deterministic_check", "build_closed_prompt", "screen_prompt",
    "read_bit", "results_agree", "settlement_of", "judge_evidence",
)


class MoneyNeverMeetsAModel(unittest.TestCase):
    def test_no_money_method_mentions_a_model_call(self):
        for name in MONEY_METHODS:
            src = inspect.getsource(getattr(w.Warrant, name))
            for marker in MODEL_MARKERS:
                self.assertNotIn(marker, src, "%s touches %s" % (name, marker))

    def test_exactly_one_method_is_nondeterministic(self):
        hits = []
        for name, member in inspect.getmembers(w.Warrant, inspect.isfunction):
            # Python 3.14 attaches __annotate_func__, whose source is the whole
            # class body, so every marker in the class appears to be in it.
            if name.startswith("__"):
                continue
            try:
                src = inspect.getsource(member)
            except (TypeError, OSError):
                continue
            if "run_nondet_unsafe" in src:
                hits.append(name)
        self.assertEqual(hits, ["adjudicate"])

    def test_the_recipient_and_amount_are_only_ever_read_from_storage(self):
        src = inspect.getsource(w.Warrant.withdraw)
        self.assertIn("recipient = job.entitled", src)
        self.assertIn("amount = job.amount", src)


class VotingCodeIsReachable(unittest.TestCase):
    def test_every_rule_that_votes_is_module_level(self):
        for name in VOTING_FUNCTIONS:
            self.assertTrue(callable(getattr(w, name, None)), name)

    def test_the_agreement_rule_is_not_defined_inside_adjudicate(self):
        src = inspect.getsource(w.Warrant.adjudicate)
        self.assertNotIn("def results_agree", src)
        self.assertIn("results_agree(", src)


class PullNotPush(unittest.TestCase):
    def test_settle_emits_no_transfer(self):
        self.assertNotIn("emit_transfer", inspect.getsource(w.Warrant.settle))

    def test_withdraw_clears_entitlement_before_emitting(self):
        src = inspect.getsource(w.Warrant.withdraw)
        self.assertLess(src.index("job.entitled = Address(ZERO_ADDRESS)"),
                        src.index("emit_transfer"))

    def test_withdraw_closes_the_job_before_emitting(self):
        src = inspect.getsource(w.Warrant.withdraw)
        self.assertLess(src.index("job.state = STATE_CLOSED"),
                        src.index("emit_transfer"))


class StorageValuesAreConvertedBeforeStdlibUse(unittest.TestCase):
    """A GenVM storage value is not a plain Python str.

    Handing one straight to json.loads kills the transaction before the
    consensus block runs at all, and the trace shows zero web and zero model
    calls, which reads like a network problem and is not one. Two adjudications
    were lost to this. The rule is cheap to keep and expensive to rediscover.
    """

    # Names that come from storage or from calldata. Values produced inside
    # the method, like the leader's own return, are ordinary Python and need
    # no conversion, so the rule is scoped rather than blanket.
    NEEDS_CONVERSION = ("job.", "criteria_json")

    def test_every_json_loads_of_a_stored_value_converts_first(self):
        checked = 0
        for name in ("open_job", "adjudicate", "settle"):
            src = inspect.getsource(getattr(w.Warrant, name))
            for line in src.splitlines():
                if "json.loads(" not in line:
                    continue
                if not any(n in line for n in self.NEEDS_CONVERSION):
                    continue
                checked += 1
                self.assertIn("json.loads(str(", line,
                              "%s passes a stored value to json.loads "
                              "without str(): %s" % (name, line.strip()))
        self.assertGreaterEqual(checked, 3, "the rule matched nothing")


class StorageIsNotTouchedInsideTheNondetBlock(unittest.TestCase):
    def test_adjudicate_pulls_what_it_needs_before_the_closures(self):
        src = inspect.getsource(w.Warrant.adjudicate)
        pulled = src.index("criteria = json.loads(str(job.criteria))")
        leader = src.index("def leader_fn")
        self.assertLess(pulled, leader)
        closures = src[leader:src.index("agreed = json.loads")]
        for forbidden in ("job.criteria", "job.evidence_url",
                          "job.evidence_sha256", "self."):
            self.assertNotIn(forbidden, closures,
                             "%s is storage, reached inside a closure" % forbidden)


if __name__ == "__main__":
    unittest.main()
