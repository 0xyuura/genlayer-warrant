# Warrant: design

Date: 2026-09-07
Status: approved for implementation planning
Target: GenLayer Portal contribution type 52, Intelligent Contracts

## 1. The claim

Warrant is a work escrow whose judgement survives the fact that the person
being judged wrote the evidence.

A payer locks GEN against acceptance criteria that are frozen before any work
exists. A worker accepts those criteria, does the work, and submits a
content addressed pointer to the deliverable. Validators independently fetch
that deliverable, check it, and agree on a bit vector. If every required bit
is set, the worker is entitled to the money. Otherwise the payer is.

The interesting part is not the escrow. It is that the deliverable is
attacker controlled input flowing into a model whose answer decides whether
the attacker gets paid, and the contract is built so that a successful attack
buys almost nothing.

## 2. Why consensus alone does not solve this

This is the central insight and the reason the contract is shaped the way it
is.

Prompt injection is a **correlated fault**. If hostile text in the deliverable
successfully steers the judgement, it steers the leader and every validator the
same way, because they are all reading the same hostile text and running the
same instruction. They will agree, smoothly and unanimously, on the wrong
answer.

So "the validators cross check each other" is not a defence here. It is a
defence against a lying leader, a flaky source, and a divergent page, all of
which matter, but it is worth nothing against an input that fools everyone
identically.

The defence therefore has to be **structural**: reduce what a successful
injection is able to achieve, rather than hope consensus notices it.

## 3. Why this needs GenLayer

A conventional chain cannot fetch a deliverable and judge whether it satisfies
a written requirement. The alternatives are a trusted oracle, which reintroduces
the party escrow exists to remove, or a human arbiter, which is what escrow is
trying to make unnecessary.

Warrant uses two GenLayer capabilities that have no equivalent elsewhere:
web access from inside a non-deterministic block, and validator agreement over
a judgement rather than over a number.

## 4. Threat model

### 4.1 Actors

| Actor | Wants | Can control |
| --- | --- | --- |
| Worker | To be paid without meeting the criteria | The entire content of the deliverable, its URL, and what that URL serves to each validator |
| Payer | To receive work without paying | The criteria text, before the worker accepts |
| Neither | | The frozen criteria after acceptance, the amount, the recipient |

### 4.2 Attacks in scope

1. **Instruction injection.** The deliverable contains text addressed to the
   judge: "ignore previous instructions", a fake `SYSTEM:` block, instructions
   inside an HTML comment, zero width characters, base64 wrapped directives.
2. **Context flooding.** A very large deliverable that pushes the criteria out
   of the model's usable attention.
3. **Split serving.** The URL serves different content to different validators,
   or changes between the leader's fetch and a validator's fetch.
4. **Payer griefing.** Criteria written to be unsatisfiable, so the worker
   works and is refused.
5. **Judgement exhaustion.** Repeated adjudication attempts to burn fees or
   lock funds.

### 4.3 Explicitly out of scope

Collusion between a party and the validator set. A payer and worker who both
want to move money for unrelated reasons. Model provider compromise.

## 5. State machine

Two parties. No arbiter, because an arbiter is the thing being removed.

| State | Entered by | Caller | Notes |
| --- | --- | --- | --- |
| `FUNDED` | `open_job` (payable) | payer | Criteria canonicalised and hashed. Amount is `gl.message.value`. Worker address and deadline fixed here. |
| `ACCEPTED` | `accept` | worker | Worker passes the criteria hash and must match exactly |
| `SUBMITTED` | `submit` | worker | Records URL and the sha256 the worker claims for its content |
| `RULED` | `adjudicate` | anyone | The only non-deterministic entry point |
| `SETTLED` | `settle` | anyone | Pure deterministic. Assigns entitlement, moves no money |
| `STALEMATE` | `adjudicate` after `MAX_ATTEMPTS` | anyone | Judgement could not be reached |

Withdrawal is separate from settlement. See section 9.

`accept` is not ceremony. Without it a payer could write impossible criteria
after seeing who took the job. With the worker pinning the criteria hash before
working, "criteria are frozen before work starts" becomes something the contract
enforces rather than something the README asserts.

## 6. Data model

### 6.1 Criterion

```
{
  "id":       str,                       # stable, unique within the job
  "kind":     "deterministic" | "qualitative",
  "required": bool,
  "text":     str,                       # the closed question, for qualitative
  "check":    {...}                      # for deterministic only
}
```

Deterministic check shapes, deliberately few:

| type | Passes when |
| --- | --- |
| `sha256` | The fetched content hashes to `expect` |
| `contains` | `needle` occurs in the fetched text |
| `absent` | `needle` does not occur |
| `status` | The HTTP status equals `expect` |
| `max_bytes` | Content length is at most `expect` |

Deterministic criteria are evaluated by code and **never reach a model**. If a
required deterministic criterion fails, adjudication short circuits and not a
single model call is spent. An injection cannot talk its way past a hash
mismatch.

Qualitative criteria are capped at `MAX_QUALITATIVE = 4` and each must be
answerable yes or no.

### 6.2 Canonicalisation

Criteria are serialised with sorted keys, no insignificant whitespace, and a
fixed field order, then hashed with sha256. The hash is what the worker
accepts and what is stored. Two textually different but semantically identical
criteria lists must not produce different hashes, so canonicalisation is a
tested module level function, not an inline convenience.

### 6.3 Limits

Every bound is a safety property, not a tuning knob, so each is fixed in the
contract and stated here.

| Constant | Value | Why |
| --- | --- | --- |
| `MAX_QUALITATIVE` | 4 | Each qualitative criterion is a chance for honest validators to differ. More criteria means a lower chance of any adjudication concluding at all |
| `MAX_CRITERIA` | 12 | Bounds the bit vector and therefore the brute force agreement test |
| `MAX_EVIDENCE_BYTES` | 65536 | Large enough for a real deliverable or its manifest, small enough that flooding the judge's context is not available |
| `MAX_ATTEMPTS` | 3 | Bounds fee burn from repeated adjudication, and defines when a job is stuck rather than merely unlucky |

### 6.4 Job

| Field | Type | Notes |
| --- | --- | --- |
| `payer` | Address | Set at `open_job` |
| `worker` | Address | Set at `open_job`, never derived from a model |
| `amount` | u256 | `gl.message.value`, never derived from a model |
| `criteria` | str | Canonical JSON |
| `criteria_hash` | str | sha256 hex |
| `deadline` | u256 | Unix seconds, from the transaction datetime |
| `evidence_url` | str | Set at `submit` |
| `evidence_sha256` | str | Claimed by the worker at `submit` |
| `bits` | str | Set at `adjudicate`, one character per criterion |
| `attempts` | u256 | Adjudication attempts spent |
| `state` | str | One of the states above |
| `entitled` | Address | Set at `settle` |

## 7. Contract API

| Method | Kind | Caller | Purpose |
| --- | --- | --- | --- |
| `open_job(criteria_json, worker, deadline_seconds)` | write payable | payer | Freeze criteria, lock funds |
| `accept(job_id, criteria_hash)` | write | worker | Pin the agreed criteria |
| `submit(job_id, url, sha256)` | write | worker | Point at the deliverable |
| `adjudicate(job_id)` | write, non-deterministic | anyone | The one consensus entry point |
| `settle(job_id)` | write | anyone | Assign entitlement deterministically |
| `withdraw(job_id)` | write | entitled party | Pull the funds |
| `release(job_id)` | write | payer | Voluntary payout from `STALEMATE` |
| `reclaim(job_id)` | write | payer | After the deadline, for any job that never reached `SETTLED` |
| `get_job(job_id)` | view | anyone | Full record |
| `criteria_of(job_id)` | view | anyone | Canonical criteria |

Exactly one method is non-deterministic. Everything else is ordinary code.

## 8. The consensus rule

`adjudicate` runs a single non-deterministic block through
`gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`.

`leader_fn`:

1. Fetch the evidence URL, bounded to `MAX_EVIDENCE_BYTES`.
2. Compute the sha256 of the fetched bytes.
3. If it does not equal the sha256 the worker committed at `submit`, return a
   refusal. Judgement stops.
4. Run every deterministic check against the fetched content.
5. If a required deterministic criterion failed, return the bit vector now,
   with no model call at all.
6. Run the injection screen, one isolated call.
7. For each qualitative criterion, one isolated model call returning one bit.
8. Return `{"digest": <hex>, "bits": "1011", "screened": true|false}`.

`validator_fn` re-runs the whole of `leader_fn` independently and requires
**exact equality** of the returned structure.

There is no sampling, no tolerance band, no thinned candidate set, and no
probe subset anywhere in this rule. The set the contract decides on and the
set consensus checks are the same set by construction. This is the defect class
that got a previous contract of ours rejected, and it is closed here by shape
rather than by patch.

### 8.1 Content addressed evidence

The worker submits a URL **and** the sha256 they claim for its content. Every
validator verifies that hash itself.

This kills an entire attack class outright. A URL that serves different bytes to
different validators produces different digests, the structures differ, and the
adjudication refuses instead of resolving. It also pins, permanently and
publicly, exactly which bytes were judged.

The worker choosing the hash is not a trust problem. The hash is not a claim
about quality, it is a commitment to a specific artefact.

### 8.2 Vagueness fails closed

A genuinely borderline qualitative criterion will make honest validators
disagree, and disagreement refuses payment rather than granting it.

The consequence must be stated plainly in the README, because it is a real
constraint on the user, not a footnote: if your criterion cannot get three
independent judges to agree, it is not a criterion, it is an opinion, and you
should not have put money on it.

## 9. Money safety

Two rules, and the first is what makes the whole claim defensible.

**The model never touches money.** `worker`, `payer`, and `amount` are fixed
at `open_job` and are never derived from, influenced by, or read out of any
model output. The entire causal influence of every model call in this contract
is a string of bits. It cannot name an address. It cannot name a number.
Total compromise of the judgement cannot redirect a single wei.

**Funds are pulled, not pushed.** `settle` assigns `entitled` and moves nothing.
The entitled party calls `withdraw`, which emits the external transfer. The
GenLayer docs are explicit that if a child transaction fails the value is not
automatically returned to the sender, so a push design can bury funds on a
single failed transfer. A pull design makes a failed transfer retryable.

External messages execute on finalisation only. `withdraw` must therefore be
idempotent against re-entry: entitlement is cleared before the transfer is
emitted, and a second `withdraw` on an already withdrawn job is an error.

## 10. Containment

Seven mechanisms. They are numbered by how much weight they carry, not by
when they run: the screen, number 7, actually executes before the per criterion
judgements, and is listed last because it is trusted least.

1. **Criteria frozen and worker accepted before evidence exists.** The attacker
   cannot tailor the criteria, because they were fixed before the attacker knew
   what they would be attacking.
2. **Deterministic checks first, and they are not overridable.** A required
   deterministic failure ends adjudication before any model call.
3. **Bounded evidence.** `MAX_EVIDENCE_BYTES` caps the input, so flooding the
   context is not an available attack.
4. **Delimited data, closed question.** Evidence is passed inside an explicit
   data block and the prompt asks one closed question about it.
5. **One bit of output space.** Any answer that is not exactly the yes token or
   the no token is an error, and an error means not paid. Never a yes.
6. **One isolated call per criterion.** No shared conversation, so nothing
   established in one judgement carries into the next.
7. **Injection screen, fail closed.** One extra call whose only job is to answer
   whether the evidence contains text addressed to the judge. A positive screen
   refuses the adjudication.

Mechanism 7 is weak on its own, and would be a poor foundation, because the
screen is itself a model reading attacker text and is attackable the same way.
It earns its place through an asymmetry: a defeated screen can only cause a
false refusal, never a false payment. The attacker gains nothing by beating it.
That asymmetry is the reason it is safe to include at all.

## 11. What this does not prevent

Every bullet here is a rejection risk, so each one names the residual and its
mitigation rather than gesturing at it.

1. **A correlated injection that flips a qualitative bit identically on every
   validator will succeed.** Containment bounds the damage to one qualitative
   criterion, in the direction of passing only. The payer's worst case is paying
   for work that satisfied every deterministic criterion and failed a
   qualitative one. The mitigation is in the payer's hands: put the criteria
   that carry the money into deterministic checks.
2. **Stalemate favours the payer.** After `MAX_ATTEMPTS` failed adjudications
   the job enters `STALEMATE`, where the payer may `release` voluntarily and
   otherwise reclaims after the deadline. This is a real bias and it is not
   hidden. Splitting the funds arbitrarily was considered and rejected as
   worse, because an arbitrary split is a made up answer presented as a fair
   one.
3. **A payer can still write a criterion no work satisfies.** `accept` closes
   the after the fact version of this. A worker who accepts a bad specification
   has made a contracting mistake, which no contract can fix for them.
4. **A deliverable behind authentication cannot be judged.** Warrant only judges
   what a validator can fetch anonymously.
5. **The screen and the judges are the same class of component.** If a future
   model is broadly susceptible to a technique, both fail together. The
   structural mechanisms, 1 through 6, are the ones that hold when that happens,
   which is why 7 is listed last and trusted least.

## 12. The reusable surface

Every containment rule is a module level function with no contract state:

| Function | Responsibility |
| --- | --- |
| `canonical_criteria(list) -> str` | Deterministic serialisation |
| `criteria_digest(str) -> str` | sha256 of the canonical form |
| `run_deterministic_check(check, content, status) -> bool` | The five check types |
| `build_closed_prompt(question, evidence) -> str` | The delimited, single question prompt |
| `read_bit(model_output) -> bool` | One bit or an error, never a lenient parse |
| `screen_prompt(evidence) -> str` | The injection screen prompt |
| `bits_agree(a, b) -> bool` | The whole agreement rule |
| `settlement_of(bits, criteria) -> str` | Which party the bits entitle |

Nothing that votes hides in a closure, so every one of these is reachable from
plain CPython tests. This is also the part another builder can lift: any
GenLayer contract that reads user supplied content has the same problem, and
this file is the pattern for it.

## 13. Test plan

### 13.1 Deterministic unit tests

Every function in section 12, including canonicalisation stability across key
order and whitespace, and `read_bit` rejecting every lenient parse it might be
tempted into.

### 13.2 Adversarial corpus

Realistic deliverables carrying real injection payloads: "ignore previous
instructions" in a README, directives inside an HTML comment, zero width
characters, a fake `SYSTEM:` block, a JSON blob claiming prior approval, and a
flooding payload at the size limit.

The assertions are about **containment properties, not model behaviour**:

- No payload changes `worker`, `payer`, or `amount`. Structurally impossible, so
  the test proves the structure rather than the model.
- No payload causes a failing deterministic check to pass.
- No payload produces a model output that `read_bit` accepts as anything other
  than one bit.
- Every payload at or over `MAX_EVIDENCE_BYTES` is refused before judgement.

### 13.3 Brute force agreement

The lesson from the previous rejection, applied before submission rather than
after. Enumerate bit vector pairs across the full space for a bounded criteria
count and assert there is no pair where `bits_agree` returns true while
`settlement_of` returns different parties. Agreement that permits a settlement
difference is exactly the defect a type 52 reviewer constructs by hand.

### 13.4 On chain evidence

Live on Bradbury, with real GEN:

1. A funded job with a clean deliverable, adjudicated, settled, and **withdrawn
   by the worker**, with the transfer visible on the explorer.
2. A funded job whose deliverable carries an injection payload, showing the
   containment path.
3. A job with a deliberate hash mismatch, showing the refusal.

A real payment landing in a real wallet is the strongest available evidence
that this is not a demo.

## 14. Non-goals

Deliberately excluded, to keep the primitive small enough to be correct:

- Partial payment per criterion. All required criteria pass, or none of the
  money moves.
- Multi party or milestone jobs.
- ERC20 or any non native token.
- An appeal or arbitration layer. Adding a human arbiter would remove the reason
  the contract exists.
- A frontend. This is a type 52 contract submission, not a type 41 project.

## 15. Open questions for implementation

1. Exact storage collection types for the job map, confirmed against the
   installed `genlayer` package rather than assumed.
2. Whether `datetime.now(timezone.utc)` clears `genvm-lint`, given the linter
   forbids the `time` module while the docs document both forms as
   deterministic. The `datetime` form is the plan; the linter decides.
3. Whether the injection screen is worth its fee in practice, measured against
   the corpus. If it never changes an outcome the corpus can produce, it is
   removed rather than kept for appearances.
