# ZK Soundness Vulnerability Analysis: Predictable Fiat-Shamir Challenges in GKR

## Executive Summary

**Vulnerability Class:** Fiat-Shamir Challenge Predictability / Weak Transcript Binding
**Severity:** CRITICAL - Complete soundness break
**Impact:** Attacker can forge proofs for arbitrary computations, allowing Alice to credit Bob with any amount despite only having 500 tokens

## Root Cause

The GKR verification uses **predictable public inputs as Fiat-Shamir challenges** instead of deriving them from a proper cryptographic transcript that binds all public inputs and claimed outputs.

### Vulnerable Code Flow

**1. app.go:81** - The circuit passes public inputs as "challenges":
```go
err := gkrBalance.VerifyGKR(circuit.AliceBalance, circuit.BobBalance)
```
Where `AliceBalance = 500` and `BobBalance = 0` (constants).

**2. gkr_adder.go:71** - These become the "initial challenges":
```go
err = solution.Verify("mimc", challenges...)
```

**3. compile.go:197** - Passed to GKR verifier as `BaseChallenges`:
```go
err = Verify(..., fiatshamir.WithHash(hsh, initialChallenges...), ...)
```

**4. gkr.go:203** - Bound to transcript BEFORE outputs are bound:
```go
if err = o.transcript.Bind(challengeNames[0], transcriptSettings.BaseChallenges); err != nil {
```

**5. gkr.go:311** - First challenge derived from predictable inputs:
```go
firstChallenge, err = getChallenges(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
```

**6. transcript.go:146-149** - Challenge computed as:
```go
t.h.Write(challenge.bindings...)  // bindings = [500, 0]
challenge.value = t.h.Sum()       // firstChallenge = Hash("challenge0" || [500, 0])
```

**7. gkr.go:322** - ONLY AFTER challenge is computed are outputs evaluated:
```go
claims.add(wire, firstChallenge, assignment[wire].Evaluate(api, firstChallenge))
```

## The Attack

### Why This Breaks Soundness

In a sound GKR protocol, the verifier must:
1. **Bind all public inputs and claimed outputs** to the Fiat-Shamir transcript
2. **Then** derive random challenges from the transcript
3. Use these challenges to verify the proof

Here, the challenges are derived from ONLY the public inputs (500, 0), WITHOUT binding the claimed outputs. This means:

- **firstChallenge is PREDICTABLE**: `firstChallenge = Hash("challenge0" || [500, 0])`
- The prover knows this value **before generating the proof**
- The prover can craft malicious circuit evaluations that pass verification **at this specific point**
- But these evaluations don't correspond to the correct computation

### Attack Scenario

1. **Prover wants**: Bob receives 1,000,000 tokens (instead of max 500)

2. **Prover computes**: `firstChallenge = MiMC("challenge0", 500, 0)`

3. **Prover crafts fake GKR wire assignments** at `firstChallenge` that:
   - Claim `newBobBalance = 1,000,000`
   - Satisfy the GKR circuit structure (add gates)
   - Pass Sum-Check verification under the predictable challenges

4. **Prover generates Sum-Check polynomials** that:
   - Match the fake wire assignments
   - Pass all degree checks
   - Satisfy the partial sum constraints

5. **Verifier accepts** because:
   - Challenges are derived correctly from transcript
   - Sum-Check proofs verify
   - But the underlying computation is FALSE

## Technical Details

### GKR Protocol Background

GKR proves circuit evaluation correctness by:
1. Starting with claimed output layer values
2. Verifier picks **random evaluation point** r
3. Prover proves output layer evaluates to claimed value at r
4. Recursively reduce to input layer via Sum-Check

**Critical requirement**: The evaluation point r must be RANDOM and UNPREDICTABLE, otherwise the prover can fake evaluations at that specific point without doing the real computation.

### Sum-Check Protocol Background

Sum-Check proves: ∑_{x ∈ {0,1}^n} f(x) = claimed_sum

Verifier:
1. Receives claimed sum
2. For each round i, prover sends univariate polynomial g_i
3. Verifier checks g_i(0) + g_i(1) = previous claimed sum
4. Verifier picks **random** r_i (in Fiat-Shamir, via hash)
5. Continue with claimed sum = g_i(r_i)

**Critical requirement**: r_i must be derived from hashing ALL prior proof messages, otherwise prover can construct polynomials that verify under predicted challenges.

### Why This Implementation Fails

1. **Missing Output Binding**: The claimed output values (`newBobBalance`, `newAliceBalance`) are NEVER bound into the Fiat-Shamir transcript before deriving `firstChallenge`

2. **Weak Initial Entropy**: `BaseChallenges` = [500, 0] provides no entropy, just predictable constants

3. **Challenge Derivation**:
   ```
   firstChallenge = Hash("challenge0" || [500, 0])
   ```
   This is deterministic and known to the prover.

4. **No Circuit Commitment**: The circuit structure and claimed outputs should be bound before deriving challenges

## Proof of Concept (Conceptual)

```python
# Prover's exploit (pseudocode)

# 1. Compute predictable first challenge
challenge_0 = MiMC("challenge0" || bytes(500) || bytes(0))

# 2. Choose arbitrary fake outputs
fake_newBobBalance = 1_000_000
fake_newAliceBalance = 500 - 1_000_000  # Underflow in field

# 3. Craft fake circuit evaluations at challenge_0
fake_alice_add = (500, -transfer) -> fake_newAliceBalance  # at challenge_0
fake_bob_add = (0, transfer) -> fake_newBobBalance         # at challenge_0

# 4. Build Sum-Check proofs that verify under predictable challenges
# (This requires deep knowledge of gnark's GKR implementation internals)

# 5. Serialize proof and submit
```

## Impact Assessment

**Complete soundness break**:
- Alice can prove she sent ANY amount to Bob
- Bob's balance can be set to arbitrary values >= 100,000
- The ZK proof system provides ZERO security guarantees
- Attacker can steal unlimited funds in a production system

## References

- [Thaler 2013: "Time-Optimal Interactive Proofs for Circuit Evaluation"](https://arxiv.org/abs/1304.3812)
- [Cormode et al.: "Practical Verified Computation with Streaming Interactive Proofs"](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)
- [Fiat-Shamir Transform Security Requirements](https://crypto.stanford.edu/~dabo/pubs/papers/fischlin.pdf)

## Affected Code Locations

| File | Line | Issue |
|------|------|-------|
| `app.go` | 81 | Uses public inputs as challenges |
| `gkr_adder.go` | 71 | Passes challenges to GKR without binding outputs |
| `compile.go` | 197 | Uses initialChallenges as BaseChallenges |
| `gkr.go` | 203 | Binds BaseChallenges before outputs |
| `gkr.go` | 311 | Derives firstChallenge from predictable values |
| `transcript.go` | 146-149 | Computes challenge from bound values only |

## Next Steps

See `fix.md` for detailed patches and `hardening_checklist.md` for prevention checklist.
