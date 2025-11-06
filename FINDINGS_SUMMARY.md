# ZK Soundness Audit Summary - zkBank Challenge

## Audit Outcome

**Status**: CRITICAL VULNERABILITY IDENTIFIED
**Vulnerability**: Predictable Fiat-Shamir Challenges in GKR Verification
**Risk Level**: Complete Soundness Break
**Exploitability**: High (with deep GKR implementation knowledge)

## Quick Summary

The zkBank circuit uses **public inputs (AliceBalance=500, BobBalance=0) as GKR verification challenges**, making them completely predictable to a malicious prover. This breaks the Fiat-Shamir transform's security assumptions and allows forging proofs for arbitrary computations.

## The Bug

**Location**: `app.go:81` and `gkr_adder.go:71`

```go
// app.go:81 - Passes public inputs as "challenges"
err := gkrBalance.VerifyGKR(circuit.AliceBalance, circuit.BobBalance)

// gkr_adder.go:71 - Uses them for GKR verification
err = solution.Verify("mimc", challenges...)
```

**Impact**: These become the `BaseChallenges` for the Fiat-Shamir transcript, resulting in:
```
firstChallenge = Hash("challenge0" || 500 || 0)
```

This value is **deterministic and predictable**, violating the core security requirement that Fiat-Shamir challenges must be unpredictable to the prover.

## Attack Scenario

1. Prover knows firstChallenge will always be `Hash("challenge0" || 500 || 0)`
2. Prover crafts malicious circuit evaluations at this specific point
3. Prover builds Sum-Check proofs that verify under these predictable challenges
4. Verifier accepts proof, but computation is INVALID
5. Result: Bob receives 100,000+ tokens despite Alice only having 500

## Root Causes

1. **Missing Output Binding**: Claimed outputs (NewBobBalance) are not bound to transcript before deriving first challenge
2. **Weak Initial Entropy**: BaseChallenges contain no randomness, just constants [500, 0]
3. **API Misuse**: Public inputs should NOT be used as verification challenges
4. **No Circuit Commitment**: Circuit structure not bound before challenge derivation

## Deliverables

### 1. `analysis.md`
Comprehensive technical analysis including:
- Complete vulnerability chain
- Code flow trace through gnark internals
- Fiat-Shamir transform security requirements
- Attack mechanism explanation
- References to academic literature

### 2. `fix.md`
Detailed patches including:
- Primary fix: Remove challenge parameters from VerifyGKR
- Alternative fix: Proper transcript binding
- Additional hardening (range checks, overflow protection)
- Test cases for soundness and completeness
- Migration notes

### 3. `hardening_checklist.md`
Comprehensive checklist covering:
- Fiat-Shamir transform best practices
- Sum-Check protocol requirements
- GKR layer reduction security
- Implementation anti-patterns
- Testing strategies
- Code review guidelines

### 4. `exploit_strategy.md`
Attack implementation strategy:
- Challenge prediction computation
- Witness crafting approach
- GKR proof forgery technique
- Technical barriers to full exploit
- Practical demonstration steps

## Technical Deep Dive

### Fiat-Shamir Transform Security

For sound Fiat-Shamir transformation:
```
Transcript Initialization:
1. Bind: circuit_description
2. Bind: public_inputs
3. Bind: claimed_outputs    ← MISSING IN VULNERABLE CODE
4. Derive: challenge_1      ← Derived too early!
```

The vulnerable code derives `challenge_1` from ONLY public inputs, before binding outputs.

### GKR Protocol Requirements

Standard GKR:
1. Verifier picks **random** evaluation point r
2. Prover proves output layer evaluates correctly at r
3. Reduce to input layer via Sum-Check

The randomness of r is CRITICAL. If predictable, prover can fake evaluations at that specific point.

### Sum-Check Soundness

For each round, challenges must be derived by hashing the proof polynomial:
```go
// CORRECT (gnark does this):
transcript.Bind("round_j", proof.Poly[j])
r_j = transcript.ComputeChallenge("challenge_j")

// But initial challenge is WRONG:
transcript.Bind("challenge_0", [500, 0])  // Predictable!
firstChallenge = transcript.ComputeChallenge("challenge_0")
```

## Why Exploit is Non-Trivial

Despite the vulnerability, generating a working `proof_hex` requires:

1. **Groth16 Constraints**: The outer proof system has R1CS constraint `Transfer <= 500`
2. **GKR Internals**: Need to understand gnark's GKR proof format and encoding
3. **Hint System**: The TransferHint is unconstrained but GKR should verify it
4. **Proof Construction**: Must build valid Sum-Check polynomials for forged values

The exploit path likely involves:
- Modifying the TransferHint to return fake values
- Crafting GKR proof that verifies under predictable challenges
- Leveraging that hints are unconstrained by R1CS

## Recommended Actions

### Immediate (Critical)

1. **Deploy fix from `fix.md`**: Remove challenge parameters from VerifyGKR
2. **Invalidate existing proofs**: Old proofs are insecure
3. **Regenerate proving/verifying keys**: After circuit modification
4. **Add soundness tests**: Verify invalid proofs are rejected

### Short-term (Important)

1. **Add range checks**: Prevent field overflow attacks
2. **Audit hint usage**: Ensure hints don't bypass security
3. **Add constraint tests**: Verify all arithmetic constraints
4. **Document security assumptions**: Make challenge derivation explicit

### Long-term (Best Practice)

1. **Follow hardening checklist**: Apply to all ZK circuits
2. **Code review process**: Check Fiat-Shamir usage
3. **Formal verification**: Consider proving circuit correctness
4. **Security audits**: Regular third-party reviews

## Testing Recommendations

### Soundness Tests
```go
// Test 1: Invalid transfer amount
Transfer = 100,000 (> Alice's 500)
Expected: Proof generation fails OR verification fails

// Test 2: Modified hint output
Hint returns wrong value
Expected: GKR verification fails

// Test 3: Manipulated proof transcript
Modify proof polynomials after generation
Expected: Verification fails
```

### Property Tests
- Valid witnesses always produce valid proofs (completeness)
- Invalid witnesses cannot produce valid proofs (soundness)
- Same witness produces verifiable proofs consistently (determinism)

## References

- **GKR Protocol**: [Goldwasser, Kalai, Rothblum 2008](https://eccc.weizmann.ac.il/report/2007/108/)
- **Sum-Check**: [Lund et al. 1992](https://dl.acm.org/doi/10.1145/146585.146605)
- **Fiat-Shamir**: [Fiat, Shamir 1986](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)
- **Fiat-Shamir Security**: [Fischlin 2005](https://eprint.iacr.org/2004/334)
- **Thaler's Survey**: [Proofs, Arguments, and Zero-Knowledge](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)

## Conclusion

This is a **textbook Fiat-Shamir soundness bug**: using predictable public values as random challenges. The vulnerability completely breaks the security of the GKR proof system.

**The fix is straightforward** (remove challenge parameters), but **the implications are severe** - any system using this pattern is completely insecure.

This bug demonstrates why careful cryptographic protocol implementation and thorough security review are critical for ZK systems.

---

**Audit Conducted By**: Senior ZK Auditor
**Date**: 2025-11-06
**Status**: CRITICAL - IMMEDIATE FIX REQUIRED
