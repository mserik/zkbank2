# Sum-Check / GKR Soundness Hardening Checklist

This checklist summarizes best practices for implementing sound Sum-Check and GKR protocols, derived from the vulnerability analysis.

## Fiat-Shamir Transform Security

### ✓ Challenge Derivation
- [ ] **Never use public inputs directly as random challenges**
- [ ] **All challenges must be derived from cryptographic hash (Fiat-Shamir)**
- [ ] **Challenges must be unpredictable to the prover before proof generation**
- [ ] **Each challenge must depend on ALL prior proof transcript elements**

### ✓ Transcript Binding
- [ ] **Bind circuit description / hash to transcript before deriving any challenges**
- [ ] **Bind ALL public inputs to transcript**
- [ ] **Bind ALL claimed outputs to transcript BEFORE deriving first challenge**
- [ ] **Bind each round's proof polynomial BEFORE deriving next challenge**
- [ ] **Use domain separation (unique labels) for each challenge**

### ✓ Transcript Initialization
```
CORRECT:
1. Initialize transcript with hash function
2. Bind: circuit_hash || public_inputs || claimed_outputs
3. Derive challenge_1 from transcript
4. Prover sends proof_1
5. Bind proof_1 to transcript
6. Derive challenge_2 from transcript
7. Repeat...

INCORRECT:
1. Use public_inputs directly as challenge_1  ❌
2. Derive challenges before binding outputs      ❌
3. Reuse challenges across rounds               ❌
```

## Sum-Check Protocol Security

### ✓ Round-by-Round Verification
- [ ] **For each round j, verify: g_j(0) + g_j(1) = previous_sum**
- [ ] **Check polynomial degree: deg(g_j) ≤ expected degree**
- [ ] **Derive r_j by hashing g_j (Fiat-Shamir)**
- [ ] **Update sum: sum' = g_j(r_j)**
- [ ] **Never reuse challenge r_j across rounds**

### ✓ Domain Enforcement
- [ ] **Verify sum is over boolean hypercube: x ∈ {0,1}^n**
- [ ] **Reject evaluations outside the boolean domain**
- [ ] **Check final evaluation against input layer (no shortcuts)**

### ✓ Polynomial Degree Bounds
- [ ] **Enforce univariate polynomial degree for each round**
- [ ] **For add gates: degree 1**
- [ ] **For mul gates: degree 2**
- [ ] **For custom gates: verify correct degree**
- [ ] **Reject polynomials exceeding degree bounds**

### ✓ Final Evaluation Check
- [ ] **Verify g_n(r_n) matches claimed input evaluation**
- [ ] **Check input values against public inputs**
- [ ] **Ensure recursion terminates at proper base layer**

## GKR Protocol Security

### ✓ Layer-by-Layer Reduction
- [ ] **Start with claimed output layer evaluation**
- [ ] **For each layer i, reduce claim about layer i to claim about layer i+1**
- [ ] **Use correct wiring multilinear extensions (add_i, mul_i)**
- [ ] **Verify add and mul gate identities separately**

### ✓ Random Linear Combination
- [ ] **Use random α, β for combining left/right child claims**
- [ ] **Derive α, β from Fiat-Shamir transcript (not fixed constants)**
- [ ] **Bind layer evaluation to transcript before deriving α, β**
- [ ] **Verify combined claim: V_i(g) = α·V_{i+1}(b) + β·V_{i+1}(c)**

### ✓ Wiring Consistency
- [ ] **Verify wiring predicates (add_i, mul_i) are used correctly**
- [ ] **Check that wire indices are within bounds**
- [ ] **Ensure left/right child evaluations correspond to correct wires**
- [ ] **Validate circuit topology matches expected structure**

### ✓ Input Layer Verification
- [ ] **Check final layer matches public input values**
- [ ] **Verify input layer MLE evaluation against witness**
- [ ] **Ensure no "shortcuts" that skip intermediate layers**

## Implementation Anti-Patterns

### ❌ Predictable Challenges
```go
// WRONG: Using public inputs as challenges
err := VerifyGKR(publicInput1, publicInput2)

// CORRECT: Derive from transcript
transcript.Bind("outputs", claimedOutputs)
challenge := transcript.ComputeChallenge("round1")
```

### ❌ Missing Output Binding
```go
// WRONG: Derive challenge before binding outputs
challenge := deriveChallenge(publicInputs)
evaluation := computeOutput(challenge)

// CORRECT: Bind outputs first
transcript.Bind("outputs", claimedOutputs)
challenge := transcript.ComputeChallenge("round1")
```

### ❌ Reusing Challenges
```go
// WRONG: Same challenge for multiple rounds
for i in rounds {
    verify(challenge, proof[i])  // Same challenge!
}

// CORRECT: Fresh challenge each round
for i in rounds {
    transcript.Bind("round" + i, proof[i])
    challenge[i] = transcript.ComputeChallenge("challenge" + i)
    verify(challenge[i], proof[i])
}
```

### ❌ Skipping Degree Checks
```go
// WRONG: Accept any polynomial
poly := proverSends()
eval := poly.Evaluate(challenge)

// CORRECT: Check degree first
poly := proverSends()
if poly.Degree() > maxDegree {
    return Error("Invalid degree")
}
eval := poly.Evaluate(challenge)
```

## Testing Checklist

### ✓ Soundness Tests
- [ ] **Test that invalid proofs are rejected**
- [ ] **Test modified proof polynomials fail verification**
- [ ] **Test incorrect final evaluations fail**
- [ ] **Test proofs with wrong degree fail**
- [ ] **Test proofs with manipulated challenges fail**

### ✓ Completeness Tests
- [ ] **Test that valid proofs always verify**
- [ ] **Test edge cases (zero values, max field elements)**
- [ ] **Test all gate types (add, mul, custom)**
- [ ] **Test various circuit sizes**

### ✓ Property Tests
```go
// Property: Prover with invalid witness cannot create valid proof
func TestInvalidWitnessFails(testing *T) {
    invalidWitness := createInvalidWitness()
    proof, err := Prove(circuit, invalidWitness)
    // Should either fail to prove OR produce invalid proof
    assert.Error(err) || assert.Error(Verify(proof))
}

// Property: Same witness produces verifiable proof
func TestValidWitnessSucceeds(testing *T) {
    validWitness := createValidWitness()
    proof, err := Prove(circuit, validWitness)
    assert.NoError(err)
    assert.NoError(Verify(proof))
}
```

## Code Review Checklist

When reviewing Sum-Check / GKR implementations:

1. **Trace challenge derivation**: Where does each challenge come from?
2. **Check transcript binding order**: Are outputs bound before first challenge?
3. **Verify polynomial degrees**: Are degree bounds enforced?
4. **Check domain**: Is sum over boolean hypercube?
5. **Inspect random combination**: Are α, β derived from transcript?
6. **Test with invalid proofs**: Do soundness tests exist and pass?

## Reference Implementations

### ✓ Secure Fiat-Shamir Pattern
```go
// 1. Setup transcript
transcript := NewTranscript(hash, challengeNames)

// 2. Bind public inputs
transcript.Bind("public", publicInputs)

// 3. Bind claimed outputs
transcript.Bind("outputs", claimedOutputs)

// 4. Derive first challenge
r1 := transcript.ComputeChallenge("challenge1")

// 5. Verify first round
transcript.Bind("proof1", proverPoly1)
r2 := transcript.ComputeChallenge("challenge2")

// 6. Continue...
```

### ✓ Secure Sum-Check Verification
```go
func VerifySumCheck(claim Sum, proof Proof) error {
    currentSum := claim.Sum
    challenges := []Challenge{}

    for j := 0; j < numVars; j++ {
        poly := proof.RoundPolys[j]

        // Check degree
        if poly.Degree() > maxDegree {
            return Error("Invalid degree")
        }

        // Check sum: g(0) + g(1) = currentSum
        if poly.Eval(0) + poly.Eval(1) != currentSum {
            return Error("Sum mismatch")
        }

        // Fiat-Shamir: hash polynomial to get challenge
        transcript.Bind("round_"+j, poly.Coefficients())
        r_j := transcript.ComputeChallenge("challenge_"+j)
        challenges = append(challenges, r_j)

        // Update sum
        currentSum = poly.Eval(r_j)
    }

    // Final check against oracle
    finalValue := oracle.Eval(challenges)
    return assert(currentSum == finalValue)
}
```

## Additional Resources

- **Thaler's Survey**: [Proofs, Arguments, and Zero-Knowledge](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)
- **Fiat-Shamir Security**: [Fischlin 2005 - Communication-Efficient Non-Interactive Proofs of Knowledge](https://eprint.iacr.org/2004/334)
- **GKR Original**: [Goldwasser, Kalai, Rothblum 2008](https://eccc.weizmann.ac.il/report/2007/108/)
- **Sum-Check Interactive Proofs**: [Cormode et al. - Practical Verified Computation](https://arxiv.org/abs/1105.2003)
- **Electisec GKR Tutorial**: [Understanding GKR](https://www.leku.blog/gkr-protocol/)

## Summary

The core principles for sound Sum-Check/GKR implementations:

1. **Challenges MUST be unpredictable** (derived from transcript)
2. **Bind ALL proof elements** before deriving next challenge
3. **Enforce degree bounds** on all polynomials
4. **Verify over correct domain** ({0,1}^n for Sum-Check)
5. **Test soundness** with invalid proofs
6. **Never reuse challenges** across rounds or instances

Following this checklist will prevent the classes of bugs found in this audit.
