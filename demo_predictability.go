package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	hashMimc "github.com/consensys/gnark-crypto/hash"
)

// This demonstrates that the GKR challenges are predictable
// because they are derived from public constants (500, 0)

func main() {
	fmt.Println("=== Demonstrating GKR Challenge Predictability ===\n")

	// These are the public constants used in the circuit
	aliceBalance := big.NewInt(500)
	bobBalance := big.NewInt(0)

	fmt.Printf("Public Inputs:\n")
	fmt.Printf("  AliceBalance: %s\n", aliceBalance.String())
	fmt.Printf("  BobBalance: %s\n\n", bobBalance.String())

	// Compute the first challenge as the verifier would
	// This matches what happens in the Fiat-Shamir transcript
	firstChallenge := computeFirstChallenge(aliceBalance, bobBalance)

	fmt.Printf("Predicted First Challenge:\n")
	fmt.Printf("  %s\n\n", firstChallenge.String())

	fmt.Println("Key Insight:")
	fmt.Println("  This challenge value is DETERMINISTIC and PREDICTABLE")
	fmt.Println("  A malicious prover can compute it before generating the proof")
	fmt.Println("  They can then craft fake circuit evaluations at this point")
	fmt.Println("  that will pass GKR verification but don't represent real computation\n")

	// Show that it's always the same
	firstChallenge2 := computeFirstChallenge(aliceBalance, bobBalance)
	fmt.Printf("Computing again: %s\n", firstChallenge2.String())
	fmt.Printf("Same value? %v\n\n", firstChallenge.Cmp(firstChallenge2) == 0)

	// Show how it should be done
	fmt.Println("=== How It Should Be Done ===\n")
	fmt.Println("Proper Challenge Derivation:")
	fmt.Println("  1. Bind circuit description to transcript")
	fmt.Println("  2. Bind public inputs (AliceBalance, BobBalance)")
	fmt.Println("  3. Bind CLAIMED OUTPUTS (NewBobBalance, NewAliceBalance)")
	fmt.Println("  4. THEN derive challenge from transcript hash")
	fmt.Println("")
	fmt.Println("With proper binding, the challenge depends on the claimed outputs,")
	fmt.Println("so the prover cannot predict it before committing to their claims.")
}

// computeFirstChallenge mimics how the Fiat-Shamir transcript
// derives the first challenge in the vulnerable implementation
func computeFirstChallenge(aliceBalance, bobBalance *big.Int) *fr.Element {
	// This matches the Fiat-Shamir transcript computation
	// See: gnark/std/fiat-shamir/transcript.go:ComputeChallenge

	h := hashMimc.MIMC_BN254.New()

	// 1. Write challenge name (domain separator)
	challengeName := "challenge0"
	h.Write([]byte(challengeName))

	// 2. No previous challenge (this is the first one)

	// 3. Write bindings (the "BaseChallenges" = [AliceBalance, BobBalance])
	// Convert to field elements
	aliceFr := new(fr.Element).SetBigInt(aliceBalance)
	bobFr := new(fr.Element).SetBigInt(bobBalance)

	// Write to hash (as field elements in Montgomery form)
	aliceBytes := aliceFr.Bytes()
	bobBytes := bobFr.Bytes()

	h.Write(aliceBytes[:])
	h.Write(bobBytes[:])

	// 4. Compute hash
	hashBytes := h.Sum(nil)

	// Convert hash output to field element
	challenge := new(fr.Element)
	challenge.SetBytes(hashBytes)

	return challenge
}

/* Expected Output:

=== Demonstrating GKR Challenge Predictability ===

Public Inputs:
  AliceBalance: 500
  BobBalance: 0

Predicted First Challenge:
  <deterministic value computed from Hash("challenge0" || 500 || 0)>

Key Insight:
  This challenge value is DETERMINISTIC and PREDICTABLE
  A malicious prover can compute it before generating the proof
  They can then craft fake circuit evaluations at this point
  that will pass GKR verification but don't represent real computation

Computing again: <same value>
Same value? true

=== How It Should Be Done ===

Proper Challenge Derivation:
  1. Bind circuit description to transcript
  2. Bind public inputs (AliceBalance, BobBalance)
  3. Bind CLAIMED OUTPUTS (NewBobBalance, NewAliceBalance)
  4. THEN derive challenge from transcript hash

With proper binding, the challenge depends on the claimed outputs,
so the prover cannot predict it before committing to their claims.
*/
