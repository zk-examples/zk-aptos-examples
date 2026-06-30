package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarktosnarkjs "github.com/mysteryon88/gnark-to-snarkjs"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	field := ecc.BLS12_381.ScalarField()

	// compiles our circuit into a R1CS
	var circuit CubicCircuit
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("compile circuit: %w", err)
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup groth16: %w", err)
	}

	// witness definition
	assignment := CubicCircuit{X: 3, Y: 35}
	witness, err := frontend.NewWitness(&assignment, field)
	if err != nil {
		return fmt.Errorf("create witness: %w", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("verify proof: %w", err)
	}

	schema, err := frontend.NewSchema(field, &circuit)
	if err != nil {
		return fmt.Errorf("create public witness schema: %w", err)
	}

	if err := writeArtifact("public.json", func(out *os.File) error {
		return gnarktosnarkjs.ExportPublicWitness(publicWitness, schema, out)
	}); err != nil {
		return err
	}

	if err := writeArtifact("proof.json", func(out *os.File) error {
		return gnarktosnarkjs.ExportProof(proof, []string{"35"}, out)
	}); err != nil {
		return err
	}

	if err := writeArtifact("verification_key.json", func(out *os.File) error {
		return gnarktosnarkjs.ExportVerifyingKey(vk, out)
	}); err != nil {
		return err
	}

	if err := writeArtifact("proof_gnark.json", func(out *os.File) error {
		return gnarktosnarkjs.ExportGnarkProof(proof, out)
	}); err != nil {
		return err
	}

	if err := writeArtifact("verification_key_gnark.json", func(out *os.File) error {
		return gnarktosnarkjs.ExportGnarkVerifyingKey(vk, out)
	}); err != nil {
		return err
	}

	if err := writeArtifact("proof.bin", func(out *os.File) error {
		return gnarktosnarkjs.ExportGnarkProofBinary(proof, out)
	}); err != nil {
		return err
	}

	if err := writeArtifact("verification_key.bin", func(out *os.File) error {
		return gnarktosnarkjs.ExportGnarkVerifyingKeyBinary(vk, out)
	}); err != nil {
		return err
	}

	return nil
}

func writeArtifact(name string, export func(*os.File) error) error {
	out, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	defer out.Close()

	if err := export(out); err != nil {
		return fmt.Errorf("export %s: %w", name, err)
	}
	return nil
}
