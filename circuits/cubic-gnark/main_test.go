package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMainExportsAllVerifierInputVariants(t *testing.T) {
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("change to temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	if err := run(); err != nil {
		t.Fatalf("run generator: %v", err)
	}

	for _, name := range []string{
		"verification_key.json",
		"proof.json",
		"verification_key_gnark.json",
		"proof_gnark.json",
		"verification_key.bin",
		"proof.bin",
		"public.json",
	} {
		info, err := os.Stat(filepath.Join(tmp, name))
		if err != nil {
			t.Fatalf("%s was not generated: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", name)
		}
	}

	assertJSONHasKey(t, filepath.Join(tmp, "verification_key.json"), "vk_alpha_1")
	assertJSONHasKey(t, filepath.Join(tmp, "proof.json"), "publicSignals")
	assertJSONHasKey(t, filepath.Join(tmp, "verification_key_gnark.json"), "G1")
	assertJSONHasKey(t, filepath.Join(tmp, "proof_gnark.json"), "Ar")
	assertJSONContainsDecimal(t, filepath.Join(tmp, "public.json"), "35")
}

func assertJSONHasKey(t *testing.T, path string, key string) {
	t.Helper()

	var value map[string]any
	readJSONFile(t, path, &value)
	if _, ok := value[key]; !ok {
		t.Fatalf("%s does not contain %q", filepath.Base(path), key)
	}
}

func assertJSONContainsDecimal(t *testing.T, path string, expected string) {
	t.Helper()

	var value any
	readJSONFile(t, path, &value)
	if !jsonContainsDecimal(value, expected) {
		t.Fatalf("%s does not contain public value %q", filepath.Base(path), expected)
	}
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if err := json.Unmarshal(content, target); err != nil {
		t.Fatalf("parse %s as JSON: %v", filepath.Base(path), err)
	}
}

func jsonContainsDecimal(value any, expected string) bool {
	switch typed := value.(type) {
	case string:
		return typed == expected
	case float64:
		return typed == 35 && expected == "35"
	case []any:
		for _, item := range typed {
			if jsonContainsDecimal(item, expected) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if jsonContainsDecimal(item, expected) {
				return true
			}
		}
	}
	return false
}
