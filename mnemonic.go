package mnemonic

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

var (
	// list of accepted strengths taken from BIP-39
	acceptedStrengths = []int{128, 160, 192, 224, 256}

	// list of accepted entropy lengths taken from BIP-39
	acceptedEntropyLength = []int{16, 20, 24, 28, 32}
)

// toBitsString returns the binary form of []byte
func toBitsString(data []byte) string {
	var buf bytes.Buffer
	for _, b := range data {
		buf.WriteString(fmt.Sprintf("%.8b", b))
	}

	return buf.String()
}

// contains checks if the int is in provided list
func contains(c int, l []int) bool {
	for _, i := range l {
		if c == i {
			return true
		}
	}

	return false
}

// generateEntropy returns entropy with strength, given strength taken from pre-defined list
func generateEntropy(strength int) ([]byte, error) {
	if !contains(strength, acceptedStrengths) {
		return nil, fmt.Errorf("required strength: %v but got: %d", acceptedStrengths, strength)
	}

	b := make([]byte, strength/8)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	return b, nil
}
