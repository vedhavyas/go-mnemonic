package mnemonic

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
func contains(v int, l []int) bool {
	for _, i := range l {
		if v == i {
			return true
		}
	}

	return false
}

// GenerateEntropy returns entropy with strength, given strength taken from pre-defined list
func GenerateEntropy(strength int) ([]byte, error) {
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

// getEntropyBits adds required checksum bits to entropy and returns the binary form
func getEntropyBits(entropy []byte) (string, error) {
	if !contains(len(entropy), acceptedEntropyLength) {
		return "", fmt.Errorf("required entropy length: %v but got: %d", acceptedEntropyLength, len(entropy))
	}

	ckSum := sha256.Sum256(entropy)
	ckSumBits := toBitsString(ckSum[:])
	cs := len(entropy) / 32

	var buf bytes.Buffer
	buf.WriteString(toBitsString(entropy))
	buf.WriteString(ckSumBits[:cs])
	return buf.String(), nil
}
