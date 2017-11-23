package mnemonic

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var (
	// list of accepted strengths taken from BIP-39
	acceptedStrengths = []int{128, 160, 192, 224, 256}

	// list of accepted entropy lengths taken from BIP-39
	acceptedEntropyLength = []int{16, 20, 24, 28, 32}

	// list of accepted entropy + checksum lengths from BIP-39
	acceptedECLength = []int{132, 165, 198, 231, 264}
)

// Generator generates mnemonic words and seed
type Generator struct {
	wordListPath string   // file path to load words from
	words        []string // words to be used
}

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

// wordIDxs returns group of 11 bits each from bits
func wordIDxs(bits string) ([]string, error) {
	bits = strings.TrimSpace(bits)
	if !contains(len(bits), acceptedECLength) {
		return nil, fmt.Errorf("expected bits length:%v got: %d", acceptedECLength, len(bits))
	}

	var sbits []string
	index := 0
	for i := 0; i < len(bits)/11; i++ {
		sbits = append(sbits, bits[index:index+11])
		index += 11
	}

	return sbits, nil
}

// wordsFromIDxs returns the mapped words from the idxs
func wordsFromIDxs(idxs []string, wordList []string) ([]string, error) {
	var words []string
	for _, idx := range idxs {
		id, err := strconv.ParseInt(idx, 2, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to parse int: %v", err)
		}

		words = append(words, wordList[id])
	}

	return words, nil
}

// loadWords loads words from the file path
func loadWords(path string) (words []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()
	r := bufio.NewReader(f)
	for {
		var w string
		w, err = r.ReadString('\n')
		if err != nil {
			break
		}

		words = append(words, strings.TrimSpace(w))
	}

	if err != io.EOF {
		return nil, err
	}

	return words, nil
}

// ToMnemonic returns mnemonic words from entropy
func (g *Generator) ToMnemonic(entropy []byte) (words []string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to generate mnemonic words: %v", err)
		}
	}()

	ebits, err := getEntropyBits(entropy)
	if err != nil {
		return nil, err
	}

	idxs, err := wordIDxs(ebits)
	if err != nil {
		return nil, err
	}

	words, err = wordsFromIDxs(idxs, g.words)
	if err != nil {
		return nil, err
	}

	return words, nil
}
