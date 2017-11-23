package mnemonic

import (
	"reflect"
	"testing"
)

func Test_toBitsString(t *testing.T) {
	tests := []struct {
		data   []byte
		result string
	}{
		{
			data:   []byte{1},
			result: "00000001",
		},

		{
			data:   []byte{128, 112},
			result: "1000000001110000",
		},

		{
			data:   []byte{128, 112, 200},
			result: "100000000111000011001000",
		},
	}

	for _, c := range tests {
		r := toBitsString(c.data)
		if r != c.result {
			t.Fatalf("expected %s but got %s", c.result, r)
		}
	}
}

func Test_contains(t *testing.T) {
	tests := []struct {
		l []int
		v int
		r bool
	}{
		{
			l: []int{1, 2, 3},
			v: 2,
			r: true,
		},

		{
			l: []int{1, 2, 3},
			v: 4,
			r: false,
		},

		{
			l: nil,
			v: 2,
			r: false,
		},

		{
			l: []int{1, 2, 3, 2},
			v: 2,
			r: true,
		},
	}

	for _, c := range tests {
		r := contains(c.v, c.l)
		if r != c.r {
			t.Fatalf("expected %t but got %t for value %d", c.r, r, c.v)
		}
	}
}

func Test_generateEntropy(t *testing.T) {
	tests := []struct {
		strength int
		err      bool
	}{
		{
			strength: 100,
			err:      true,
		},

		{
			strength: 160,
			err:      false,
		},

		{
			strength: 256,
			err:      false,
		},

		{
			strength: 300,
			err:      true,
		},
	}

	for _, c := range tests {
		d, err := GenerateEntropy(c.strength)
		if err != nil {
			if c.err {
				continue
			}

			t.Fatalf("unexpected error for strength %d: %v", c.strength, err)
		}

		if len(d)*8 != c.strength {
			t.Fatalf("expected %d bits but got %d", c.strength, len(d)*8)
		}
	}
}

func Test_getEntropyBits(t *testing.T) {
	tests := []struct {
		entropy []byte
		result  string
		err     bool
	}{
		{
			entropy: []byte{157, 139, 19, 71, 158, 100, 239, 50, 20, 107, 23, 98},
			err:     true,
		},

		{
			entropy: []byte{119, 253, 211, 38, 253, 249, 106, 172, 160, 203, 84, 191, 36, 86, 181, 56},
			result:  "01110111111111011101001100100110111111011111100101101010101011001010000011001011010101001011111100100100010101101011010100111000",
		},
	}

	for _, c := range tests {
		r, err := getEntropyBits(c.entropy)
		if err != nil {
			if c.err {
				continue
			}

			t.Fatalf("unexpcted error: %v", err)
		}

		if r != c.result {
			t.Fatalf("expected %s bits but got %s", c.result, r)
		}
	}
}

func Test_wordIDx(t *testing.T) {
	tests := []struct {
		bits  string
		sbits []string
		err   bool
	}{
		{
			bits: "1111101000010100111010001110011011101110100111001111110100111010001010100010110011111111100001010110",
			err:  true,
		},

		{
			bits: "111110010001100111100011001011011011000101000100100100111000110001001000100011110101010010101000100010110010100110001110111111000000",
			sbits: []string{
				"11111001000",
				"11001111000",
				"11001011011",
				"01100010100",
				"01001001001",
				"11000110001",
				"00100010001",
				"11101010100",
				"10101000100",
				"01011001010",
				"01100011101",
				"11111000000",
			},
		},
	}

	for _, c := range tests {
		sbits, err := wordIDxs(c.bits)
		if err != nil {
			if c.err {
				continue
			}

			t.Fatalf("unexpected error: %v", err)
		}

		if !reflect.DeepEqual(c.sbits, sbits) {
			t.Fatalf("wordIdx mismatch")
		}
	}
}

func Test_wordsFromIDxs(t *testing.T) {
	tests := []struct {
		wordsIDxs []string
		words     []string
		err       bool
	}{

		{
			wordsIDxs: []string{
				"11111001000",
				"11001111000",
				"11001011011",
				"01100010100",
				"01001001001",
				"randomstring",
				"00100010001",
				"11101010100",
				"10101000100",
				"01011001010",
				"01100011101",
				"11111000000",
			},
			err: true,
		},

		{
			wordsIDxs: []string{
				"11111001000",
				"11001111000",
				"11001011011",
				"01100010100",
				"01001001001",
				"11000110001",
				"00100010001",
				"11101010100",
				"10101000100",
				"01011001010",
				"01100011101",
				"11111000000",
			},

			words: []string{
				"weekend",
				"someone",
				"slice",
				"glad",
				"empty",
				"shiver",
				"captain",
				"tunnel",
				"possible",
				"flock",
				"glove",
				"way",
			},
		},
	}

	wordList, err := loadWords("./wordlist/english.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range tests {
		words, err := wordsFromIDxs(c.wordsIDxs, wordList)
		if err != nil {
			if c.err {
				continue
			}

			t.Fatalf("unexpected err: %v", err)
		}

		if !reflect.DeepEqual(words, c.words) {
			t.Fatalf("words mismatch: expected %v got %v", c.words, words)
		}
	}
}

func TestToSeed(t *testing.T) {
	tests := []struct {
		mnemonic []string
		password string
		seed     string
	}{
		{
			mnemonic: []string{"analyst", "latin", "claw", "cube", "pelican", "copy", "clap", "royal", "task", "elegant", "gravity", "during", "nut", "situate", "seat"},
			seed:     "70e8290d465c494b093076f51adb77f09b91334559e1abd32164c5536cb11a82ead3a1af267ff9888f948f20618da4eb8f7dd2b7225e6bea549678db1ec51c42",
		},

		{
			mnemonic: []string{"analyst", "latin", "claw", "cube", "pelican", "copy", "clap", "royal", "task", "elegant", "gravity", "during", "nut", "situate", "seat"},
			password: "password",
			seed:     "b693da578716e078a3e533d62ec0b86528cb9edcfcb31dddd31943bde9eff841a2c94edd502d4e705a6e701fd0c0da6390d564df8b8fc45e47d445ad80262493",
		},
	}

	for _, c := range tests {
		r := ToSeed(c.mnemonic, c.password)
		if c.seed != r {
			t.Fatalf("expected %s seed but got %s", c.seed, r)
		}
	}
}
