package mnemonic

import "testing"

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
