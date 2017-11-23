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
