package spdz2

import "testing"

func TestSpdz2(t *testing.T) {
	t.Run("spdz2Test", func(t *testing.T) {
		GenTriple2(8, 64, 8)
	})
}
