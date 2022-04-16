package spdz2

import "testing"

func TestSpdz(t *testing.T) {
	t.Run("1goroutine", func(t *testing.T) {
		genTriple(2)
	})
	t.Run("numgoroutine", func(t *testing.T) {
		GenTriple(3)
	})
}
