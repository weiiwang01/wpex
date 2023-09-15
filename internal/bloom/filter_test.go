package bloom

import (
	"math/rand"
	"testing"
)

func TestFilter(t *testing.T) {
	filter := MakeFilter(1024*1000, 1, nil)
	var data [][]byte
	for i := 0; i < 5000; i++ {
		d := make([]byte, 64)
		rand.Read(d)
		data = append(data, d)
		filter.Add(d)
		for _, d := range data {
			if !filter.Contains(d) {
				t.Errorf("testing an known existing element should return true")
			}
		}
	}
	var falsePositives float64 = 0
	test := 5000
	for i := 0; i < test; i++ {
		d := make([]byte, 64)
		rand.Read(d)
		if filter.Contains(d) {
			falsePositives += 1
		}
	}
	if falsePositives > 0.01*float64(test) {
		t.Errorf("false positive rate too high, excepted > 0.01, got %f", falsePositives/float64(test))
	}
}
