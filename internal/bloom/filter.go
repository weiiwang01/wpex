package bloom

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

type Filter struct {
	array []byte
	salt  []byte
	k     uint64
	lock  sync.Mutex
}

func (f *Filter) hash(k uint64, d []byte) uint64 {
	hash := sha256.New()
	hash.Write(f.salt)
	ka := make([]byte, 8)
	binary.BigEndian.PutUint64(ka, k)
	hash.Write(ka)
	hash.Write(d)
	offset := binary.BigEndian.Uint64(hash.Sum(nil))
	return offset % (uint64(len(f.array)) * 8)
}

// Add inserts the provided element into the filter.
func (f *Filter) Add(elem []byte) {
	f.lock.Lock()
	defer f.lock.Unlock()
	for k := uint64(0); k < f.k; k++ {
		offset := f.hash(k, elem)
		byteOffset := offset / 8
		mask := byte(1) << (7 - offset%8)
		f.array[byteOffset] |= mask
	}
}

// Contains checks if the provided element might be in the filter.
func (f *Filter) Contains(elem []byte) bool {
	f.lock.Lock()
	defer f.lock.Unlock()
	for k := uint64(0); k < f.k; k++ {
		offset := f.hash(k, elem)
		byteOffset := offset / 8
		mask := byte(1) << (7 - offset%8)
		if f.array[byteOffset]&mask == 0 {
			return false
		}
	}
	return true
}

// MakeFilter constructs and returns a new Bloom filter with the specified parameters.
// m is the size of the bit array in bits, and k is the number of hash functions to use.
// A salt can be provided to introduce variability in the hash computations.
func MakeFilter(m uint64, k uint64, salt []byte) Filter {
	return Filter{
		array: make([]byte, (m+7)/8),
		salt:  salt,
		k:     k,
	}
}
