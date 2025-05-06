package util

// -----------------------------------------------------------------------------

// SafeZeroMem zeros the given memory.
func SafeZeroMem(v []byte) {
	vLen := len(v)
	if vLen > 0 {
		v[0] = 0
		for ofs := 1; ofs < vLen; ofs *= 2 {
			copy(v[ofs:], v[:ofs])
		}
	}
}

// SafeZeroMemArray zeros the given memory array.
func SafeZeroMemArray(v [][]byte) {
	vLen := len(v)
	for idx := 0; idx < vLen; idx++ {
		SafeZeroMem(v[idx])
	}
}
