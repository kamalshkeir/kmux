// Copyright 2016 The Kago Author. All rights reserved.  

//go:build appengine
// +build appengine

package ws

func maskBytes(key [4]byte, pos int, b []byte) int {
	for i := range b {
		b[i] ^= key[pos&3]
		pos++
	}
	return pos & 3
}
