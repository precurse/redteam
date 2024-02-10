#!/usr/bin/env python3

from typing import Iterator
from base64 import b64encode


# Taken from: https://gist.github.com/hsauers5/491f9dde975f1eaa97103427eda50071
def key_scheduling(key: bytes) -> list[int]:
	sched = [i for i in range(0, 256)]

	i = 0
	for j in range(0, 256):
		i = (i + sched[j] + key[j % len(key)]) % 256
		tmp = sched[j]
		sched[j] = sched[i]
		sched[i] = tmp

	return sched

def stream_generation(sched: list[int]) -> Iterator[bytes]:
	i, j = 0, 0
	while True:
		i = (1 + i) % 256
		j = (sched[i] + j) % 256
		tmp = sched[j]
		sched[j] = sched[i]
		sched[i] = tmp
		yield sched[(sched[i] + sched[j]) % 256]        

def encrypt(plaintext: bytes, key: bytes) -> bytes:
	sched = key_scheduling(key)
	key_stream = stream_generation(sched)
	
	ciphertext = b''
	for char in plaintext:
		enc = char ^ next(key_stream)
		ciphertext += bytes([enc])
		
	return ciphertext
