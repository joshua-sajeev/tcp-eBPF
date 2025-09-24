package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux counter bpf_src/counter.c
