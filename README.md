# Problem Statement
Write an **eBPF** code to drop the **TCP packets** on a port (def: 4040). Additionally, make the port number configurable from the userspace.

## How to run 
```bash
go generate
go build && ./eBPF 
```
