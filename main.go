package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "lo"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DropTcpPacket,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	var prevCount uint64
	var prevDrop uint64

	for {
		select {
		case <-tick:
			var count uint64
			if err := objs.PktCount.Lookup(uint32(0), &count); err != nil {
				log.Fatal("Map lookup:", err)
			}

			var dropCount uint64
			if err := objs.PktCount.Lookup(uint32(1), &dropCount); err != nil {
				log.Fatal("Map lookup:", err)
			}

			if count != prevCount || dropCount != prevDrop {
				log.Printf("Received %d packets, Dropped %d packets", count, dropCount)
				prevCount = count
				prevDrop = dropCount
			}

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
