package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux counter bpf_src/xdp_drop_tcp.c

func main() {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	defaultPort := uint16(4040)
	if err := objs.Config.Put(uint32(0), defaultPort); err != nil {
		log.Fatal("Setting default port:", err)
	}

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
	log.Printf("Current drop port: %d", defaultPort)
	log.Println("Commands:")
	log.Println("  Type 'port XXXX' to change port (e.g., 'port 8080')")
	log.Println("  Type 'status' to see current stats")
	log.Println("  Type 'quit' or Ctrl+C to exit")

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	userInput := make(chan string, 10)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			userInput <- scanner.Text()
		}
	}()

	var prevCount uint64
	var prevDrop uint64
	currentPort := defaultPort

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
				log.Printf("Received %d packets, Dropped %d packets (port %d)",
					count, dropCount, currentPort)
				prevCount = count
				prevDrop = dropCount
			}

		case input := <-userInput:
			handleUserInput(input, &objs, &currentPort)

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}

func handleUserInput(input string, objs *counterObjects, currentPort *uint16) {
	input = strings.TrimSpace(input)
	parts := strings.Fields(input)

	if len(parts) == 0 {
		return
	}

	command := strings.ToLower(parts[0])

	switch command {
	case "port":
		if len(parts) != 2 {
			log.Println("Usage: port <number> (e.g., port 8080)")
			return
		}

		newPort, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil || newPort == 0 || newPort > 65535 {
			log.Println("Invalid port number. Must be between 1-65535")
			return
		}

		portValue := uint16(newPort)
		if err := objs.Config.Put(uint32(0), portValue); err != nil {
			log.Printf("Error updating port: %v", err)
			return
		}

		*currentPort = portValue
		log.Printf("Port changed to %d", portValue)

	case "status":
		var count uint64
		var dropCount uint64

		objs.PktCount.Lookup(uint32(0), &count)
		objs.PktCount.Lookup(uint32(1), &dropCount)

		log.Printf("Status: Total packets: %d, Dropped: %d, Current port: %d",
			count, dropCount, *currentPort)

	case "quit", "exit":
		log.Println("Exiting...")
		os.Exit(0)

	case "help":
		printHelp()

	default:
		log.Printf("Unknown command: %s. Type 'help' for available commands", command)
	}
}

func printHelp() {
	fmt.Println("\n Available Commands:")
	fmt.Println("  port <number>  - Change the drop port (e.g., 'port 8080')")
	fmt.Println("  status         - Show current statistics")
	fmt.Println("  help          - Show this help message")
	fmt.Println("  quit/exit     - Exit the program")
	fmt.Println("  Ctrl+C        - Force exit")
	fmt.Println()
}
