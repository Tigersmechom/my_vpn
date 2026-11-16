package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"myvpn/health"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ca := flag.String("ca-file", "", "Optional platform trust roots exported by the Android app")
	flag.Parse()
	var roots *x509.CertPool
	if *ca != "" {
		b, e := os.ReadFile(*ca)
		if e != nil || len(b) > 1048576 {
			os.Exit(2)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			os.Exit(2)
		}
	}
	engine := health.New(roots)
	defer engine.Stop()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	go func() { <-signals; engine.Stop(); os.Exit(0) }()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 1048577)
	for scanner.Scan() {
		reply := engine.Check(scanner.Bytes())
		if !json.Valid(reply) {
			reply = []byte(`{"error":"internal","results":[]}`)
		}
		fmt.Println(string(reply))
	}
}
