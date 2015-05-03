package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
)

const (
	SelfCert       = ``
	SelfPrivateKey = ""
)

var (
	listenPort        = flag.Int("l", 65536, "The port to listen")
	certificationFile = flag.String("c", "", "Certification file")
	privateKeyFile    = flag.String("k", "", "Private Key file")
)

func main() {
	flag.Parse()
	if *listenPort < 65536 && 0 < *listenPort {
		ServerMode()
	} else {
		ClientMode()
	}
}

func ClientMode() {

	addr := os.Args[1]
	port := os.Args[2]

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", addr, port), &tls.Config{})
	if err != nil {
		fmt.Printf("Can not connect to %s:%s due to %s", addr, port, err)
		os.Exit(1)
	}
	go func(conn net.Conn) {
		b := make([]byte, 2048)
		conn.Read(b)
		fmt.Println(b)
	}(conn)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		conn.Write(scanner.Bytes())
	}

}

func ServerMode() {
	var (
		s        net.Listener
		certPair tls.Certificate
		err      error
	)

	if *certificationFile != "" && *privateKeyFile != "" {
		certPair, err = tls.LoadX509KeyPair(*certificationFile, *privateKeyFile)
		if err != nil {
			fmt.Printf("Parsing error:%s", err)
			return
		}
	} else {
		// Load a made cert
	}
	fmt.Printf("Cert:%x\nPrivateKey:%x\n", certPair.Certificate, certPair.PrivateKey)
	config := tls.Config{Certificates: []tls.Certificate{certPair}}
	s, err = tls.Listen("tcp", fmt.Sprintf(":%d", *listenPort), &config)
	if err != nil {
		panic(err)
	}

	// Only accept the first one
	con, _ := s.Accept()
	defer con.Close()

	for {
		b := make([]byte, 2048)
		n, err := con.Read(b)
		if n == 0 || err != nil {
			return
		}
		fmt.Print(string(b))
	}
}