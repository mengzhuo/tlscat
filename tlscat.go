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
	verbose           = flag.Bool("v", false, "Verbose Output")
	starttls          = flag.Bool("s", false, "SMTP STARTTLS support")
)

func verbosePrintf(str string, args ...interface{}) {
	if *verbose {
		fmt.Printf(str, args...)
	}
}

func errorCheckf(err error, str string, args ...interface{}) {

	if err != nil {
		fmt.Printf(str, args...)
		fmt.Printf("Due to %s\n", err)
		if *verbose {
			panic(err)
		}
		os.Exit(1)
	}
}

func main() {

	flag.Parse()
	if *listenPort < 65536 && 0 < *listenPort {
		ServerMode()
	} else {
		ClientMode()
	}
}

func recv(conn net.Conn) {

	b := make([]byte, 2048)
	conn.Read(b)
	verbosePrintf("Starttls recv:%s", b)
}

func StartTLS(conn net.Conn) bool {

	recv(conn)

	conn.Write([]byte("EHLO example.com\r\n"))
	recv(conn)

	conn.Write([]byte("STARTTLS\r\n"))
	recv(conn)
	recv(conn)

	return true
}

func ClientMode() {

	args := flag.Args()
	if len(args) < 2 {
		fmt.Printf("Not enough for address and port, only get %s", args)
		os.Exit(2)
	}
	addr := args[0]
	port := args[1]
	verbosePrintf("Connecting %s:%s\n", addr, port)

	var conn net.Conn
	var err error
	endpoint := fmt.Sprintf("%s:%s", addr, port)
	tls_config := &tls.Config{ServerName: addr}

	if *starttls {
		conn, err = net.Dial("tcp", endpoint)
		errorCheckf(err, "Connect failed %s", endpoint)
		if StartTLS(conn) {
			conn = tls.Client(conn, tls_config)
		}
	} else {
		conn, err = tls.Dial("tcp", endpoint, tls_config)
		errorCheckf(err, "Can not connect to %s:%s", addr, port)
	}

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			buf := scanner.Bytes()
			buf = append(buf, []byte("\n")...)
			if *verbose {
				fmt.Printf("Sending: %x\n", buf)
			}
			conn.Write(buf)
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Scanner end:%s\n", err)
		}
	}()
	for {
		b := make([]byte, 2048)
		n, err := conn.Read(b)
		errorCheckf(err, "Error")
		if n != 0 {
			fmt.Print(string(b))
		} else {
			verbosePrintf("Disconnected")
			break
		}
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
		errorCheckf(err, "Parsing Error")
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
