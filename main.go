/*
Serve is a very simple static file server in go
Usage:
	-p="8100": port to serve on
	-d=".":    the directory of static files to host
Navigating to http://localhost:8100 will display the index.html or directory
listing file.
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

func main() {
	port := flag.String("p", "8080", "port to serve on")
	directory := flag.String("d", ".", "the directory of static file to host")
	secure := flag.Bool("s", false, "use self signed https")
	flag.Parse()

	http.Handle("/", http.FileServer(http.Dir(*directory)))

	if *secure {
		if !exists("cert.pem") || !exists("key.pem") {
			log.Println("Generating certificates")
			GenerateCertificate()
		}
		log.Printf("Serving %s on HTTPS port: %s\n", *directory, *port)
		log.Fatal(http.ListenAndServeTLS(":"+*port, "cert.pem", "key.pem", nil))
	} else {
		log.Printf("Serving %s on HTTP port: %s\n", *directory, *port)
		log.Fatal(http.ListenAndServe(":"+*port, nil))
	}
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func GenerateCertificate() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	ioutil.WriteFile("cert.pem", out.Bytes(), os.ModePerm)
	fmt.Println(out.String())
	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))
	ioutil.WriteFile("key.pem", out.Bytes(), os.ModePerm)
	fmt.Println(out.String())
}

func exists(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}
