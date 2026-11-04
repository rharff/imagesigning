package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"imgsign/pkg/keys"
	"imgsign/pkg/signer"
	"imgsign/pkg/store"
	"imgsign/pkg/verifier"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var rejection *verifier.Rejection
		if errors.As(err, &rejection) {
			fmt.Fprintf(os.Stderr, "REJECT %s\n", rejection.Code)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "ERROR %v\n", err)
		os.Exit(2)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out-dir", "./keys", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := keys.Generate()
	if err != nil {
		return err
	}
	return keys.SavePair(*out, key)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", os.Getenv("IMGSIGN_PRIVATE_KEY"), "private key PEM path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("sign requires one image reference")
	}
	if *keyPath == "" {
		return errors.New("--key or IMGSIGN_PRIVATE_KEY is required")
	}
	var key *ecdsa.PrivateKey
	var err error
	if strings.Contains(*keyPath, "-----BEGIN") {
		key, err = keys.ParsePrivate([]byte(*keyPath))
	} else {
		key, err = keys.LoadPrivate(*keyPath)
	}
	if err != nil {
		return err
	}
	result, err := signer.Sign(context.Background(), store.NewORASStore(), key, fs.Arg(0), time.Now())
	if err != nil {
		return err
	}
	fmt.Println("signed " + result)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "public key PEM path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || fs.NArg() != 1 {
		return errors.New("--pub and one image reference are required")
	}
	key, err := keys.LoadPublic(*pubPath)
	if err != nil {
		return err
	}
	if err := verifier.Verify(context.Background(), store.NewORASStore(), key, fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("VALID " + strings.TrimSpace(fs.Arg(0)))
	return nil
}

func usage() { fmt.Fprintln(os.Stderr, "usage: imgsign keygen|sign|verify") }
