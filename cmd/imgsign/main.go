package main

import (
	"context"
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
		return
	}
	var err error
	switch os.Args[1] {
	case "-h", "--help", "help":
		usage()
		return
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "verify-detail":
		err = verifyDetail(os.Args[2:])
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
	algorithm := fs.String("alg", keys.ECDSA, "algorithm: ecdsa or mldsa65")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := keys.GenerateAlgorithm(*algorithm)
	if err != nil {
		return err
	}
	return keys.SavePair(*out, key)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", os.Getenv("IMGSIGN_PRIVATE_KEY"), "private key PEM path")
	algorithm := fs.String("alg", keys.ECDSA, "algorithm: ecdsa or mldsa65")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("sign requires one image reference")
	}
	if *keyPath == "" {
		return errors.New("--key or IMGSIGN_PRIVATE_KEY is required")
	}
	var key keys.PrivateKey
	var err error
	if strings.Contains(*keyPath, "-----BEGIN") {
		key, err = keys.ParsePrivate([]byte(*keyPath))
	} else {
		key, err = keys.LoadPrivate(*keyPath)
	}
	if err != nil {
		return err
	}
	result, err := signer.Sign(context.Background(), store.NewORASStore(), key, *algorithm, fs.Arg(0), time.Now())
	if err != nil {
		return err
	}
	fmt.Println("signed " + result)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "public key PEM path")
	algorithm := fs.String("alg", keys.ECDSA, "algorithm: ecdsa or mldsa65")
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
	if err := verifier.Verify(context.Background(), store.NewORASStore(), key, *algorithm, fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("VALID " + strings.TrimSpace(fs.Arg(0)))
	return nil
}

func verifyDetail(args []string) error {
	fs := flag.NewFlagSet("verify-detail", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "public key PEM path")
	privPath := fs.String("priv", "", "optional private key path; only its file size is reported")
	algorithm := fs.String("alg", keys.ECDSA, "algorithm: ecdsa or mldsa65")
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
	report, verifyErr := verifier.VerifyDetail(context.Background(), store.NewORASStore(), key, *algorithm, fs.Arg(0), *pubPath, *privPath)
	data, err := report.JSON()
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return verifyErr
}

func usage() {
	fmt.Println(`Usage:
  imgsign <command> [options]

Commands:
  keygen          Generate an ECDSA or ML-DSA-65 key pair
  sign            Sign a container image
  verify          Verify an image signature
  verify-detail   Verify and print detailed metrics as JSON

Global options:
  -h, --help      Show this help

Examples:
  imgsign keygen --alg ecdsa --out-dir ./keys
  imgsign keygen --alg mldsa65 --out-dir ./keys-mldsa
  imgsign sign --alg ecdsa --key ./keys/priv.pem IMAGE
  imgsign verify --alg ecdsa --pub ./keys/pub.pem IMAGE
  imgsign verify-detail --alg ecdsa --pub ./keys/pub.pem IMAGE

Run "imgsign <command> -h" for command-specific options.`)
}
