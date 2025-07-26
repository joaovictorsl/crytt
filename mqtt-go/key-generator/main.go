package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

const (
	rsaKeySizeBits = 2048 // Standard size for RSA keys
)

// KeyPair represents the structure for the JSON output.
type KeyPair struct {
	IDUnidade         string `json:"id_unidade"`
	ChavePublicaRSA   string `json:"chave_publica_rsa"`
	ChavePublicaECDSA string `json:"chave_publica_ecdsa"`
}

func main() {
	// Default unit ID
	unitID := "ut-alfa"

	// Parse command-line arguments for unit ID
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-id":
			if i+1 < len(os.Args) {
				unitID = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -id requires a value.")
				printUsage()
				os.Exit(1)
			}
		case "-h", "--help":
			printUsage()
			os.Exit(0)
		default:
			fmt.Printf("Unknown argument: %s\n", os.Args[i])
			printUsage()
			os.Exit(1)
		}
	}

	// 1. Generate RSA Key Pair
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySizeBits)
	if err != nil {
		fmt.Printf("Failed to generate RSA private key: %v\n", err)
		os.Exit(1)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	// 2. Generate ECDSA Key Pair (using P-256 curve)
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA private key: %v\n", err)
		os.Exit(1)
	}
	ecdsaPublicKey := &ecdsaPrivateKey.PublicKey

	// 3. Encode Public Keys to DER format (ASN.1)
	rsaPubDER, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal RSA public key: %v\n", err)
		os.Exit(1)
	}

	ecdsaPubDER, err := x509.MarshalPKIXPublicKey(ecdsaPublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal ECDSA public key: %v\n", err)
		os.Exit(1)
	}

	// 4. Base64 Encode the DER Public Keys
	rsaPubKeyB64 := base64.StdEncoding.EncodeToString(rsaPubDER)
	ecdsaPubKeyB64 := base64.StdEncoding.EncodeToString(ecdsaPubDER)

	// 5. Create the JSON structure
	keyPairData := KeyPair{
		IDUnidade:         unitID,
		ChavePublicaRSA:   rsaPubKeyB64,
		ChavePublicaECDSA: ecdsaPubKeyB64,
	}

	// 6. Marshal to JSON (no indent for single line output)
	jsonData, err := json.Marshal(keyPairData) // Changed from json.MarshalIndent
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		os.Exit(1)
	}

	// 7. Print the JSON output to stdout
	fmt.Println(string(jsonData))
}

func printUsage() {
	fmt.Println("Usage: go run main.go [-id <unit_id>]")
	fmt.Println("  -id        Identifier for the unit (e.g., ut-alfa)")
	fmt.Println("  -h, --help  Show this help message")
}
