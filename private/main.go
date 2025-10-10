package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"golang.org/x/crypto/sha3" // for Keccak-256
)

// secp256k1 curve order (n)
const curveOrderHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

var curveOrder *big.Int

func init() {
	n, ok := new(big.Int).SetString(curveOrderHex, 16)
	if !ok {
		log.Fatal("failed to parse curve order")
	}
	curveOrder = n
}

// padHex returns hex string of len bytes*2 (no "0x")
func padHex(b []byte, bytes int) string {
	hexs := hex.EncodeToString(b)
	// ensure length (left-pad with zeros if needed)
	if len(hexs) < bytes*2 {
		padding := make([]byte, bytes*2-len(hexs))
		for i := range padding {
			padding[i] = '0'
		}
		hexs = string(padding) + hexs
	}
	return hexs
}

// GeneratePrivKeyRandom generates a 32-byte (256-bit) private key
// by reading 32 bytes from a CSPRNG and checking 1 <= key < n.
// Repeats until a valid key is found.
func GeneratePrivKeyRandom() ([]byte, *big.Int, error) {
	for {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			return nil, nil, err
		}
		k := new(big.Int).SetBytes(b)
		// k in [0, 2^256-1]; valid if 1 <= k < curveOrder
		if k.Sign() == 0 {
			// zero -> invalid, try again
			continue
		}
		if k.Cmp(curveOrder) >= 0 {
			// >= n -> invalid, try again
			continue
		}
		return b, k, nil
	}
}

// GeneratePrivKeyFromHash takes extra random bytes, hashes them to produce 256 bits,
// then checks the valid range 1 <= k < n.
// hashType: "keccak" or "sha256"
func GeneratePrivKeyFromHash(hashType string, randomBytesLen int) ([]byte, *big.Int, error) {
	for {
		buf := make([]byte, randomBytesLen)
		_, err := rand.Read(buf)
		if err != nil {
			return nil, nil, err
		}

		var h []byte
		switch hashType {
		case "keccak":
			sum := sha3.NewLegacyKeccak256()
			sum.Write(buf)
			h = sum.Sum(nil) // 32 bytes
		case "sha256":
			s := sha256.Sum256(buf)
			h = s[:]
		default:
			return nil, nil, fmt.Errorf("unknown hash type: %s", hashType)
		}

		k := new(big.Int).SetBytes(h)
		if k.Sign() == 0 || k.Cmp(curveOrder) >= 0 {
			// invalid -> try again
			continue
		}
		return h, k, nil
	}
}

func main() {
	// Method 1: direct 32 bytes from CSPRNG
	privBytes, privInt, err := GeneratePrivKeyRandom()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Private key (method 1, raw random): 0x" + padHex(privBytes, 32))
	fmt.Println("Private key (big.Int):", privInt.Text(16))

	// Method 2: hash extra entropy (Keccak-256)
	privBytes2, privInt2, err := GeneratePrivKeyFromHash("keccak", 64) // 64 bytes random -> keccak -> 32 bytes
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Private key (method 2, keccak of extra entropy): 0x" + padHex(privBytes2, 32))
	fmt.Println("Private key (big.Int):", privInt2.Text(16))

	// Method 3: hash extra entropy (SHA-256) - optional
	privBytes3, privInt3, err := GeneratePrivKeyFromHash("sha256", 64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Private key (method 3, sha256 of extra entropy): 0x" + padHex(privBytes3, 32))
	fmt.Println("Private key (big.Int):", privInt3.Text(16))

	// Warning/reminder
	fmt.Println("\nWARNING: Do NOT run this on an online/untrusted machine to generate real funds' keys.")
	fmt.Println("Use hardware wallets or air-gapped devices for production/private use.")
}
