package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Tx is the transactional information between two parties.
type Tx struct {
	FromID string `json:"from"`  // Ethereum: Account sending the transaction. Will be checked against signature.
	ToID   string `json:"to"`    // Ethereum: Account receiving the benefit of the transaction.
	Value  uint64 `json:"value"` // Ethereum: Monetary value received from this transaction.
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	//privateKey, err := crypto.GenerateKey()
	//if err != nil {
	//	return err
	//}

	tx := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Arthur",
		Value:  1000,
	}

	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("unable to load private key for node: %w", err)
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	stamp := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	v := crypto.Keccak256(stamp, data)
	fmt.Println("HASH: ", hexutil.Encode(v))

	sig, err := crypto.Sign(v, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	sigHash := hexutil.Encode(sig)

	fmt.Println("SIG: ", sigHash)

	// Capture the public key associated with this data and signature.
	publicKey, err := crypto.SigToPub(v, sig)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	// Extract the account address from the public key.
	address := crypto.PubkeyToAddress(*publicKey).String()
	fmt.Println("ADDRESS: ", address)

	// =============================================================================
	// OVER THE WIRE

	tx2 := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Nicola",
		Value:  250,
	}

	data2, err := json.Marshal(tx2)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	stamp2 := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data2)))
	v2 := crypto.Keccak256(stamp2, data2)
	fmt.Println("HASH2: ", hexutil.Encode(v2))

	sig2, err := crypto.Sign(v2, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	sigHash2 := hexutil.Encode(sig2)
	fmt.Println("SIG2: ", sigHash2)

	// Capture the public key associated with this data and signature.
	publicKey2, err := crypto.SigToPub(v2, sig2)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	// Extract the account address from the public key.
	address2 := crypto.PubkeyToAddress(*publicKey2).String()
	fmt.Println("ADDRESS2: ", address2)

	return nil
}
