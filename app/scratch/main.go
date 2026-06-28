package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

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
	hash1 := crypto.Keccak256(stamp, data)
	fmt.Println("HASH: ", hexutil.Encode(hash1))

	sig, err := crypto.Sign(hash1, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	sigHash := hexutil.Encode(sig)

	fmt.Println("SIG: ", sigHash)

	// Capture the public key associated with this data and signature.
	publicKey, err := crypto.SigToPub(hash1, sig)
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
	hash2 := crypto.Keccak256(stamp2, data2)
	fmt.Println("HASH2: ", hexutil.Encode(hash2))

	sig2, err := crypto.Sign(hash2, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	sigHash2 := hexutil.Encode(sig2)
	fmt.Println("SIG2: ", sigHash2)

	// Capture the public key associated with this data and signature.
	publicKey2, err := crypto.SigToPub(hash2, sig2)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	// Extract the account address from the public key.
	address2 := crypto.PubkeyToAddress(*publicKey2).String()
	fmt.Println("ADDRESS2: ", address2)

	v, r, s, err := ToVRSFromHexSignature(sigHash2)
	if err != nil {
		return fmt.Errorf("unable to VRS: %w", err)
	}

	fmt.Println("V|R|S", v, r, s)

	return nil
}

// ToVRSFromHexSignature converts a hex representation of the signature into
// its R, S and V parts.
func ToVRSFromHexSignature(sigStr string) (v, r, s *big.Int, err error) {
	sig, err := hex.DecodeString(sigStr[2:])
	if err != nil {
		return nil, nil, nil, err
	}

	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64]})

	return v, r, s, nil
}
