package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/noot/go-gelato"

	ethcommon "github.com/ethereum/go-ethereum/common"
)

func main() {
	// generate new random keypair
	key, err := gelato.GenerateKey()
	if err != nil {
		panic(err)
	}

	fmt.Printf("sponsor address: %s\n", key.Address())

	// build request
	var (
		chainID        = big.NewInt(5) // goerli
		targetContract = ethcommon.HexToAddress("0x8580995EB790a3002A55d249e92A8B6e5d0b384a")
		nativeToken    = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
		paymentType    = big.NewInt(1)
		maxFee         = big.NewInt(1000000000000000000) // wei
		gas            = big.NewInt(200000)
		nonce          = big.NewInt(0)
	)

	// TODO: generate this from function signature
	calldata, err := hex.DecodeString("4b327067000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeaeeeeeeeeeeeeeeeee")
	if err != nil {
		panic(err)
	}

	req := &gelato.ForwardRequest{
		ChainID:                     chainID,
		Target:                      targetContract,
		Data:                        calldata,
		FeeToken:                    nativeToken,
		PaymentType:                 paymentType,
		MaxFee:                      maxFee,
		Gas:                         gas,
		Sponsor:                     key.Address(),
		SponsorChainID:              chainID,
		Nonce:                       nonce,
		EnforceSponsorNonce:         false,
		EnforceSponsorNonceOrdering: true,
	}

	digest, err := gelato.GetForwardRequestDigestToSign(req)
	if err != nil {
		panic(err)
	}

	sig, err := key.Sign(digest)
	if err != nil {
		panic(err)
	}

	resp, err := gelato.SendForwardRequest(req, sig)
	if err != nil {
		panic(err)
	}

	fmt.Println("request submitted successfully!")
	fmt.Println("taskId:", resp.TaskID)
}
