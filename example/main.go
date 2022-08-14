package main

import (
	"fmt"
	"math/big"

	"github.com/noot/go-gelato"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
)

// this example is equivalent to https://docs.gelato.network/developer-products/gelato-relay-sdk/quick-start
func main() {
	// generate new random keypair
	key, err := gelato.GenerateKey()
	if err != nil {
		panic(err)
	}

	fmt.Printf("sponsor address: %s\n", key.Address())

	// build request
	var (
		chainID = big.NewInt(5) // goerli
		// https://goerli.etherscan.io/address/0x8580995EB790a3002A55d249e92A8B6e5d0b384a#code
		targetContract = ethcommon.HexToAddress("0x8580995EB790a3002A55d249e92A8B6e5d0b384a")
		nativeToken    = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
		paymentType    = big.NewInt(1)
		maxFee         = big.NewInt(1000000000000000000) // wei
		gas            = big.NewInt(200000)
		nonce          = big.NewInt(0)
	)

	// encode transaction data
	functionSig := gelato.GetFunctionSignature("sayHiVanilla(address)")

	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		panic(err)
	}

	args := &abi.Arguments{
		{
			Type: addressTy,
		},
	}
	calldata, err := args.Pack(ethcommon.HexToAddress(nativeToken))
	if err != nil {
		panic(err)
	}

	data := append(functionSig, calldata...)

	req := &gelato.ForwardRequest{
		ChainID:                     chainID,
		Target:                      targetContract,
		Data:                        data,
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

	// get digest to sign
	digest, err := gelato.GetForwardRequestDigestToSign(req)
	if err != nil {
		panic(err)
	}

	// sign and send
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
