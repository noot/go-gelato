package gelato

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	forwardRequestTypehash = crypto.Keccak256Hash([]byte("ForwardRequest(uint256 chainId,address target,bytes data,address feeToken,uint256 paymentType,uint256 maxFee,uint256 gas,address sponsor,uint256 sponsorChainId,uint256 nonce,bool enforceSponsorNonce,bool enforceSponsorNonceOrdering)"))
)

func padBytesLeft(in []byte, n int) []byte {
	if len(in) > n {
		return in // error probably
	}

	out := make([]byte, n-len(in))
	return append(out, in...)
}

// GetFunctionSignature returns the 4-byte function signature of a Solidity function.
func GetFunctionSignature(fn string) []byte {
	hash := crypto.Keccak256Hash([]byte(fn))
	return hash[:4]
}

func getEIP712DomainSeparator(name, version []byte, chainID *big.Int, address ethcommon.Address) ([32]byte, error) {
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create bytes32 type: %w", err)
	}

	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create address type: %w", err)
	}

	eip712DomainHash := crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	var chainIDArr [32]byte
	copy(chainIDArr[:], padBytesLeft(chainID.Bytes(), 32))

	args := &abi.Arguments{
		{
			Type: bytes32Ty,
		},
		{
			Type: bytes32Ty,
		},
		{
			Type: bytes32Ty,
		},
		{
			Type: bytes32Ty,
		},
		{
			Type: addressTy,
		},
	}
	domainSeparatorPreimage, err := args.Pack(
		eip712DomainHash,
		crypto.Keccak256Hash(name),
		crypto.Keccak256Hash(version),
		chainIDArr,
		address,
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create domainSeparatorPreimage: %w", err)
	}

	return crypto.Keccak256Hash(domainSeparatorPreimage), nil
}

// GetForwardRequestDigestToSign returns a 32-byte digest for signing
func GetForwardRequestDigestToSign(req *ForwardRequest) ([32]byte, error) {
	relayAddress := getRelayForwarderAddress(req.ChainID)
	domainSeparator, err := getEIP712DomainSeparator(
		[]byte("GelatoRelayForwarder"),
		[]byte("V1"),
		req.ChainID,
		relayAddress,
	)
	if err != nil {
		return [32]byte{}, err
	}

	uint256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create uint256 type: %w", err)
	}

	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create bytes32 type: %w", err)
	}

	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create address type: %w", err)
	}

	boolTy, err := abi.NewType("bool", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to create bool type: %w", err)
	}

	// https://github.com/gelatodigital/relay-sdk/blob/8a9b9b2d0ef92ea9a3d6d64a230d9467a4b4da6d/src/constants/index.ts#L14
	hashedData := crypto.Keccak256Hash(req.Data)

	args := &abi.Arguments{
		{
			Type: bytes32Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: addressTy,
		},
		{
			Type: bytes32Ty,
		},
		{
			Type: addressTy,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: addressTy,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: boolTy,
		},
		{
			Type: boolTy,
		},
	}
	hashPreimage, err := args.Pack(
		forwardRequestTypehash,
		req.ChainID,
		req.Target,
		hashedData,
		ethcommon.HexToAddress(req.FeeToken),
		req.PaymentType,
		req.MaxFee,
		req.Gas,
		req.Sponsor,
		req.SponsorChainID,
		req.Nonce,
		req.EnforceSponsorNonce,
		req.EnforceSponsorNonceOrdering,
	)
	if err != nil {
		return [32]byte{}, err
	}

	hash := crypto.Keccak256Hash(hashPreimage)

	// what is this from?
	// https://github.com/gelatodigital/relay-sdk/blob/162f6392fb23bf52ef32f4c96168bc0433a5b0c0/src/lib/index.ts#L337
	prefix, err := hex.DecodeString("1901")
	if err != nil {
		return [32]byte{}, err
	}

	digestPreimage := append(append(prefix, domainSeparator[:]...), hash[:]...)
	return crypto.Keccak256Hash(digestPreimage), nil
}
