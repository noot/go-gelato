package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	contentTypeJSON   = "application/json"
	dialTimeout       = 60 * time.Second
	httpClientTimeout = 30 * time.Minute
	callTimeout       = 30 * time.Minute

	transport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: dialTimeout,
		}).Dial,
	}
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   httpClientTimeout,
	}
)

type Key struct {
	priv    *ecdsa.PrivateKey
	pub     ecdsa.PublicKey
	address ethcommon.Address
}

func generateKey() (*Key, error) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	return &Key{
		priv:    priv,
		pub:     priv.PublicKey,
		address: crypto.PubkeyToAddress(priv.PublicKey),
	}, nil
}

// https://github.com/gelatodigital/relay-sdk/blob/162f6392fb23bf52ef32f4c96168bc0433a5b0c0/src/lib/index.ts#L250
type ForwardRequest struct {
	ChainID                     *big.Int          `json:"chainId"`
	Target                      ethcommon.Address `json:"target"`
	FeeToken                    ethcommon.Address `json:"feeToken"`
	Data                        []byte            `json:"data"`
	PaymentType                 *big.Int          `json:"paymentType"`
	MaxFee                      *big.Int          `json:"maxFee"`
	Gas                         *big.Int          `json:"gas"`
	Nonce                       *big.Int          `json:"nonce"`
	EnforceSponsorNonce         bool              `json:"enforceSponsorNonce"`
	Sponsor                     ethcommon.Address `json:"sponsor"`
	SponsorChainID              *big.Int          `json:"sponsorChainId"`
	EnforceSponsorNonceOrdering bool              `json:"enforceSponsorNonceOrdering"`
}

func padBytesLeft(in []byte, n int) []byte {
	if len(in) > n {
		return in // idk error probably
	}

	out := make([]byte, n-len(in))
	return append(out, in...)
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

	// bytesTy, err := abi.NewType("bytes", "", nil)
	// if err != nil {
	// 	return [32]byte{}, fmt.Errorf("failed to create bytes type: %w", err)
	// }

	// args := &abi.Arguments{
	// 	{
	// 		Type: bytesTy,
	// 	},
	// }
	// eip712Domain, err := args.Pack(
	// 	[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
	// )
	// if err != nil {
	// 	return [32]byte{}, err
	// }

	// eip712DomainHash := crypto.Keccak256Hash(eip712Domain)

	// idk just hardcode this for now, i think the "bytes" type in the abi is causing a mismatch
	eip712DomainHash := ethcommon.HexToHash("0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f")
	fmt.Println("eip712DomainHash", eip712DomainHash)

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

func getForwardRequestDigestToSign(req *ForwardRequest) ([32]byte, error) {
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

	fmt.Printf("domainSeparator: %x\n", domainSeparator)

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

	// idk maybe not right cause it's string
	// https://github.com/gelatodigital/relay-sdk/blob/8a9b9b2d0ef92ea9a3d6d64a230d9467a4b4da6d/src/constants/index.ts#L14
	ForwardRequestTypehash := crypto.Keccak256Hash([]byte("ForwardRequest(uint256 chainId,address target,bytes data,address feeToken,uint256 paymentType,uint256 maxFee,uint256 gas,address sponsor,uint256 sponsorChainId,uint256 nonce,bool enforceSponsorNonce,bool enforceSponsorNonceOrdering)"))
	fmt.Println("ForwardRequestTypehash", ForwardRequestTypehash)

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
		ForwardRequestTypehash,
		req.ChainID,
		req.Target,
		crypto.Keccak256Hash(req.Data),
		req.FeeToken,
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

	// wtf is this https://github.com/gelatodigital/relay-sdk/blob/162f6392fb23bf52ef32f4c96168bc0433a5b0c0/src/lib/index.ts#L337
	const prefix = "0x1901"
	return crypto.Keccak256Hash(append(append(ethcommon.Hex2Bytes(prefix), domainSeparator[:]...), hash[:]...)), nil
}

func getRelayForwarderAddress(chainID *big.Int) ethcommon.Address {
	switch chainID.Int64() {
	case 1:
		return ethcommon.HexToAddress("0x5ca448e53e77499222741DcB6B3c959Fa829dAf2")
	case 4:
		return ethcommon.HexToAddress("0x9B79b798563e538cc326D03696B3Be38b971D282")
	case 5:
		return ethcommon.HexToAddress("0x61BF11e6641C289d4DA1D59dC3E03E15D2BA971c")
	case 42:
		return ethcommon.HexToAddress("0x4F36f93F58d36DcbC1E60b9bdBE213482285C482")
	case 56:
		return ethcommon.HexToAddress("0xeeea839E2435873adA11d5dD4CAE6032742C0445")
	case 100:
		return ethcommon.HexToAddress("0xeeea839E2435873adA11d5dD4CAE6032742C0445")
	// case big.NewInt(137):
	// 	return ethcommon.HexToAddress("0xc2336e796F77E4E57b6630b6dEdb01f5EE82383e")
	// case big.NewInt(1284):
	// 	return ethcommon.HexToAddress("0x14cdD6d9eBfbB7DAAF09395E56B2A89905D62b4C")
	// case big.NewInt(1285):
	// 	return ethcommon.HexToAddress("0x79A0cB573D3Db184752511969F1b869A184EA445")
	// case big.NewInt(9001):
	// 	return ethcommon.HexToAddress("0x9561aCdf04C2B639dFfeCB357438e7B3eD979C5C")
	// case big.NewInt(43114):
	// 	return ethcommon.HexToAddress("0x3456E168d2D7271847808463D6D383D079Bd5Eaa")
	// case big.NewInt(44787):
	// 	return ethcommon.HexToAddress("0xc2336e796F77E4E57b6630b6dEdb01f5EE82383e")
	// case big.NewInt(80001):
	// 	return ethcommon.HexToAddress("0x3428E19A01E40333D5D51465A08476b8F61B86f3")
	default:
		panic(fmt.Sprintf("chain ID %s not supported", chainID))
	}

	return ethcommon.Address{}
}

type ForwardRequestData struct {
	TypeID                      string            `json:"typeId"`
	ChainID                     *big.Int          `json:"chainId"`
	Target                      ethcommon.Address `json:"target"`
	FeeToken                    ethcommon.Address `json:"feeToken"`
	Data                        string            `json:"data"`
	PaymentType                 *big.Int          `json:"paymentType"`
	MaxFee                      string            `json:"maxFee"`
	Gas                         string            `json:"gas"`
	Nonce                       *big.Int          `json:"nonce"`
	EnforceSponsorNonce         bool              `json:"enforceSponsorNonce"`
	Sponsor                     ethcommon.Address `json:"sponsor"`
	SponsorChainID              *big.Int          `json:"sponsorChainId"`
	EnforceSponsorNonceOrdering bool              `json:"enforceSponsorNonceOrdering"`
	SponsorSignature            string            `json:"sponsorSignature"`
}

func postRPC(endpoint string, data interface{}) ([]byte, error) {
	bz, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	_, err = buf.Write(bz)
	if err != nil {
		return nil, err
	}

	fmt.Println("req", string(bz))

	r, err := http.NewRequest("POST", endpoint, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	r.Header.Set("Content-Type", contentTypeJSON)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	resp, err := httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to post request: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil

	// var sv *Response
	// if err = json.Unmarshal(body, &sv); err != nil {
	// 	return nil, err
	// }

	// return sv, nil
}

func sendForwardRequest(req *ForwardRequest, sig []byte) error {
	endpoint := "https://relay.gelato.digital" + "/metabox-relays/" + req.ChainID.String()
	fmt.Println("data", req.Data)
	data := &ForwardRequestData{
		TypeID:                      "ForwardRequest",
		ChainID:                     req.ChainID,
		Target:                      req.Target,
		FeeToken:                    req.FeeToken,
		Data:                        "0x" + hex.EncodeToString(req.Data),
		PaymentType:                 req.PaymentType,
		MaxFee:                      req.MaxFee.String(),
		Gas:                         req.Gas.String(),
		Nonce:                       req.Nonce,
		EnforceSponsorNonce:         req.EnforceSponsorNonce,
		Sponsor:                     req.Sponsor,
		SponsorChainID:              req.SponsorChainID,
		EnforceSponsorNonceOrdering: req.EnforceSponsorNonceOrdering,
		SponsorSignature:            "0x" + hex.EncodeToString(sig),
	}
	resp, err := postRPC(endpoint, data)
	if err != nil {
		return err
	}

	fmt.Println("resp", string(resp))
	return nil

}

func main() {
	// generate wallet
	key, err := generateKey()
	if err != nil {
		panic(err)
	}

	fmt.Printf("sponsor address: %s\n", key.address)

	// build request
	var (
		// goerli
		chainID        = big.NewInt(5)
		targetContract = ethcommon.HexToAddress("0x8580995EB790a3002A55d249e92A8B6e5d0b384a")
		nativeToken    = ethcommon.HexToAddress("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")
		paymentType    = big.NewInt(1)
		maxFee         = big.NewInt(1000000000000000) // wei
		gas            = big.NewInt(200000)
		nonce          = big.NewInt(0)
	)
	calldata, err := hex.DecodeString("4b327067000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeaeeeeeeeeeeeeeeeee")
	if err != nil {
		panic(err)
	}

	req := &ForwardRequest{
		ChainID:                     chainID,
		Target:                      targetContract,
		Data:                        calldata,
		FeeToken:                    nativeToken,
		PaymentType:                 paymentType,
		MaxFee:                      maxFee,
		Gas:                         gas,
		Sponsor:                     key.address,
		SponsorChainID:              chainID,
		Nonce:                       nonce,
		EnforceSponsorNonce:         false,
		EnforceSponsorNonceOrdering: false,
	}

	digest, err := getForwardRequestDigestToSign(req)
	if err != nil {
		panic(err)
	}

	sig, err := crypto.Sign(digest[:], key.priv)
	if err != nil {
		panic(err)
	}

	err = sendForwardRequest(req, sig)
	if err != nil {
		panic(err)
	}
}
