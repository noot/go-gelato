package gelato

import (
	"encoding/hex"
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
)

const GelatoRelayURL = "https://relay.gelato.digital"

// ForwardRequest represents a relay request
// https://github.com/gelatodigital/relay-sdk/blob/162f6392fb23bf52ef32f4c96168bc0433a5b0c0/src/lib/index.ts#L250
type ForwardRequest struct {
	ChainID                     *big.Int          `json:"chainId"`
	Target                      ethcommon.Address `json:"target"`
	FeeToken                    string            `json:"feeToken"`
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

// ForwardRequestData represents the data forwarded to a Gelato relayer
type ForwardRequestData struct {
	TypeID                      string            `json:"typeId"`
	ChainID                     *big.Int          `json:"chainId"`
	Target                      ethcommon.Address `json:"target"`
	FeeToken                    string            `json:"feeToken"`
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

// SendForwardRequest sends a signed ForwardRequest to the relayer network
func SendForwardRequest(req *ForwardRequest, sig []byte) (*PostResponse, error) {
	endpoint := GelatoRelayURL + "/metabox-relays/" + req.ChainID.String()
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
	return postRPC(endpoint, data)
}

type ForwardCall struct {
	ChainID  *big.Int          `json:"chainId"`
	Target   ethcommon.Address `json:"target"`
	FeeToken string            `json:"feeToken"`
	Data     []byte            `json:"data"`
	Gas      *big.Int          `json:"gas"`
}

type ForwardCallData struct {
	TypeID   string            `json:"typeId"`
	ChainID  *big.Int          `json:"chainId"`
	Target   ethcommon.Address `json:"target"`
	FeeToken string            `json:"feeToken"`
	Data     string            `json:"data"`
	Gas      string            `json:"gas"`
}

// SendForwardCall sends a ForwardCall (unsigned) to the relayer network
func SendForwardCall(req *ForwardCall) (*PostResponse, error) {
	endpoint := GelatoRelayURL + "/metabox-relays/" + req.ChainID.String()
	data := &ForwardCallData{
		TypeID:   "ForwardCall",
		ChainID:  req.ChainID,
		Target:   req.Target,
		FeeToken: req.FeeToken,
		Data:     "0x" + hex.EncodeToString(req.Data),
		Gas:      req.Gas.String(),
	}
	return postRPC(endpoint, data)
}
