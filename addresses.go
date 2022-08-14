package gelato

import (
	"fmt"
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
)

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
	case 137:
		return ethcommon.HexToAddress("0xc2336e796F77E4E57b6630b6dEdb01f5EE82383e")
	case 1284:
		return ethcommon.HexToAddress("0x14cdD6d9eBfbB7DAAF09395E56B2A89905D62b4C")
	case 1285:
		return ethcommon.HexToAddress("0x79A0cB573D3Db184752511969F1b869A184EA445")
	case 9001:
		return ethcommon.HexToAddress("0x9561aCdf04C2B639dFfeCB357438e7B3eD979C5C")
	case 43114:
		return ethcommon.HexToAddress("0x3456E168d2D7271847808463D6D383D079Bd5Eaa")
	case 44787:
		return ethcommon.HexToAddress("0xc2336e796F77E4E57b6630b6dEdb01f5EE82383e")
	case 80001:
		return ethcommon.HexToAddress("0x3428E19A01E40333D5D51465A08476b8F61B86f3")
	default:
		panic(fmt.Sprintf("chain ID %s not supported", chainID))
	}

	return ethcommon.Address{}
}
