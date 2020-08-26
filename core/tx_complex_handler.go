package core

import (
	"encoding/json"
	"math/big"
)

type ComplexHandler struct {
	Data []byte
}

// LoadComplexHandler from bytes
func LoadComplexHandler(bytes []byte) (*ComplexHandler, error) {
	handler := &ComplexHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewComplexHandler(handler.Data), nil
}

// NewComplexHandler with data
func NewComplexHandler(data []byte) *ComplexHandler {
	return &ComplexHandler{
		Data: data,
	}
}

// ToBytes serialize handler
func (handler *ComplexHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *ComplexHandler) BaseGasCount() *big.Int {
	return big.NewInt(0)
}

func (handler *ComplexHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	return nil
}

// Execute the complex handler in tx, call a function
func (handler *ComplexHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	return nil, "", nil
}

func (handler *ComplexHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	return nil
}
