package cvm

import (
	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/core/state"
)

type GtVM struct {
}

func NewGtVM() core.CVM {
	return &GtVM{}
}

// CreateEngine
func (cvm *GtVM) CreateEngine(block *core.Block, tx *core.Transaction, contract state.Account, state core.WorldState) (core.ContractEngine, error) {
	ctx, err := NewContext(block, tx, contract, state)
	if err != nil {
		return nil, err
	}
	return NewV8Engine(ctx), nil
}
