package core

import (
	"encoding/json"
	"math/big"
)

const (
	DoubleMint = "doubleMint"
	TwoWayVote = "twoWayVote"
)

type Report struct {
	Timestamp  int64  `json:"timestamp"`
	Malefactor string `json:"malefactor"`
	Evil       string `json:"evil"`
}

func (r *Report) ToBytes() ([]byte, error) {
	return json.Marshal(r)
}

func (r *Report) FromBytes(data []byte) error {
	if err := json.Unmarshal(data, r); err != nil {
		return err
	}
	return nil
}

type ReportHandler struct {
	ReportType string
	Data       []byte
}

// LoadReportHandler from bytes
func LoadReportHandler(bytes []byte) (*ReportHandler, error) {
	handler := &ReportHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewReportHandler(handler.ReportType, handler.Data), nil
}

// NewReportHandler with data
func NewReportHandler(reportType string, data []byte) *ReportHandler {
	return &ReportHandler{
		ReportType: reportType,
		Data:       data,
	}
}

// ToBytes serialize handler
func (handler *ReportHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *ReportHandler) BaseGasCount() *big.Int {
	return big.NewInt(0)
}

func (handler *ReportHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	return nil
}

// Execute the Report handler in tx, call a function
func (handler *ReportHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	if block == nil || tx == nil || ws == nil {
		return zero, "", ErrNilArgument
	}

	var err error

	switch handler.ReportType {
	case DoubleMint:
		err = ws.RecordEvil(tx.hash, tx.from.String(), DoubleMint, handler.Data)
	case TwoWayVote:
		err = ws.RecordEvil(tx.hash, tx.from.String(), TwoWayVote, handler.Data)
	default:
		err = ErrInvalidArgument
	}

	if err != nil {
		return zero, "", err
	}
	return zero, "", nil
}

func (handler *ReportHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	return nil
}
