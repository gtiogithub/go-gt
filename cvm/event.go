package cvm

import "C"
import (
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
	"unsafe"
)

const (
	// EventBaseGasCount the gas count of a new event
	EventBaseGasCount = 20
)

// TransferFromContractEvent event for transfer in contract
type TransferFromContractEvent struct {
	Amount string `json:"amount"`
	From   string `json:"from"`
	To     string `json:"to"`
}

// TransferFromContractFailureEvent event for transfer in contract
type TransferFromContractFailureEvent struct {
	Amount string `json:"amount"`
	From   string `json:"from"`
	To     string `json:"to"`
	Status uint8  `json:"status"`
	Error  string `json:"error"`
}

// InnerTransferContractEvent event for inner transfer in contract
type InnerContractEvent struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Value    string `json:"value"`
	Err      string `json:"error"`
	Function string `json:"function,omitempty"`
	Args     string `json:"args,omitempty"`
}

// EventTriggerFunc export EventTriggerFunc
//export EventTriggerFunc
func EventTriggerFunc(handler unsafe.Pointer, topic, data *C.char, gasCnt *C.size_t) {
	gTopic := C.GoString(topic)
	gData := C.GoString(data)
	var engine *V8Engine
	e := getEngineByEngineHandler(handler)
	if e == nil {
		logging.VLog().WithFields(logrus.Fields{
			"category": 0, // ChainEventCategory.
			"topic":    gTopic,
			"data":     gData,
		}).Error("Event.Trigger delegate handler does not found.")
		return
	}
	if e.ctx.head != nil {
		engine = getEngineByEngineHandler(e.ctx.head)
		if engine == nil {
			logging.VLog().WithFields(logrus.Fields{
				"category": 0, // ChainEventCategory.
				"topic":    gTopic,
				"data":     gData,
			}).Error("Event.Trigger delegate head handler does not found.")
			return
		}
	} else {
		engine = e
	}
	// calculate Gas.
	*gasCnt = C.size_t(EventBaseGasCount + len(gTopic) + len(gData))

	var (
		contractTopic string
	)

	contractTopic = EventNameSpaceContract + "." + e.ctx.contract.Address().String() + "." + gTopic
	event := &state.Event{Topic: contractTopic, Data: gData}
	e.ctx.state.RecordEvent(engine.ctx.tx.Hash(), event)
}
