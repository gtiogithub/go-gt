package cvm

/*
#include <stdlib.h>
#cgo CFLAGS:
#cgo LDFLAGS: -L ${SRCDIR}/../library/libgtv8/linux -lgtv8

#include "../v8/engine.h"
// Forward declaration.
void V8Log_cgo(int level, const char *msg);

char *RequireDelegateFunc_cgo(void *handler, const char *filename, size_t *lineOffset);
char *AttachLibVersionDelegateFunc_cgo(void *handler, const char *libname);

char *StorageGetFunc_cgo(void *handler, const char *key, size_t *gasCnt);
int StoragePutFunc_cgo(void *handler, const char *key, const char *value, size_t *gasCnt);
int StorageDelFunc_cgo(void *handler, const char *key, size_t *gasCnt);
int StorageSetContractAddrFunc_cgo(void *handler, const char *key, size_t *gasCnt);

char *GetTxByHashFunc_cgo(void *handler, const char *hash, size_t *gasCnt);
char *GetAccountStateFunc_cgo(void *handler, const char *address, size_t *gasCnt, char **result, char **info);
int TransferFunc_cgo(void *handler, const char *to, const char *value, size_t *gasCnt);
int VerifyAddressFunc_cgo(void *handler, const char *address, size_t *gasCnt);
char *GetPreBlockHashFunc_cgo(void *handler, unsigned long long offset, size_t *gasCnt, char **result, char **info);

char *Sha256Func_cgo(const char *data, size_t *gasCnt);
char *Sha3256Func_cgo(const char *data, size_t *gasCnt);
char *Ripemd160Func_cgo(const char *data, size_t *gasCnt);
char *RecoverAddressFunc_cgo(const char *signer, size_t *gasCnt);
char *Md5Func_cgo(const char *data, size_t *gasCnt);
char *Base64Func_cgo(const char *data, size_t *gasCnt);
char *GetContractSourceFunc_cgo(void *handler, const char *address);
char *InnerContractFunc_cgo(void *handler, const char *address, const char *funcName, const char *v, const char *args, size_t *gasCnt);

char *GetTxRandomFunc_cgo(void *handler, size_t *gasCnt, char **result, char **exceptionInfo);

void EventTriggerFunc_cgo(void *handler, const char *topic, const char *data, size_t *gasCnt);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/crypto/hash"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

const (
	ExecutionTimeout                 = 15 * 1000 * 1000
	MaxLimitsOfExecutionInstructions = 10000000
)

var (
	v8engineOnce         = sync.Once{}
	enginesLock          = sync.RWMutex{}
	engines              = make(map[*C.V8Engine]*V8Engine, 1024)
	storagesLock         = sync.RWMutex{}
	storages             = make(map[uint64]*V8Engine, 1024)
	storagesIdx          = uint64(0)
	sourceModuleCache, _ = lru.New(40960)
)

// V8Engine v8 engine.
type V8Engine struct {
	ctx                                     *Context
	modules                                 Modules
	v8engine                                *C.V8Engine
	strictDisallowUsageOfInstructionCounter int
	enableLimits                            bool
	limitsOfExecutionInstructions           uint64
	limitsOfTotalMemorySize                 uint64
	actualCountOfExecutionInstructions      uint64
	actualTotalMemorySize                   uint64
	lcsHandler                              uint64
	innerErrMsg                             string
	innerErr                                error
	funcs                                   string
}

type sourceModuleItem struct {
	source                    string
	sourceLineOffset          int
	traceableSource           string
	traceableSourceLineOffset int
}

// InitV8Engine initialize the v8 engine.
func InitV8Engine() {
	C.Initialize()

	// Logger.
	C.InitializeLogger((C.LogFunc)(unsafe.Pointer(C.V8Log_cgo)))

	// Require.
	C.InitializeRequireDelegate((C.RequireDelegate)(unsafe.Pointer(C.RequireDelegateFunc_cgo)), (C.AttachLibVersionDelegate)(unsafe.Pointer(C.AttachLibVersionDelegateFunc_cgo)))

	// execution_env require
	C.InitializeExecutionEnvDelegate((C.AttachLibVersionDelegate)(unsafe.Pointer(C.AttachLibVersionDelegateFunc_cgo)))

	// Storage.
	C.InitializeStorage((C.StorageGetFunc)(unsafe.Pointer(C.StorageGetFunc_cgo)),
		(C.StoragePutFunc)(unsafe.Pointer(C.StoragePutFunc_cgo)),
		(C.StorageDelFunc)(unsafe.Pointer(C.StorageDelFunc_cgo)),
		(C.StorageSetContractAddrFunc)(unsafe.Pointer(C.StorageSetContractAddrFunc_cgo)))

	// Blockchain.
	C.InitializeBlockchain((C.GetTxByHashFunc)(unsafe.Pointer(C.GetTxByHashFunc_cgo)),
		(C.GetAccountStateFunc)(unsafe.Pointer(C.GetAccountStateFunc_cgo)),
		(C.TransferFunc)(unsafe.Pointer(C.TransferFunc_cgo)),
		(C.VerifyAddressFunc)(unsafe.Pointer(C.VerifyAddressFunc_cgo)),
		(C.GetPreBlockHashFunc)(unsafe.Pointer(C.GetPreBlockHashFunc_cgo)),
		(C.GetContractSourceFunc)(unsafe.Pointer(C.GetContractSourceFunc_cgo)),
		(C.InnerContractFunc)(unsafe.Pointer(C.InnerContractFunc_cgo)))

	// random.
	C.InitializeRandom((C.GetTxRandomFunc)(unsafe.Pointer(C.GetTxRandomFunc_cgo)))

	// Event.
	C.InitializeEvent((C.EventTriggerFunc)(unsafe.Pointer(C.EventTriggerFunc_cgo)))

	// Crypto
	C.InitializeCrypto((C.Sha256Func)(unsafe.Pointer(C.Sha256Func_cgo)),
		(C.Sha3256Func)(unsafe.Pointer(C.Sha3256Func_cgo)),
		(C.Ripemd160Func)(unsafe.Pointer(C.Ripemd160Func_cgo)),
		(C.RecoverAddressFunc)(unsafe.Pointer(C.RecoverAddressFunc_cgo)),
		(C.Md5Func)(unsafe.Pointer(C.Md5Func_cgo)),
		(C.Base64Func)(unsafe.Pointer(C.Base64Func_cgo)))
}

// NewV8Engine return new V8Engine instance.
func NewV8Engine(ctx *Context) *V8Engine {
	v8engineOnce.Do(func() {
		InitV8Engine()
	})

	engine := &V8Engine{
		ctx:                                     ctx,
		modules:                                 NewModules(),
		v8engine:                                C.CreateEngine(),
		strictDisallowUsageOfInstructionCounter: 1, // enable by default.
		enableLimits:                            true,
		limitsOfExecutionInstructions:           0,
		limitsOfTotalMemorySize:                 0,
		actualCountOfExecutionInstructions:      0,
		actualTotalMemorySize:                   0,
	}

	(func() {
		enginesLock.Lock()
		defer enginesLock.Unlock()
		engines[engine.v8engine] = engine
	})()

	(func() {
		storagesLock.Lock()
		defer storagesLock.Unlock()

		storagesIdx++
		engine.lcsHandler = storagesIdx
		storages[engine.lcsHandler] = engine
	})()

	engine.SetTimeOut(ExecutionTimeout)

	engine.EnableInnerContract()

	return engine
}

func (e *V8Engine) SetTimeOut(timeout uint64) {
	e.v8engine.timeout = C.int(timeout)
}

func (e *V8Engine) EnableInnerContract() {
	C.EnableInnerContract(e.v8engine)
}

// DeployAndInit a contract
func (e *V8Engine) DeployAndInit(source, args string) (string, error) {
	result, err := e.RunContractScript(source, "init", args)
	if err == nil {
		e.ctx.contract.Put(trie.HashDomains(state.ContractMeta_Prefix, state.ContractFunList), []byte(e.funcs))
	}
	logging.VLog().WithFields(logrus.Fields{
		"args": args,
	}).Debug("DeployAndInit")

	logging.CLog().WithFields(logrus.Fields{
		"variables": byteutils.Hex(e.ctx.contract.VarsHash()), "address": e.ctx.contract.Address().String(),
	}).Debug("DeployAndInit Finished")
	//log.Println("DeployAndInit" + funcs)
	return result, err
}

// Call function in a script
func (e *V8Engine) Call(source, function, args string) (string, error) {
	if core.PublicFuncNameChecker.MatchString(function) == false {
		logging.VLog().Debugf("Invalid function: %v", function)
		return "", ErrDisallowCallNotStandardFunction
	}
	if strings.EqualFold("init", function) == true {
		return "", ErrDisallowCallPrivateFunction
	}
	result, err := e.RunContractScript(source, function, args)
	logging.VLog().WithFields(logrus.Fields{
		"function": function,
		"args":     args,
	}).Debug("DeployAndInit")
	return result, err
}

// Dispose dispose all resources.
func (e *V8Engine) Dispose() {
	storagesLock.Lock()
	delete(storages, e.lcsHandler)
	storagesLock.Unlock()

	enginesLock.Lock()
	delete(engines, e.v8engine)
	enginesLock.Unlock()

	C.DeleteEngine(e.v8engine)
}

// RunContractScript execute script in Smart Contract's way.
func (e *V8Engine) RunContractScript(source, function, args string) (string, error) {
	var runnableSource string
	var sourceLineOffset int
	var err error

	runnableSource, sourceLineOffset, err = e.prepareRunnableContractScript(source, function, args)

	if err != nil {
		return "", err
	}

	e.CollectTracingStats()
	mem := e.actualTotalMemorySize + core.DefaultLimitsOfTotalMemorySize
	logging.VLog().WithFields(logrus.Fields{
		"actualTotalMemorySize": e.actualTotalMemorySize,
		"limit":                 mem,
		"tx.hash":               e.ctx.tx.Hash(),
	}).Debug("mem limit")
	if err := e.SetExecutionLimits(e.limitsOfExecutionInstructions, mem); err != nil {
		return "", err
	}

	if e.limitsOfExecutionInstructions > MaxLimitsOfExecutionInstructions {
		e.SetExecutionLimits(MaxLimitsOfExecutionInstructions, e.limitsOfTotalMemorySize)
	}

	result, err := e.RunScriptSource(runnableSource, sourceLineOffset)

	if e.limitsOfExecutionInstructions == MaxLimitsOfExecutionInstructions && err == ErrInsufficientGas {
		err = ErrExecutionTimeout
		result = "\"null\""
	}
	return result, err
}

// RunScriptSource run js source.
func (e *V8Engine) RunScriptSource(source string, sourceLineOffset int) (string, error) {
	cSource := C.CString(source)
	defer C.free(unsafe.Pointer(cSource))

	var (
		result  string
		err     error
		ret     C.int
		cResult *C.char
	)
	ctx := e.Context()
	if ctx == nil || ctx.block == nil {
		logging.VLog().WithFields(logrus.Fields{
			"ctx": ctx,
		}).Error("Unexpected: Failed to get current height")
		err = core.ErrUnexpected
		return "", err
	}

	ret = C.RunScriptSourceThread(&cResult, e.v8engine, cSource, C.int(sourceLineOffset), C.uintptr_t(e.lcsHandler))
	e.CollectTracingStats()

	if e.innerErr != nil {
		if e.innerErrMsg == "" { //the first call of muti-nvm
			result = "Inner Contract: \"\""
		} else {
			result = "Inner Contract: " + e.innerErrMsg
		}
		err := e.innerErr
		if cResult != nil {
			C.free(unsafe.Pointer(cResult))
		}
		if e.actualCountOfExecutionInstructions > e.limitsOfExecutionInstructions {
			e.actualCountOfExecutionInstructions = e.limitsOfExecutionInstructions
		}
		return result, err
	}

	if ret == C.CVM_EXE_TIMEOUT_ERR {
		err = ErrExecutionTimeout
	} else if ret == C.CVM_UNEXPECTED_ERR {
		err = core.ErrUnexpected
	} else if ret == C.CVM_INNER_EXE_ERR {
		err = core.ErrInnerExecutionFailed
		if e.limitsOfExecutionInstructions < e.actualCountOfExecutionInstructions {
			logging.VLog().WithFields(logrus.Fields{
				"actualGas": e.actualCountOfExecutionInstructions,
				"limitGas":  e.limitsOfExecutionInstructions,
			}).Error("Unexpected error: actual gas exceed the limit")
		}
	} else {
		if ret != C.CVM_SUCCESS {
			err = core.ErrExecutionFailed
		}
		if e.limitsOfExecutionInstructions > 0 &&
			e.limitsOfExecutionInstructions < e.actualCountOfExecutionInstructions {
			// Reach instruction limits.
			err = ErrInsufficientGas
			e.actualCountOfExecutionInstructions = e.limitsOfExecutionInstructions
		} else if e.limitsOfTotalMemorySize > 0 && e.limitsOfTotalMemorySize < e.actualTotalMemorySize {
			// reach memory limits.
			err = ErrExceedMemoryLimits
			e.actualCountOfExecutionInstructions = e.limitsOfExecutionInstructions
		}
	}

	//set result
	if cResult != nil {
		result = C.GoString(cResult)
		C.free(unsafe.Pointer(cResult))
	} else if ret == C.CVM_SUCCESS {
		result = "\"\"" // default JSON String.
	}

	return result, err
}

// CollectTracingStats collect tracing data from v8 engine.
func (e *V8Engine) CollectTracingStats() {
	// read memory stats.
	C.ReadMemoryStatistics(e.v8engine)

	e.actualCountOfExecutionInstructions = uint64(e.v8engine.stats.count_of_executed_instructions)
	e.actualTotalMemorySize = uint64(e.v8engine.stats.total_memory_size)
}

// ExecutionInstructions returns the execution instructions
func (e *V8Engine) ExecutionInstructions() uint64 {
	return e.actualCountOfExecutionInstructions
}

// SetExecutionLimits set execution limits of V8 Engine, prevent Halting Problem.
func (e *V8Engine) SetExecutionLimits(limitsOfExecutionInstructions, limitsOfTotalMemorySize uint64) error {

	e.v8engine.limits_of_executed_instructions = C.size_t(limitsOfExecutionInstructions)
	e.v8engine.limits_of_total_memory_size = C.size_t(limitsOfTotalMemorySize)

	logging.VLog().WithFields(logrus.Fields{
		"limits_of_executed_instructions": limitsOfExecutionInstructions,
		"limits_of_total_memory_size":     limitsOfTotalMemorySize,
	}).Debug("set execution limits.")

	e.limitsOfExecutionInstructions = limitsOfExecutionInstructions
	e.limitsOfTotalMemorySize = limitsOfTotalMemorySize

	if limitsOfExecutionInstructions == 0 || limitsOfTotalMemorySize == 0 {
		logging.VLog().Debugf("limit args has empty. limitsOfExecutionInstructions:%v,limitsOfTotalMemorySize:%d", limitsOfExecutionInstructions, limitsOfTotalMemorySize)
		return ErrLimitHasEmpty
	}
	// V8 needs at least 6M heap memory.
	if limitsOfTotalMemorySize > 0 && limitsOfTotalMemorySize < 6000000 {
		logging.VLog().Debugf("V8 needs at least 6M (6000000) heap memory, your limitsOfTotalMemorySize (%d) is too low.", limitsOfTotalMemorySize)
		return ErrSetMemorySmall
	}
	return nil
}

func (e *V8Engine) AddModule(id, source string, sourceLineOffset int) error {
	// inject tracing instruction when enable limits.
	if e.enableLimits {
		var item *sourceModuleItem
		sourceHash := byteutils.Hex(hash.Sha3256([]byte(source)))

		// try read from cache.
		if sourceModuleCache.Contains(sourceHash) { //ToDo cache whether need into db
			value, _ := sourceModuleCache.Get(sourceHash)
			item = value.(*sourceModuleItem)
		}

		if item == nil {
			// fix
			traceableSource, funcs, lineOffset, err := e.InjectTracingInstructions(source)
			if err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"funcs": funcs,
					"err":   err,
				}).Debug("Failed to inject tracing instruction.")
				return err
			}
			//log.Println("AddModule" + funcs)

			item = &sourceModuleItem{
				source:                    source,
				sourceLineOffset:          sourceLineOffset,
				traceableSource:           traceableSource,
				traceableSourceLineOffset: lineOffset,
			}
			e.funcs = funcs
			// put to cache.
			sourceModuleCache.Add(sourceHash, item)
		}

		source = item.traceableSource
		sourceLineOffset = item.traceableSourceLineOffset
	}
	e.modules.Add(NewModule(id, source, sourceLineOffset))
	return nil
}

func (e *V8Engine) prepareRunnableContractScript(source, function, args string) (string, int, error) {
	sourceLineOffset := 0
	ClearSourceModuleCache()

	// add module.
	const ModuleID string = "contract.js"
	if err := e.AddModule(ModuleID, source, sourceLineOffset); err != nil {
		return "", 0, err
	}

	// prepare for execute.
	block := toSerializableBlock(e.ctx.block)
	blockJSON, err := json.Marshal(block)
	if err != nil {
		return "", 0, err
	}
	tx := toSerializableTransaction(e.ctx.tx)
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return "", 0, err
	}

	var runnableSource string
	var argsInput []byte
	if len(args) > 0 {
		var argsObj []interface{}
		if err := json.Unmarshal([]byte(args), &argsObj); err != nil {
			return "", 0, ErrArgumentsFormat
		}
		if argsInput, err = json.Marshal(argsObj); err != nil {
			return "", 0, ErrArgumentsFormat
		}

	} else {
		argsInput = []byte("[]")
	}
	runnableSource = fmt.Sprintf(`Blockchain.blockParse("%s");
									Blockchain.transactionParse("%s");
									var __contract = require("%s");
									var __instance = new __contract();
									__instance["%s"].apply(__instance, JSON.parse("%s"));`,
		formatArgs(string(blockJSON)), formatArgs(string(txJSON)),
		ModuleID, function, formatArgs(string(argsInput)))
	return runnableSource, 0, nil
}

// Context returns engine context
func (e *V8Engine) Context() *Context {
	return e.ctx
}

// ClearModuleCache ..
func ClearSourceModuleCache() {
	sourceModuleCache.Purge()
}

// InjectTracingInstructions process the source to inject tracing instructions.
func (e *V8Engine) InjectTracingInstructions(source string) (string, string, int, error) {
	cSource := C.CString(source)
	defer C.free(unsafe.Pointer(cSource))
	var cFuncs *C.char

	lineOffset := C.int(0)

	traceableCSource := C.InjectTracingInstructionsThread(e.v8engine, cSource, &lineOffset, C.int(e.strictDisallowUsageOfInstructionCounter), &cFuncs)
	if traceableCSource == nil {
		return "", "", 0, ErrInjectTracingInstructionFailed
	}

	funcs := C.GoString(cFuncs)
	C.free(unsafe.Pointer(cFuncs))
	//log.Printf("InjectTracingInstructions =>%s", funcs)

	defer C.free(unsafe.Pointer(traceableCSource))
	return C.GoString(traceableCSource), funcs, int(lineOffset), nil
}

func formatArgs(s string) string {
	s = strings.Replace(s, "\\", "\\\\", -1)
	s = strings.Replace(s, "\n", "\\n", -1)
	s = strings.Replace(s, "\r", "\\r", -1)
	s = strings.Replace(s, "\"", "\\\"", -1)
	return s
}

func getEngineByStorageHandler(handler uint64) (*V8Engine, Account) {
	storagesLock.RLock()
	engine := storages[handler]
	storagesLock.RUnlock()

	if engine == nil {
		logging.VLog().WithFields(logrus.Fields{
			"wantedHandler": handler,
		}).Error("wantedHandler is not found.")
		return nil, nil
	}

	if engine.lcsHandler == handler {
		return engine, engine.ctx.contract
	} else {
		logging.VLog().WithFields(logrus.Fields{
			"lcsHandler":    engine.lcsHandler,
			"wantedHandler": handler,
		}).Error("in-consistent storage handler.")
		return nil, nil
	}
}

func getEngineByEngineHandler(handler unsafe.Pointer) *V8Engine {
	v8engine := (*C.V8Engine)(handler)
	enginesLock.RLock()
	defer enginesLock.RUnlock()

	return engines[v8engine]
}

func (e *V8Engine) GetCVMLeftResources() (uint64, uint64) {
	e.CollectTracingStats()
	instruction := uint64(0)
	mem := uint64(0)
	if e.limitsOfExecutionInstructions >= e.actualCountOfExecutionInstructions {
		instruction = e.limitsOfExecutionInstructions - e.actualCountOfExecutionInstructions
	}

	if e.limitsOfTotalMemorySize >= e.actualTotalMemorySize {
		mem = e.limitsOfTotalMemorySize - e.actualTotalMemorySize
	}

	return instruction, mem
}
