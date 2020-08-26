package cvm

import "C"
import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

func analysisStorageKeyType(key string) (int, string, string) {
	meta := key[0:6]
	varData := key[6:]
	if meta == state.ContractVariableMeta_Prefix {
		return 1, meta, varData
	} else if meta == state.ContractVariable_Prefix {
		return 2, meta, varData
	} else {
		return 0, meta, varData
	}
}

// 处理变量继承描述信息
func processVarMeta(ws WorldState, acc Account, metaKey, metaValue string) (bool, []byte) {
	// 检测上级合约地址
	//val, err := acc.Get([]byte("@CTM:FCA"))
	p := &state.InheritMetaInfo{}
	err := json.Unmarshal([]byte(metaValue), p)
	if err != nil {
		return false, nil
	}
	val, err := acc.Get(trie.HashDomains(state.ContractMeta_Prefix, state.ContractFCA))
	if err != nil {
		//没有指定上级合约地址，直接把继承信息写进去
		if err == ErrKeyNotFound {
			re, _ := json.Marshal(p)
			return true, re
		} else {
			logging.VLog().WithFields(logrus.Fields{
				"key": state.ContractMeta_Prefix,
				"err": err,
			}).Debug("processVarMeta failed.")
			return false, nil
		}
	} else {
		//找到上级合约地址，对本合约继承信息做检测
		fca, err := core.AddressParse(string(val))
		if err != nil {
			return false, nil
		}
		//fmt.Printf("Find processVarMeta fca:%s %s %s\n",fca,metaKey,metaValue)
		if p.InheritField != "" {

			process := false
			for process == false {
				fcaAccount, err := ws.GetContractAccount(fca.Bytes())
				if err != nil {
					fmt.Printf("fca err: %v \n", err)
					return false, nil
				}
				// 通过找到的上级合约地址,检测合约变量继承的描述信息是否正确
				fcaValue, err := fcaAccount.Get(trie.HashDomains(state.ContractVariableMeta_Prefix, p.InheritField))
				//fmt.Printf("put processVarMeta : %v \n",string(fcaValue))
				if err != nil {

					if err == ErrKeyNotFound {
						val, err = fcaAccount.Get(trie.HashDomains(state.ContractMeta_Prefix, state.ContractFCA))
						if err != nil {
							return false, nil
						}
						fca, err = core.AddressParse(string(val))
						if err != nil {
							return false, nil
						}
						continue

					} else {
						fmt.Printf("Find processVarMeta fca %s  err:%s \n", "@CTVM:"+p.InheritField, err.Error())
						return false, nil
					}
				} else {
					f := &state.InheritMetaInfo{}
					err := json.Unmarshal([]byte(fcaValue), f)
					if err != nil || f.Inheritable == false || f.InheritedField != nil {
						return false, nil
					}
					varValuem, err := fcaAccount.Get(trie.HashDomains(state.ContractVariable_Prefix, p.InheritField))

					//fmt.Printf("Find fcaAccount var %v :%v == %v\n",state.ContractVariable_Prefix, p.InheritField,varValuem)
					p.InheritField = fca.String() + "|" + p.InheritField
					re, _ := json.Marshal(p)
					if err != nil {
						//fmt.Printf("Find ContractVariable_Prefix fca err:%v \n",err)
						if err == ErrKeyNotFound {

							return true, re
						}
						return false, nil
					}
					varName := metaKey[6:]
					err = acc.Put(trie.HashDomains(state.ContractVariable_Prefix, varName), varValuem)
					if err != nil {
						//fmt.Printf("Set ContractVariable_Prefix fca err:%v \n",err)
						return false, nil
					}
					process = true
				}
			}
		}
		re, _ := json.Marshal(p)
		return true, re
	}
}

// StorageGetFunc export StorageGetFunc
//export StorageGetFunc
func StorageGetFunc(handler unsafe.Pointer, key *C.char, gasCnt *C.size_t) *C.char {
	_, storage := getEngineByStorageHandler(uint64(uintptr(handler)))
	if storage == nil {
		logging.VLog().Error("Failed to get storage handler.")
		return nil
	}

	k := C.GoString(key)
	//logging.CLog().WithFields(logrus.Fields{
	//	"variables": byteutils.Hex(storage.VarsHash()), "address": storage.Address().String(),
	//}).Debug("Get variables data")
	// calculate Gas.
	*gasCnt = C.size_t(0)
	keyType, prefix, k := analysisStorageKeyType(k)
	if keyType != 2 {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "Invalid storage key.",
		}).Debug("Invalid storage key.")
		return nil
	}
	keys := strings.Split(k, "|")
	if len(keys) != 2 {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "Invalid storage key.",
		}).Debug("Invalid storage key.")
		return nil
	}
	val, err := storage.Get(trie.HashDomains(prefix, keys[0]))
	//fmt.Printf("storage.Get1  :%v - %x \n",uint64(uintptr(handler)),storage.Address())
	//fmt.Printf("storage.Get  :%s-%x\n",keys[0],string(trie.HashDomains(keys[0])))

	if err != nil {
		fmt.Printf("storage.Get 2  :key 找不到！！ %v \n", err)
		if err != ErrKeyNotFound {
			logging.VLog().WithFields(logrus.Fields{
				"handler": uint64(uintptr(handler)),
				"key":     k,
				"err":     err,
			}).Debug("StorageGetFunc get key failed.")
		}
		return nil
	}
	varTrie, err := trie.NewTrie(val, storage.GetStorage(), false)
	val, err = varTrie.Get(trie.HashDomains(prefix, keys[1]))
	//var
	//fmt.Printf("Call StorageGetFunc :%s-%s  == %s\n",C.GoString(key),string(val),err)
	if err != nil {
		if err != ErrKeyNotFound {
			return C.CString(err.Error())
		} else {
			logging.VLog().WithFields(logrus.Fields{
				"handler": uint64(uintptr(handler)),
				"key":     k,
				"err":     err,
			}).Debug("StorageGetFunc get key failed.")
			return nil
		}
	}
	//fmt.Printf("Call StorageGetFunc  :%s-%s\n",C.GoString(key),string(val))
	return C.CString(string(val))
}

// StoragePutFunc export StoragePutFunc
//export StoragePutFunc
func StoragePutFunc(handler unsafe.Pointer, key *C.char, value *C.char, gasCnt *C.size_t) int {
	engine, storage := getEngineByStorageHandler(uint64(uintptr(handler)))
	if storage == nil {
		logging.VLog().Error("Failed to get storage handler.")
		return 1
	}

	k := C.GoString(key)
	v := []byte(C.GoString(value))
	ws := engine.ctx.state

	// calculate Gas.
	*gasCnt = C.size_t(len(k) + len(v))

	keyType, prefix, k := analysisStorageKeyType(k)
	//@CTVM 这个地方只保存一次
	if keyType == 1 {
		_, err := storage.Get(trie.HashDomains(prefix, k))
		if err != nil {
			if err == ErrKeyNotFound {
				ok, v := processVarMeta(ws, storage, C.GoString(key), C.GoString(value))
				if ok == false {
					//fmt.Printf("Call StoragePutFunc processVarMeta faild :%s-%s\n",k,string(v))
					return 1
				}
				storage.Put(trie.HashDomains(prefix, k), v)
				//fmt.Printf("Call StoragePutFunc set value :%s-%s\n",k,string(v))
				return 0
			} else {
				logging.VLog().WithFields(logrus.Fields{
					"handler": uint64(uintptr(handler)),
					"key":     k,
					"err":     err,
				}).Debug("StorageGetFunc get key failed.")
			}
		}
		//fmt.Printf("Call StoragePutFunc find value :%s-%s\n",k,string(val))
		return 0
	}

	if keyType <= 0 {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "Invalid storage key.",
		}).Debug("Invalid storage key.")
		return 1
	}
	//fmt.Printf("Call StoragePutFunc @CTVD :%s-%s\n",C.GoString(key),C.GoString(value))
	keys := strings.Split(k, "|")
	if len(keys) != 2 {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "Invalid storage key.",
		}).Debug("Invalid storage key.")
		return 1
	}
	//fmt.Printf("Call StoragePutFunc 2 :%s-%s\n",C.GoString(key),C.GoString(value))
	val, err := storage.Get(trie.HashDomains(prefix, keys[0]))
	if err != nil && err != ErrKeyNotFound {
		logging.CLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "Invalid storage key.",
		}).Debug("Invalid storage key.")
		return 1
	}
	varTrie, err := trie.NewTrie(val, storage.GetStorage(), false)
	//fmt.Printf("storage.GetStorage() :%s \n",storage.GetStorage())
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"err":     "varTrie NewTrie Faild.",
		}).Debug("varTrie NewTrie Faild.")
		return 1
	}
	val, err = varTrie.Put(trie.HashDomains(prefix, keys[1]), []byte(C.GoString(value)))
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"err":     "varTrie Put Faild.",
		}).Debug("varTrie Put Faild.")
		return 1
	}
	err = storage.Put(trie.HashDomains(prefix, keys[0]), varTrie.RootHash())
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"err":     "storage Put varTrie Faild.",
		}).Debug("storage Put varTrie Faild.")
		return 1
	}
	//fmt.Printf("Call StoragePutFunc  :%s-%s\n",C.GoString(key),C.GoString(value))
	return 0
}

// StorageDelFunc export StorageDelFunc
//export StorageDelFunc
func StorageDelFunc(handler unsafe.Pointer, key *C.char, gasCnt *C.size_t) int {
	_, storage := getEngineByStorageHandler(uint64(uintptr(handler)))
	if storage == nil {
		logging.VLog().Error("Failed to get storage handler.")
		return 1
	}

	k := C.GoString(key)

	// calculate Gas.
	*gasCnt = C.size_t(len(k))

	keyType, prefix, k := analysisStorageKeyType(k)
	if keyType == 1 {
		return 0
	}

	if keyType <= 0 {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "Invalid storage key.",
		}).Debug("Invalid storage key.")
		return 1
	}
	//fmt.Printf("Call StorageDelFunc :%s\n",C.GoString(key))
	keys := strings.Split(k, "|")
	if len(keys) != 2 {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "Invalid storage key.",
		}).Debug("Invalid storage key.")
		return 1
	}
	val, err := storage.Get(trie.HashDomains(prefix, keys[0]))
	if err != nil {
		if err == ErrKeyNotFound {
			return 0
		}
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "StorageDelFunc Invalid key.",
		}).Debug("StorageDelFunc Invalid key.")
		return 1
	}
	varTrie, err := trie.NewTrie(val, storage.GetStorage(), false)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "StorageDelFunc varTrie faild.",
		}).Debug("StorageDelFunc varTrie faild.")
		return 1
	}
	val, err = varTrie.Del(trie.HashDomains(prefix, keys[1]))
	if err != nil {
		if err == ErrKeyNotFound {
			return 0
		}
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     k,
			"err":     "StorageDelFunc varTrie del faild.",
		}).Debug("StorageDelFunc varTrie del faild.")
		return 1
	}
	storage.Put(trie.HashDomains(prefix, keys[0]), varTrie.RootHash())
	return 0
}

// StorageSetContractAddrFunc export StorageSetContractAddrFunc
//export StorageSetContractAddrFunc
func StorageSetContractAddrFunc(handler unsafe.Pointer, addr *C.char, gasCnt *C.size_t) int {
	_, storage := getEngineByStorageHandler(uint64(uintptr(handler)))
	if storage == nil {
		logging.VLog().Error("Failed to get storage handler.")
		return 1
	}
	v := C.GoString(addr)
	// calculate Gas.
	*gasCnt = C.size_t(len(v))
	_, err := storage.Get(trie.HashDomains(state.ContractMeta_Prefix, state.ContractFCA))
	if err != nil {
		if err == ErrKeyNotFound {
			storage.Put(trie.HashDomains(state.ContractMeta_Prefix, state.ContractFCA), []byte(v))
			//fmt.Printf("Set StorageSetContractAddrFunc set :%s\n",string(v))
			return 0
		} else {
			logging.VLog().WithFields(logrus.Fields{
				"handler": uint64(uintptr(handler)),
				"key":     state.ContractMeta_Prefix,
				"err":     err,
			}).Debug("StorageSetContractAddrFunc failed.")
			return 1
		}
	}
	//fmt.Printf("Find StorageSetContractAddrFunc :%s \n",string(val))
	return 0
}
