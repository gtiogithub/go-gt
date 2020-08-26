package cvm

import "C"
import (
	"crypto/md5"
	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/crypto/hash"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

// Sha256Func ..
//export Sha256Func
func Sha256Func(data *C.char, gasCnt *C.size_t) *C.char {
	s := C.GoString(data)
	*gasCnt = C.size_t(len(s) + CryptoSha256GasBase)

	r := hash.Sha256([]byte(s))
	return C.CString(byteutils.Hex(r))
}

// Sha3256Func ..
//export Sha3256Func
func Sha3256Func(data *C.char, gasCnt *C.size_t) *C.char {
	s := C.GoString(data)
	*gasCnt = C.size_t(len(s) + CryptoSha3256GasBase)

	r := hash.Sha3256([]byte(s))
	return C.CString(byteutils.Hex(r))
}

// Ripemd160Func ..
//export Ripemd160Func
func Ripemd160Func(data *C.char, gasCnt *C.size_t) *C.char {
	s := C.GoString(data)
	*gasCnt = C.size_t(len(s) + CryptoRipemd160GasBase)

	r := hash.Ripemd160([]byte(s))
	return C.CString(byteutils.Hex(r))
}

// RecoverAddressFunc ..
//export RecoverAddressFunc
func RecoverAddressFunc(signer *C.char, gasCnt *C.size_t) *C.char {
	s := C.GoString(signer)
	*gasCnt = C.size_t(CryptoRecoverAddressGasBase)
	cipher, err := byteutils.FromHex(s)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"sign": s,
			"err":  err,
		}).Debug("convert signer to byte array error.")
		return nil
	}
	addr, err := core.RecoverSignerFromSignBytes(cipher)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"sign": s,
			"err":  err,
		}).Debug("recover address error.")
		return nil
	}

	return C.CString(addr.String())
}

// Md5Func ..
//export Md5Func
func Md5Func(data *C.char, gasCnt *C.size_t) *C.char {
	s := C.GoString(data)
	*gasCnt = C.size_t(len(s) + CryptoMd5GasBase)

	r := md5.Sum([]byte(s))
	return C.CString(byteutils.Hex(r[:]))
}

// Base64Func ..
//export Base64Func
func Base64Func(data *C.char, gasCnt *C.size_t) *C.char {
	s := C.GoString(data)
	*gasCnt = C.size_t(len(s) + CryptoBase64GasBase)

	r := hash.Base64Encode([]byte(s))
	return C.CString(string(r))
}
