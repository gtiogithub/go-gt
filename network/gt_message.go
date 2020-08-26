// Copyright (C) 2018 go-gt authors
//
// This file is part of the go-gt library.
//
// the go-gt library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// the go-gt library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-gt library.  If not, see <http://www.gnu.org/licenses/>.
//

package network

import (
	"bytes"
	"errors"
	"hash/crc32"
	"time"

	"github.com/golang/snappy"
	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
)

/*
GtMessage defines protocol in GT, we define our own wire protocol, as the following:

 0               1               2               3              (bytes)
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Number                          |
+-----------------------------------------------+---------------+
|               	Chain ID	                |    Reserved   |
+-----------------------------------------------+---------------+
|           		Reserved   		         	|    Version    |
+-----------------------------------------------+---------------+
|                                                               |
+                                                               +
|                         Message Name                          |
+                                                               +
|                                                               |
+---------------------------------------------------------------+
|                         Data Length                           |
+---------------------------------------------------------------+
|                         Data Checksum                         |
+---------------------------------------------------------------+
|                         Header Checksum                       |
|---------------------------------------------------------------+
|                                                               |
+                         Data                                  +
.                                                               .
|                                                               |
+---------------------------------------------------------------+
*/

const (
	GtMessageMagicNumberEndIdx    = 4
	GtMessageChainIDEndIdx        = 7
	GtMessageReservedEndIdx       = 11
	GtMessageVersionIndex         = 11
	GtMessageVersionEndIdx        = 12
	GtMessageNameEndIdx           = 24
	GtMessageDataLengthEndIdx     = 28
	GtMessageDataCheckSumEndIdx   = 32
	GtMessageHeaderCheckSumEndIdx = 36
	GtMessageHeaderLength         = 36

	// Consider that a block is too large in sync.
	MaxGtMessageDataLength = 512 * 1024 * 1024 // 512m.
	MaxGtMessageNameLength = 24 - 12           // 12.

	DefaultReservedFlag           = 0x0
	ReservedCompressionEnableFlag = 0x80
	ReservedCompressionClientFlag = 0x40
)

var (
	MagicNumber         = []byte{0x47, 0x54, 0x4D, 0x4E}
	GTNTMagicNumber     = []byte{0x47, 0x54, 0x54, 0x4E}
	DefaultReserved     = []byte{DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag}
	CompressionReserved = []byte{DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag | ReservedCompressionEnableFlag}

	ErrInsufficientMessageHeaderLength = errors.New("insufficient message header length")
	ErrInsufficientMessageDataLength   = errors.New("insufficient message data length")
	ErrInvalidMagicNumber              = errors.New("invalid magic number")
	ErrInvalidHeaderCheckSum           = errors.New("invalid header checksum")
	ErrInvalidDataCheckSum             = errors.New("invalid data checksum")
	ErrExceedMaxDataLength             = errors.New("exceed max data length")
	ErrExceedMaxMessageNameLength      = errors.New("exceed max message name length")
	ErrUncompressMessageFailed         = errors.New("uncompress message failed")
	ErrInvalidNetworkID                = errors.New("invalid network id")
)

//GtMessage struct
type GtMessage struct {
	content     []byte
	messageName string

	// debug fields.
	sendMessageAt  int64
	writeMessageAt int64
}

// MagicNumber return magicNumber
func (message *GtMessage) MagicNumber() []byte {
	return message.content[0:GtMessageMagicNumberEndIdx]
}

// ChainID return chainID
func (message *GtMessage) ChainID() uint32 {
	chainIdData := make([]byte, 4)
	copy(chainIdData[1:], message.content[GtMessageMagicNumberEndIdx:GtMessageChainIDEndIdx])
	return byteutils.Uint32(chainIdData)
}

// Reserved return reserved
func (message *GtMessage) Reserved() []byte {
	return message.content[GtMessageChainIDEndIdx:GtMessageReservedEndIdx]
}

// Version return version
func (message *GtMessage) Version() byte {
	return message.content[GtMessageVersionIndex]
}

// MessageName return message name
func (message *GtMessage) MessageName() string {
	if message.messageName == "" {
		data := message.content[GtMessageVersionEndIdx:GtMessageNameEndIdx]
		pos := bytes.IndexByte(data, 0)
		if pos != -1 {
			message.messageName = string(data[0:pos])
		} else {
			message.messageName = string(data)
		}
	}
	return message.messageName
}

// DataLength return dataLength
func (message *GtMessage) DataLength() uint32 {
	return byteutils.Uint32(message.content[GtMessageNameEndIdx:GtMessageDataLengthEndIdx])
}

// DataCheckSum return data checkSum
func (message *GtMessage) DataCheckSum() uint32 {
	return byteutils.Uint32(message.content[GtMessageDataLengthEndIdx:GtMessageDataCheckSumEndIdx])
}

// HeaderCheckSum return header checkSum
func (message *GtMessage) HeaderCheckSum() uint32 {
	return byteutils.Uint32(message.content[GtMessageDataCheckSumEndIdx:GtMessageHeaderCheckSumEndIdx])
}

// HeaderWithoutCheckSum return header without checkSum
func (message *GtMessage) HeaderWithoutCheckSum() []byte {
	return message.content[:GtMessageDataCheckSumEndIdx]
}

// Data return data
func (message *GtMessage) Data() ([]byte, error) {
	reserved := message.Reserved()
	data := message.content[GtMessageHeaderLength:]
	if (reserved[2] & ReservedCompressionEnableFlag) > 0 {
		var err error
		data, err = snappy.Decode(nil, data)
		//dstData := make([]byte, MaxGtMessageDataLength)
		//l, err := lz4.UncompressBlock(data, dstData)
		if err != nil {
			return nil, ErrUncompressMessageFailed
		}
		//if l > 0 {
		//	data = make([]byte, l)
		//	data = dstData[:l]
		//}
	}
	return data, nil
}

// OriginalData return original data
func (message *GtMessage) OriginalData() []byte {
	return message.content[GtMessageHeaderLength:]
}

// Content return message content
func (message *GtMessage) Content() []byte {
	return message.content
}

// Length return message Length
func (message *GtMessage) Length() uint64 {
	return uint64(len(message.content))
}

// NewGtMessage new gt message
func NewGtMessage(networkID uint32, chainID uint32, reserved []byte, version byte, messageName string, data []byte) (*GtMessage, error) {

	// Process message compression
	if ((reserved[2] & ReservedCompressionClientFlag) == 0) && ((reserved[2] & ReservedCompressionEnableFlag) > 0) {
		data = snappy.Encode(nil, data)
		//dstData := make([]byte, len(data))
		//ht := make([]int, 64<<10)
		//l, err := lz4.CompressBlock(data, dstData, ht)
		//if err != nil {
		//	panic(err)
		//}
		//if l > 0 {
		//	data = make([]byte, l)
		//	data = dstData[:l]
		//}
	}

	if len(data) > MaxGtMessageDataLength {
		logging.VLog().WithFields(logrus.Fields{
			"messageName": messageName,
			"dataLength":  len(data),
			"limits":      MaxGtMessageDataLength,
		}).Debug("Exceeded max data length.")
		return nil, ErrExceedMaxDataLength
	}

	if len(messageName) > MaxGtMessageNameLength {
		logging.VLog().WithFields(logrus.Fields{
			"messageName":      messageName,
			"len(messageName)": len(messageName),
			"limits":           MaxGtMessageNameLength,
		}).Debug("Exceeded max message name length.")
		return nil, ErrExceedMaxMessageNameLength
	}

	dataCheckSum := crc32.ChecksumIEEE(data)

	message := &GtMessage{
		content: make([]byte, GtMessageHeaderLength+len(data)),
	}

	magicNumber, err := getCurrentNetworkMagicNumber(networkID)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"messageName": messageName,
			"networkID":   networkID,
		}).Debug("invalid network id.")
		return nil, ErrInvalidNetworkID
	}
	// copy fields.
	copy(message.content[0:GtMessageMagicNumberEndIdx], magicNumber)
	chainIdData := byteutils.FromUint32(chainID)
	copy(message.content[GtMessageMagicNumberEndIdx:GtMessageChainIDEndIdx], chainIdData[1:])
	copy(message.content[GtMessageChainIDEndIdx:GtMessageReservedEndIdx], reserved)
	message.content[GtMessageVersionIndex] = version
	copy(message.content[GtMessageVersionEndIdx:GtMessageNameEndIdx], []byte(messageName))
	copy(message.content[GtMessageNameEndIdx:GtMessageDataLengthEndIdx], byteutils.FromUint32(uint32(len(data))))
	copy(message.content[GtMessageDataLengthEndIdx:GtMessageDataCheckSumEndIdx], byteutils.FromUint32(dataCheckSum))

	// header checksum.
	headerCheckSum := crc32.ChecksumIEEE(message.HeaderWithoutCheckSum())
	copy(message.content[GtMessageDataCheckSumEndIdx:GtMessageHeaderCheckSumEndIdx], byteutils.FromUint32(headerCheckSum))

	// copy data.
	copy(message.content[GtMessageHeaderCheckSumEndIdx:], data)

	return message, nil
}

// ParseGtMessage parse gt message
func ParseGtMessage(networkID uint32, data []byte) (*GtMessage, error) {
	if len(data) < GtMessageHeaderLength {
		return nil, ErrInsufficientMessageHeaderLength
	}

	message := &GtMessage{
		content: make([]byte, GtMessageHeaderLength),
	}
	copy(message.content, data)

	if err := message.VerifyHeader(networkID); err != nil {
		return nil, err
	}

	return message, nil
}

// ParseMessageData parse gt message data
func (message *GtMessage) ParseMessageData(data []byte) error {
	if uint32(len(data)) < message.DataLength() {
		return ErrInsufficientMessageDataLength
	}

	message.content = append(message.content, data[:message.DataLength()]...)
	return message.VerifyData()
}

func getCurrentNetworkMagicNumber(networkID uint32) ([]byte, error) {
	if networkID == MajorNetworkID {
		return MagicNumber, nil
	} else if networkID == GTNTNetworkID {
		return GTNTMagicNumber, nil
	} else {
		return nil, ErrInvalidNetworkID
	}
}

// VerifyHeader verify message header
func (message *GtMessage) VerifyHeader(networkID uint32) error {
	magicNumber, err := getCurrentNetworkMagicNumber(networkID)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"networkID":   networkID,
			"magicNumber": message.MagicNumber(),
			"err":         err.Error(),
		}).Debug("Failed to verify header.")
		return err
	}
	if !byteutils.Equal(magicNumber, message.MagicNumber()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": magicNumber,
			"actual": message.MagicNumber(),
			"err":    "invalid magic number",
		}).Debug("Failed to verify header.")
		return ErrInvalidMagicNumber
	}

	expectedCheckSum := crc32.ChecksumIEEE(message.HeaderWithoutCheckSum())
	if expectedCheckSum != message.HeaderCheckSum() {
		logging.VLog().WithFields(logrus.Fields{
			"expect": expectedCheckSum,
			"actual": message.HeaderCheckSum(),
			"err":    "invalid header checksum",
		}).Debug("Failed to verify header.")
		return ErrInvalidHeaderCheckSum
	}

	if message.DataLength() > MaxGtMessageDataLength {
		logging.VLog().WithFields(logrus.Fields{
			"messageName": message.MessageName(),
			"dataLength":  message.DataLength(),
			"limit":       MaxGtMessageDataLength,
			"err":         "exceeded max data length",
		}).Debug("Failed to verify header.")
		return ErrExceedMaxDataLength
	}

	return nil
}

// VerifyData verify message data
func (message *GtMessage) VerifyData() error {
	expectedCheckSum := crc32.ChecksumIEEE(message.OriginalData())
	if expectedCheckSum != message.DataCheckSum() {
		logging.VLog().WithFields(logrus.Fields{
			"expect": expectedCheckSum,
			"actual": message.DataCheckSum(),
			"err":    "invalid data checksum",
		}).Debug("Failed to verify data")
		return ErrInvalidDataCheckSum
	}
	return nil
}

// FlagWriteMessageAt flag of write message time
func (message *GtMessage) FlagWriteMessageAt() {
	message.writeMessageAt = time.Now().UnixNano()
}

// FlagSendMessageAt flag of send message time
func (message *GtMessage) FlagSendMessageAt() {
	message.sendMessageAt = time.Now().UnixNano()
}

// LatencyFromSendToWrite latency from sendMessage to writeMessage
func (message *GtMessage) LatencyFromSendToWrite() int64 {
	if message.sendMessageAt == 0 {
		return -1
	} else if message.writeMessageAt == 0 {
		message.FlagWriteMessageAt()
	}

	// convert from nano to millisecond.
	return (message.writeMessageAt - message.sendMessageAt) / int64(time.Millisecond)
}
