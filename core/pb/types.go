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

package corepb

import (
	"gt.pro/gtio/go-gt/util/byteutils"
	"errors"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/crypto/sha3"
)

var (
	ErrNoMaster     = errors.New("no master in group")
	ErrWrongGroup   = errors.New("wrong group")
	ErrGetGroupNext = errors.New("get next error")
)

func (p *Propose) CalcHash() []byte {
	hasher := sha3.New256()
	hasher.Write(byteutils.FromUint64(p.Num))
	if p.Value != nil {
		hasher.Write(p.Value)
	}
	return hasher.Sum(nil)
}

func (p *Promise) CalcHash() []byte {
	hasher := sha3.New256()
	hasher.Write(byteutils.FromUint64(p.ProposalId))
	if p.MaxAcceptedPropose != nil {
		hasher.Write(byteutils.FromUint64(p.MaxAcceptedPropose.Num))
		if p.MaxAcceptedPropose.Value != nil {
			hasher.Write(p.MaxAcceptedPropose.Value)
		}
	}

	return hasher.Sum(nil)
}

func (p *Propose) ToProto() (proto.Message, error) {
	prop := &Propose{
		Num:   p.Num,
		Value: p.Value,
	}
	return prop, nil
}

func (p *Propose) FromProto(msg proto.Message) error {
	p.Num = msg.(*Propose).Num
	p.Value = msg.(*Propose).Value
	return nil
}

func (pbftMsg *PbftMsg) CalcHash() []byte {
	hasher := sha3.New256()
	hasher.Write(byteutils.FromUint32(pbftMsg.Type))
	hasher.Write([]byte(pbftMsg.ViewId))
	hasher.Write(byteutils.FromUint64(pbftMsg.SeqId))
	hasher.Write(pbftMsg.Data)
	hasher.Write(byteutils.FromInt64(pbftMsg.Timestamp))

	hash := hasher.Sum(nil)
	return hash
}
