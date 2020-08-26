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

package netpb

import (
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
)

// HelloMessageFromProto parse the data into Hello message
func HelloMessageFromProto(data []byte) (*Hello, error) {
	pb := new(Hello)

	if err := proto.Unmarshal(data, pb); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to unmarshal Hello message.")
		return nil, err
	}

	return pb, nil
}

// OKMessageFromProto parse the data into OK message
func OKMessageFromProto(data []byte) (*OK, error) {
	pb := new(OK)

	if err := proto.Unmarshal(data, pb); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to unmarshal OK message.")
		return nil, err
	}

	return pb, nil
}
