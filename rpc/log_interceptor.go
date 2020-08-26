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

package rpc

import (
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"strings"
)

func loggingStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	logging.VLog().WithFields(logrus.Fields{
		"method": info.FullMethod,
	}).Info("Rpc request.")
	metricsRPCCounter.Mark(1)
	return handler(srv, ss)
}

func loggingUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	if strings.Contains(info.FullMethod, "ApiService") {
		logging.VLog().WithFields(logrus.Fields{
			"method": info.FullMethod,
			"params": req,
		}).Info("Rpc request.")
	} else {
		logging.VLog().WithFields(logrus.Fields{
			"method": info.FullMethod,
		}).Info("Rpc request.")
	}
	metricsRPCCounter.Mark(1)
	return handler(ctx, req)
}
