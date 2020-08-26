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
	"gt.pro/gtio/go-gt/core"
	rpcpb "gt.pro/gtio/go-gt/rpc/pb"
	"gt.pro/gtio/go-gt/util/config"

	"errors"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/netutil"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gt.pro/gtio/go-gt/util/logging"
)

// Errors
var (
	ErrEmptyRPCListenList = errors.New("empty rpc listen list")
)

// Const
const (
	DefaultConnectionLimits = 128
	MaxRecvMsgSize          = 3 * 1024 * 1024 * 1024
	Rpc                     = "rpc"
)

// GRPCServer server interface for api & management etc.
type GRPCServer interface {
	Start() error // Start start server
	Stop()        // Stop stop server
	RunGateway() error
}

type RpcConfig struct {
	RpcListen  []string `yaml:"rpc_listen"`
	HttpListen []string `yaml:"http_listen"`
	HttpModule []string `yaml:"http_module"`
	HttpCors   []string `yaml:"http_cors"`
	HttpLimits uint32   `yaml:"http_limits"`
}

func GetRpcConfig(config *config.Config) *RpcConfig {
	rpcConfig := new(RpcConfig)
	config.GetObject(Rpc, rpcConfig)
	//todo: default config
	return rpcConfig
}

func SetRpcConfig(config *config.Config, rpcCfg *RpcConfig) {
	config.Set(Rpc, rpcCfg)
}

// Server is the RPC server type.
type Server struct {
	rpcServer *grpc.Server
	rpcConfig *RpcConfig
}

// NewServer creates a new RPC server and registers the rpc endpoints.
func NewServer(gt core.Gt) *Server {
	cfg := GetRpcConfig(gt.Config())

	if cfg == nil {
		logging.CLog().Fatal("Failed to find rpc config in config file.")
	}
	rpc := grpc.NewServer(grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(loggingStream)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(loggingUnary)),
		grpc.MaxRecvMsgSize(MaxRecvMsgSize),
		grpc.MaxSendMsgSize(MaxRecvMsgSize))

	srv := &Server{rpcServer: rpc, rpcConfig: cfg}
	api := &ApiService{chain: gt.BlockChain(), gt: gt}
	admin := &AdminService{
		server:  srv,
		gt:      gt,
		log:     logging.VLog(),
		logConf: logging.GetLogConfig(gt.Config())}

	rpcpb.RegisterApiServiceServer(rpc, api)
	rpcpb.RegisterAdminServiceServer(rpc, admin)
	// Register reflection service on gRPC server.
	// TODO: Enable reflection only for testing mode.
	reflection.Register(rpc)

	return srv
}

// Start starts the rpc server and serves incoming requests.
func (s *Server) Start() error {
	logging.CLog().Info("Starting RPC GRPCServer...")

	if len(s.rpcConfig.RpcListen) == 0 {
		return ErrEmptyRPCListenList
	}

	for _, v := range s.rpcConfig.RpcListen {
		if err := s.start(v); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to listen to RPC GRPCServer")
		return err
	}

	logging.CLog().WithFields(logrus.Fields{
		"address": addr,
	}).Info("Started RPC GRPCServer.")

	// Limit the total number of grpc connections.
	connectionLimits := s.rpcConfig.HttpLimits
	if connectionLimits == 0 {
		connectionLimits = DefaultConnectionLimits
	}

	listener = netutil.LimitListener(listener, int(connectionLimits))

	go func() {
		if err := s.rpcServer.Serve(listener); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err": err,
			}).Info("RPC server exited.")
		}
	}()

	return nil
}

// RunGateway run grpc mapping to http after apiserver have started.
func (s *Server) RunGateway() error {
	//time.Sleep(3 * time.Second)

	logging.CLog().WithFields(logrus.Fields{
		"rpc-server":  s.rpcConfig.RpcListen[0],
		"http-server": s.rpcConfig.HttpListen,
		"http-cors":   s.rpcConfig.HttpCors,
	}).Info("Starting RPC Gateway GRPCServer...")

	go func() {
		if err := Run(s.rpcConfig); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to start RPC Gateway.")
		}

	}()
	return nil
}

// Stop stops the rpc server and closes listener.
func (s *Server) Stop() {
	logging.CLog().WithFields(logrus.Fields{
		"listen": s.rpcConfig.RpcListen,
	}).Info("Stopping RPC GRPCServer and Gateway...")

	s.rpcServer.Stop()

	logging.CLog().Info("Stopped RPC GRPCServer and Gateway.")
}
