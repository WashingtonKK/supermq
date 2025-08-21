// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const StopWaitTime = 5 * time.Second

// Server is an interface that defines the methods to start and stop a server.
type Server interface {
	// Start starts the server.
	Start() error
	// Stop stops the server.
	Stop() error
}

// Config is a struct that contains the configuration for the server.
type Config struct {
	Host         string `env:"HOST"            envDefault:"localhost"`
	Port         string `env:"PORT"            envDefault:""`
	CertFile     string `env:"SERVER_CERT"     envDefault:""`
	KeyFile      string `env:"SERVER_KEY"      envDefault:""`
	ServerCAFile string `env:"SERVER_CA_CERTS" envDefault:""`
	ClientCAFile string `env:"CLIENT_CA_CERTS" envDefault:""`
}

type BaseServer struct {
	Ctx      context.Context
	Cancel   context.CancelFunc
	Name     string
	Address  string
	Config   Config
	Logger   *slog.Logger
	Protocol string
}

func NewBaseServer(ctx context.Context, cancel context.CancelFunc, name string, config Config, logger *slog.Logger) BaseServer {
	address := fmt.Sprintf("%s:%s", config.Host, config.Port)

	return BaseServer{
		Ctx:     ctx,
		Cancel:  cancel,
		Name:    name,
		Address: address,
		Config:  config,
		Logger:  logger,
	}
}

func stopAllServer(servers ...Server) error {
	var err error
	for _, server := range servers {
		err1 := server.Stop()
		if err1 != nil {
			if err == nil {
				err = fmt.Errorf("%w", err1)
			} else {
				err = fmt.Errorf("%v ; %w", err, err1)
			}
		}
	}
	return err
}

// StopSignalHandler stops the server when a signal is received.
func StopSignalHandler(ctx context.Context, cancel context.CancelFunc, logger *slog.Logger, svcName string, servers ...Server) error {
	var err error
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGABRT)
	select {
	case sig := <-c:
		defer cancel()
		err = stopAllServer(servers...)
		if err != nil {
			logger.Error(fmt.Sprintf("%s service error during shutdown: %v", svcName, err))
		}
		logger.Info(fmt.Sprintf("%s service shutdown by signal: %s", svcName, sig))
		return err
	case <-ctx.Done():
		return nil
	}
}

func ReadFileOrData(input string) ([]byte, error) {
	if _, err := os.Stat(input); err == nil {
		return os.ReadFile(input)
	}
	return []byte(input), nil
}

func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := ReadFileOrData(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert: %v", err)
	}

	key, err := ReadFileOrData(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key: %v", err)
	}

	return tls.X509KeyPair(cert, key)
}

func LoadRootCACerts(input string) (*x509.CertPool, error) {
	pemData, err := ReadFileOrData(input)
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA data: %w", err)
	}

	if len(pemData) > 0 {
		capool := x509.NewCertPool()
		if !capool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("failed to append root ca to tls.Config")
		}
		return capool, nil
	}
	return nil, nil
}
