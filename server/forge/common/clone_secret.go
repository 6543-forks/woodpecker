// Copyright 2026 Woodpecker Authors
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

package common

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

const (
	// DeployKeyTitle is the title of the read-only deploy key Woodpecker adds on activation.
	DeployKeyTitle = "woodpecker-deploy-key"
	// CloneTokenPrefix starts the name of every clone token Woodpecker creates for a pipeline.
	CloneTokenPrefix = "woodpecker-clone-"
	// CloneTokenSlack is added to the repository timeout, so a token outlives the time a pipeline waits in the queue.
	CloneTokenSlack = 24 * time.Hour

	sshScanTimeout = 10 * time.Second
)

// GenerateDeployKey returns a new ed25519 key pair, the private key as OpenSSH PEM
// and the public key in authorized_keys format.
func GenerateDeployKey() (privateKey, authorizedKey string, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	block, err := ssh.MarshalPrivateKey(private, DeployKeyTitle)
	if err != nil {
		return "", "", err
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(block)), string(ssh.MarshalAuthorizedKey(sshPublic)), nil
}

// ScanSSHHostKey connects to the SSH server of an SSH clone URL and returns its
// host key as known_hosts line. The key is trusted on first use, call it on
// activation and keep the result.
func ScanSSHHostKey(ctx context.Context, cloneSSH string) (string, error) {
	address, err := sshAddress(cloneSSH)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, sshScanTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "git",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
	}
	// without auth methods the handshake fails after the key exchange, which is all we need
	sshConn, _, _, err := ssh.NewClientConn(conn, address, config)
	if err == nil {
		_ = sshConn.Close()
	}
	if hostKey == nil {
		return "", fmt.Errorf("could not get the host key of %s: %w", address, err)
	}
	return knownhosts.Line([]string{knownhosts.Normalize(address)}, hostKey) + "\n", nil
}

// sshAddress returns host:port of an SSH clone URL, in URL (ssh://) or scp-like form.
func sshAddress(cloneSSH string) (string, error) {
	if strings.HasPrefix(cloneSSH, "ssh://") {
		u, err := url.Parse(cloneSSH)
		if err != nil {
			return "", err
		}
		if u.Hostname() == "" {
			return "", fmt.Errorf("no host in SSH clone URL %q", cloneSSH)
		}
		port := u.Port()
		if port == "" {
			port = "22"
		}
		return net.JoinHostPort(u.Hostname(), port), nil
	}

	// scp-like: [user@]host:path
	hostPart, _, found := strings.Cut(cloneSSH, ":")
	if !found || strings.Contains(hostPart, "/") || strings.Contains(cloneSSH, "://") {
		return "", fmt.Errorf("unsupported SSH clone URL %q", cloneSSH)
	}
	if _, host, ok := strings.Cut(hostPart, "@"); ok {
		hostPart = host
	}
	if hostPart == "" {
		return "", errors.New("no host in SSH clone URL")
	}
	return net.JoinHostPort(hostPart, "22"), nil
}

// CloneTokenExpiry returns when a clone token created now for a pipeline of the repository may be removed.
func CloneTokenExpiry(r *model.Repo, now time.Time) time.Time {
	return now.Add(time.Duration(r.Timeout)*time.Minute + CloneTokenSlack)
}

// NewCloneTokenName returns a unique clone token name that carries its expiry,
// for forges whose tokens do not expire on their own.
func NewCloneTokenName(expiry time.Time) string {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	return CloneTokenPrefix + strconv.FormatInt(expiry.Unix(), 10) + "-" + hex.EncodeToString(suffix)
}

// CloneTokenExpired reports whether name is a clone token created by NewCloneTokenName that expired before now.
func CloneTokenExpired(name string, now time.Time) bool {
	rest, ok := strings.CutPrefix(name, CloneTokenPrefix)
	if !ok {
		return false
	}
	unix, _, _ := strings.Cut(rest, "-")
	expiry, err := strconv.ParseInt(unix, 10, 64)
	if err != nil {
		return false
	}
	return now.After(time.Unix(expiry, 0))
}
