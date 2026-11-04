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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

func TestGenerateDeployKey(t *testing.T) {
	private, authorized, err := GenerateDeployKey()
	require.NoError(t, err)

	signer, err := ssh.ParsePrivateKey([]byte(private))
	require.NoError(t, err)
	public, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	require.NoError(t, err)
	assert.Empty(t, comment)
	assert.Equal(t, ssh.KeyAlgoED25519, public.Type())
	assert.Equal(t, signer.PublicKey().Marshal(), public.Marshal(), "the authorized key must belong to the private key")

	other, _, err := GenerateDeployKey()
	require.NoError(t, err)
	assert.NotEqual(t, private, other)
}

func TestSSHAddress(t *testing.T) {
	for _, tc := range []struct {
		cloneSSH string
		want     string
		wantErr  bool
	}{
		{cloneSSH: "git@gitea.com:owner/repo.git", want: "gitea.com:22"},
		{cloneSSH: "gitea.com:owner/repo.git", want: "gitea.com:22"},
		{cloneSSH: "ssh://git@gitea.com/owner/repo.git", want: "gitea.com:22"},
		{cloneSSH: "ssh://git@gitea.com:2222/owner/repo.git", want: "gitea.com:2222"},
		{cloneSSH: "ssh://git@[::1]:2222/owner/repo.git", want: "[::1]:2222"},
		{cloneSSH: "", wantErr: true},
		{cloneSSH: "https://gitea.com/owner/repo.git", wantErr: true},
		{cloneSSH: "/local/path", wantErr: true},
	} {
		t.Run(tc.cloneSSH, func(t *testing.T) {
			got, err := sshAddress(tc.cloneSSH)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestScanSSHHostKey(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, errors.New("denied")
		},
	}
	config.AddHostKey(hostSigner)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// the client offers no auth method, so the connection ends after the key exchange
			_, _, _, _ = ssh.NewServerConn(conn, config)
			_ = conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // tcp listener
	line, err := ScanSSHHostKey(t.Context(), "ssh://git@127.0.0.1:"+strconv.Itoa(port)+"/owner/repo.git")
	require.NoError(t, err)
	assert.Equal(t, knownhosts.Line([]string{knownhosts.Normalize("127.0.0.1:" + strconv.Itoa(port))}, hostSigner.PublicKey())+"\n", line)

	_, err = ScanSSHHostKey(t.Context(), "https://gitea.com/owner/repo.git")
	assert.Error(t, err)
}

func TestCloneToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	expiry := CloneTokenExpiry(&model.Repo{Timeout: 60}, now)
	assert.Equal(t, now.Add(time.Hour+CloneTokenSlack), expiry)

	name := NewCloneTokenName(expiry)
	assert.True(t, strings.HasPrefix(name, CloneTokenPrefix))
	assert.LessOrEqual(t, len(name), 50, "gitea limits deploy key titles to 50 characters")
	assert.NotEqual(t, name, NewCloneTokenName(expiry), "names must be unique per repository")

	for _, tc := range []struct {
		name    string
		now     time.Time
		expired bool
	}{
		{name: name, now: now, expired: false},
		{name: name, now: expiry, expired: false},
		{name: name, now: expiry.Add(time.Second), expired: true},
		{name: DeployKeyTitle, now: expiry.Add(time.Hour)},
		{name: "my-own-token", now: expiry.Add(time.Hour)},
		{name: CloneTokenPrefix + "garbage", now: expiry.Add(time.Hour)},
	} {
		assert.Equal(t, tc.expired, CloneTokenExpired(tc.name, tc.now), tc.name)
	}
}
