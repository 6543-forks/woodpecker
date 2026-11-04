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

package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v93/github"
	github_mock "github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

func newAppKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func TestNewWithApp(t *testing.T) {
	_, pemKey := newAppKey(t)

	f, err := New(1, Opts{URL: defaultURL, AppID: 42, AppPrivateKey: pemKey})
	require.NoError(t, err)
	c, _ := f.(*client)
	assert.EqualValues(t, 42, c.appID)
	assert.NotNil(t, c.appKey)

	_, err = New(1, Opts{URL: defaultURL, AppID: 42, AppPrivateKey: "not a key"})
	assert.Error(t, err)
	_, err = New(1, Opts{URL: defaultURL, AppPrivateKey: pemKey})
	assert.Error(t, err, "a private key needs the app id")
}

// fakeApp serves the installation and access token API of a GitHub App.
type fakeApp struct {
	key          *rsa.PrivateKey
	installed    bool
	tokenRequest map[string]any
}

func (f *fakeApp) server(t *testing.T) *httptest.Server {
	t.Helper()
	checkJWT := func(r *http.Request) bool {
		signed, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !assert.True(t, ok, "app requests use a bearer JWT") {
			return false
		}
		token, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return &f.key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
		if !assert.NoError(t, err) {
			return false
		}
		issuer, _ := token.Claims.GetIssuer()
		return assert.Equal(t, "42", issuer)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/octocat/hello-world/installation", func(w http.ResponseWriter, r *http.Request) {
		if !checkJWT(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !f.installed {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, w, github.Installation{ID: new(int64(7))})
	})
	mux.HandleFunc("POST /api/v3/app/installations/7/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if !checkJWT(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.tokenRequest = make(map[string]any)
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&f.tokenRequest))
		w.WriteHeader(http.StatusCreated)
		writeJSON(t, w, github.InstallationToken{Token: new("ghs_installation")})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestNetrcAppToken(t *testing.T) {
	key, pemKey := newAppKey(t)
	user := &model.User{AccessToken: "token"}
	newRepo := func() *model.Repo {
		return &model.Repo{ForgeRemoteID: "1", Owner: "octocat", Name: "hello-world", Clone: "https://ghe.example/octocat/hello-world.git"}
	}
	newForge := func(t *testing.T, fake *fakeApp) *client {
		t.Helper()
		f, err := New(1, Opts{URL: fake.server(t).URL, AppID: 42, AppPrivateKey: pemKey})
		require.NoError(t, err)
		c, _ := f.(*client)
		return c
	}

	t.Run("installed app gives a read-only token for the repository", func(t *testing.T) {
		fake := &fakeApp{key: key, installed: true}
		repo := newRepo()
		repo.CloneSecret = &model.CloneSecret{SSHKey: "fallback key"}

		netrc, err := newForge(t, fake).Netrc(user, repo)
		require.NoError(t, err)
		assert.Equal(t, &model.Netrc{Machine: "ghe.example", Login: "x-access-token", Password: "ghs_installation", Type: model.ForgeTypeGithub}, netrc)
		assert.Equal(t, []any{float64(1)}, fake.tokenRequest["repository_ids"])
		assert.Equal(t, map[string]any{"contents": "read"}, fake.tokenRequest["permissions"])
	})

	t.Run("app not installed falls back to the deploy key", func(t *testing.T) {
		repo := newRepo()
		repo.CloneSecret = &model.CloneSecret{SSHKey: "fallback key", SSHHostKey: "host key"}

		netrc, err := newForge(t, &fakeApp{key: key}).Netrc(user, repo)
		require.NoError(t, err)
		assert.Equal(t, &model.Netrc{Machine: "ghe.example", SSHKey: "fallback key", SSHHostKey: "host key", Type: model.ForgeTypeGithub}, netrc)
	})

	t.Run("app not installed and no deploy key falls back to the user token", func(t *testing.T) {
		netrc, err := newForge(t, &fakeApp{key: key}).Netrc(user, newRepo())
		require.NoError(t, err)
		assert.Equal(t, &model.Netrc{Machine: "ghe.example", Login: "token", Password: "x-oauth-basic", Type: model.ForgeTypeGithub}, netrc)
	})
}

func TestActivateWithInstalledApp(t *testing.T) {
	_, pemKey := newAppKey(t)
	f, err := New(1, Opts{URL: defaultURL, AppID: 42, AppPrivateKey: pemKey})
	require.NoError(t, err)
	c, _ := f.(*client)

	var deleted []string
	var created *github.CreateDeployKeyRequest
	mocks := append(deployKeyMocks(t, &deleted, &created, &github.APIMeta{SSHKeys: []string{"ssh-ed25519 AAAAgithub"}}),
		github_mock.WithRequestMatch(github_mock.GetReposInstallationByOwnerByRepo, github.Installation{ID: new(int64(7))}))
	ctx := mockedContext(t, t.Context(), mocks...)
	repo := &model.Repo{Owner: "octocat", Name: "hello-world", CloneSSH: "git@github.com:octocat/hello-world.git", CloneSecret: &model.CloneSecret{SSHKey: "old"}}

	require.NoError(t, c.Activate(ctx, &model.User{AccessToken: "token"}, repo, "https://ci.example.com/api/hook?access_token=new"))
	assert.Nil(t, created, "the installed app replaces the deploy key")
	assert.Nil(t, repo.CloneSecret)
	assert.Equal(t, []string{"/repos/octocat/hello-world/keys/7"}, deleted, "a key of an earlier activation is removed")
}
