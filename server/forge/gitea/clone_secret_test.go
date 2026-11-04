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

package gitea

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"go.woodpecker-ci.org/woodpecker/v3/server/forge/common"
	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

type fakeDeployKey struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	Key      string `json:"key"`
	ReadOnly bool   `json:"read_only"`
	Token    string `json:"token,omitempty"`
}

// fakeKeyServer is a Gitea API with a fixed version and in-memory deploy keys.
type fakeKeyServer struct {
	mu          sync.Mutex
	version     string
	keys        []*fakeDeployKey
	nextID      int64
	failTokens  bool
	tokenAuth   []string
	tokenOption map[string]any
}

func (f *fakeKeyServer) handler() http.Handler {
	gin.SetMode(gin.TestMode)
	e := gin.New()
	e.GET("/api/v1/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"version": f.version})
	})
	e.GET("/api/v1/repos/:owner/:name", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"id": 5, "name": c.Param("name"), "full_name": c.Param("owner") + "/" + c.Param("name"),
			"owner": gin.H{"login": c.Param("owner")},
		})
	})
	e.GET("/api/v1/repos/:owner/:name/hooks", func(c *gin.Context) { c.JSON(http.StatusOK, []any{}) })
	e.POST("/api/v1/repos/:owner/:name/hooks", func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"id": 1}) })
	e.GET("/api/v1/repos/:owner/:name/keys", func(c *gin.Context) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if page := c.Query("page"); page != "" && page != "1" {
			c.JSON(http.StatusOK, []any{})
			return
		}
		c.JSON(http.StatusOK, f.keys)
	})
	e.POST("/api/v1/repos/:owner/:name/keys", func(c *gin.Context) {
		var opt fakeDeployKey
		if err := c.BindJSON(&opt); err != nil {
			return
		}
		c.JSON(http.StatusCreated, f.add(&opt))
	})
	e.POST("/api/v1/repos/:owner/:name/keys/tokens", func(c *gin.Context) {
		f.mu.Lock()
		f.tokenAuth = append(f.tokenAuth, c.GetHeader("Authorization"))
		fail := f.failTokens
		f.mu.Unlock()
		if fail {
			c.Status(http.StatusInternalServerError)
			return
		}
		var opt map[string]any
		if err := c.BindJSON(&opt); err != nil {
			return
		}
		f.mu.Lock()
		f.tokenOption = opt
		f.mu.Unlock()
		title, _ := opt["title"].(string)
		key := f.add(&fakeDeployKey{Title: title, ReadOnly: true})
		created := *key
		created.Token = "gdt_" + strconv.FormatInt(key.ID, 10)
		c.JSON(http.StatusCreated, created)
	})
	e.DELETE("/api/v1/repos/:owner/:name/keys/:id", func(c *gin.Context) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, key := range f.keys {
			if strconv.FormatInt(key.ID, 10) == c.Param("id") {
				f.keys = append(f.keys[:i], f.keys[i+1:]...)
				c.Status(http.StatusNoContent)
				return
			}
		}
		c.Status(http.StatusNotFound)
	})
	return e
}

func (f *fakeKeyServer) add(key *fakeDeployKey) *fakeDeployKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	key.ID = f.nextID
	f.keys = append(f.keys, key)
	return key
}

func (f *fakeKeyServer) titles() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	titles := make([]string, 0, len(f.keys))
	for _, key := range f.keys {
		titles = append(titles, key.Title)
	}
	return titles
}

func newKeyForge(t *testing.T, version string) (*Gitea, *fakeKeyServer) {
	t.Helper()
	fake := &fakeKeyServer{version: version}
	s := httptest.NewServer(fake.handler())
	t.Cleanup(s.Close)
	f, err := New(1, Opts{URL: s.URL})
	require.NoError(t, err)
	g, _ := f.(*Gitea)
	g.scanHostKey = func(_ context.Context, cloneSSH string) (string, error) {
		if cloneSSH == "git@unreachable:owner/repo.git" {
			return "", errors.New("connection refused")
		}
		return "gitea.example ssh-ed25519 AAAA\n", nil
	}
	return g, fake
}

func cloneRepo() *model.Repo {
	return &model.Repo{
		Owner: "owner", Name: "repo", FullName: "owner/repo", Timeout: 60,
		Clone: "https://gitea.example/owner/repo.git", CloneSSH: "git@gitea.example:owner/repo.git",
	}
}

func TestNetrcCloneCredentials(t *testing.T) {
	user := &model.User{Login: "alice", AccessToken: "oauth-token"}
	expired := common.CloneTokenPrefix + strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10) + "-00000000"
	valid := common.CloneTokenPrefix + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + "-00000000"

	t.Run("gitea with deploy tokens creates a read-only token and removes expired ones", func(t *testing.T) {
		g, fake := newKeyForge(t, "1.28.0")
		fake.add(&fakeDeployKey{Title: expired})
		fake.add(&fakeDeployKey{Title: valid})
		fake.add(&fakeDeployKey{Title: "someone-else"})
		repo := cloneRepo()
		repo.CloneSecret = &model.CloneSecret{SSHKey: "left from an older gitea"}

		netrc, err := g.Netrc(user, repo)
		require.NoError(t, err)
		assert.Equal(t, "gitea.example", netrc.Machine)
		assert.True(t, strings.HasPrefix(netrc.Password, "gdt_"), "the netrc must carry the deploy token, got %q", netrc.Password)
		assert.NotEmpty(t, netrc.Login)
		assert.Empty(t, netrc.SSHKey, "a deploy token replaces the deploy key")
		assert.Equal(t, []string{"token oauth-token"}, fake.tokenAuth)
		assert.Equal(t, true, fake.tokenOption["read_only"])

		titles := fake.titles()
		assert.NotContains(t, titles, expired)
		assert.Contains(t, titles, valid)
		assert.Contains(t, titles, "someone-else")
		created := titles[len(titles)-1]
		assert.True(t, strings.HasPrefix(created, common.CloneTokenPrefix))
		assert.False(t, common.CloneTokenExpired(created, time.Now().Add(time.Hour+common.CloneTokenSlack-time.Minute)),
			"the token must outlive the repo timeout plus queue slack")
	})

	t.Run("failing deploy token falls back to the user token", func(t *testing.T) {
		g, fake := newKeyForge(t, "1.28.0")
		fake.failTokens = true

		netrc, err := g.Netrc(user, cloneRepo())
		require.NoError(t, err)
		assert.Equal(t, "alice", netrc.Login)
		assert.Equal(t, "oauth-token", netrc.Password)
	})

	t.Run("older gitea uses the deploy key", func(t *testing.T) {
		g, fake := newKeyForge(t, "1.27.3")
		repo := cloneRepo()
		repo.CloneSecret = &model.CloneSecret{SSHKey: "private key", SSHHostKey: "host key"}

		netrc, err := g.Netrc(user, repo)
		require.NoError(t, err)
		assert.Equal(t, "private key", netrc.SSHKey)
		assert.Equal(t, "host key", netrc.SSHHostKey)
		assert.Empty(t, netrc.Login)
		assert.Empty(t, netrc.Password)
		assert.Empty(t, fake.tokenAuth, "older gitea has no deploy tokens")
	})

	t.Run("older gitea without deploy key falls back to the user token", func(t *testing.T) {
		g, _ := newKeyForge(t, "1.27.3")

		netrc, err := g.Netrc(user, cloneRepo())
		require.NoError(t, err)
		assert.Equal(t, "alice", netrc.Login)
		assert.Equal(t, "oauth-token", netrc.Password)
	})
}

func TestActivateCloneSecret(t *testing.T) {
	user := &model.User{Login: "alice", AccessToken: "oauth-token"}

	t.Run("older gitea rotates the deploy key", func(t *testing.T) {
		g, fake := newKeyForge(t, "1.27.3")
		fake.add(&fakeDeployKey{Title: common.DeployKeyTitle, Key: "old"})
		fake.add(&fakeDeployKey{Title: "someone-else"})
		repo := cloneRepo()

		require.NoError(t, g.Activate(t.Context(), user, repo, "https://ci.example/api/hook"))

		require.NotNil(t, repo.CloneSecret)
		assert.Equal(t, "gitea.example ssh-ed25519 AAAA\n", repo.CloneSecret.SSHHostKey)
		signer, err := ssh.ParsePrivateKey([]byte(repo.CloneSecret.SSHKey))
		require.NoError(t, err)

		fake.mu.Lock()
		defer fake.mu.Unlock()
		require.Len(t, fake.keys, 2, "the old woodpecker key must be replaced")
		assert.Equal(t, "someone-else", fake.keys[0].Title)
		created := fake.keys[1]
		assert.Equal(t, common.DeployKeyTitle, created.Title)
		assert.True(t, created.ReadOnly)
		assert.Equal(t, strconv.FormatInt(created.ID, 10), repo.CloneSecret.KeyID)
		public, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(created.Key))
		require.NoError(t, err)
		assert.Empty(t, comment)
		assert.Equal(t, signer.PublicKey().Marshal(), public.Marshal())
	})

	t.Run("gitea with deploy tokens drops the deploy key", func(t *testing.T) {
		g, fake := newKeyForge(t, "1.28.0")
		fake.add(&fakeDeployKey{Title: common.DeployKeyTitle, Key: "old"})
		repo := cloneRepo()
		repo.CloneSecret = &model.CloneSecret{SSHKey: "old"}

		require.NoError(t, g.Activate(t.Context(), user, repo, "https://ci.example/api/hook"))

		assert.Nil(t, repo.CloneSecret)
		assert.Empty(t, fake.titles())
	})

	for _, tc := range []struct {
		name     string
		cloneSSH string
	}{
		{name: "no ssh clone url keeps the user token", cloneSSH: ""},
		{name: "unreachable ssh server keeps the user token", cloneSSH: "git@unreachable:owner/repo.git"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, fake := newKeyForge(t, "1.27.3")
			repo := cloneRepo()
			repo.CloneSSH = tc.cloneSSH

			require.NoError(t, g.Activate(t.Context(), user, repo, "https://ci.example/api/hook"), "activation must not fail on the optional key")
			assert.Nil(t, repo.CloneSecret)
			assert.Empty(t, fake.titles())
		})
	}
}

func TestDeactivateRemovesCloneCredentials(t *testing.T) {
	g, fake := newKeyForge(t, "1.28.0")
	fake.add(&fakeDeployKey{Title: common.DeployKeyTitle})
	fake.add(&fakeDeployKey{Title: common.NewCloneTokenName(time.Now().Add(time.Hour))})
	fake.add(&fakeDeployKey{Title: "someone-else"})

	require.NoError(t, g.Deactivate(t.Context(), &model.User{AccessToken: "oauth-token"}, cloneRepo(), "https://ci.example"))
	assert.Equal(t, []string{"someone-else"}, fake.titles())
}
