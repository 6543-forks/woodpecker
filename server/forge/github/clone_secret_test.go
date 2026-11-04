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
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-github/v93/github"
	github_mock "github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"go.woodpecker-ci.org/woodpecker/v3/server/forge/common"
	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

// deployKeyMocks serves the repository, its hooks and its deploy keys.
func deployKeyMocks(t *testing.T, deleted *[]string, created **github.CreateDeployKeyRequest, meta *github.APIMeta) []github_mock.MockBackendOption {
	t.Helper()
	return []github_mock.MockBackendOption{
		github_mock.WithRequestMatch(github_mock.GetReposByOwnerByRepo, github.Repository{
			ID: new(int64(1)), Name: new("hello-world"), FullName: new("octocat/hello-world"), Owner: &github.User{Login: new("octocat")},
		}),
		github_mock.WithRequestMatch(github_mock.GetReposHooksByOwnerByRepo, []*github.Hook{}),
		github_mock.WithRequestMatchHandler(github_mock.PostReposHooksByOwnerByRepo, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, github.Hook{ID: new(int64(3))})
		})),
		github_mock.WithRequestMatch(github_mock.GetReposKeysByOwnerByRepo, []*github.Key{
			{ID: new(int64(7)), Title: new(common.DeployKeyTitle)},
			{ID: new(int64(8)), Title: new("someone-else")},
		}),
		github_mock.WithRequestMatchHandler(github_mock.DeleteReposKeysByOwnerByRepoByKeyId, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*deleted = append(*deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		})),
		github_mock.WithRequestMatchHandler(github_mock.PostReposKeysByOwnerByRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*created = new(github.CreateDeployKeyRequest)
			assert.NoError(t, json.NewDecoder(r.Body).Decode(*created))
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, github.Key{ID: new(int64(9))})
		})),
		github_mock.WithRequestMatch(github_mock.GetMeta, meta),
	}
}

func TestActivateCloneSecret(t *testing.T) {
	user := &model.User{AccessToken: "token"}

	t.Run("activation replaces the deploy key", func(t *testing.T) {
		var deleted []string
		var created *github.CreateDeployKeyRequest
		ctx := mockedContext(t, t.Context(), deployKeyMocks(t, &deleted, &created, &github.APIMeta{SSHKeys: []string{"ssh-ed25519 AAAAgithub"}})...)
		repo := &model.Repo{Owner: "octocat", Name: "hello-world", FullName: "octocat/hello-world", CloneSSH: "git@github.com:octocat/hello-world.git"}

		c := &client{API: defaultAPI, url: defaultURL}
		require.NoError(t, c.Activate(ctx, user, repo, "https://ci.example.com/api/hook?access_token=new"))

		assert.Equal(t, []string{"/repos/octocat/hello-world/keys/7"}, deleted, "only the old woodpecker key is removed")
		require.NotNil(t, created)
		assert.Equal(t, common.DeployKeyTitle, created.GetTitle())
		assert.True(t, created.GetReadOnly())

		require.NotNil(t, repo.CloneSecret)
		assert.Equal(t, "9", repo.CloneSecret.KeyID)
		assert.Equal(t, "github.com ssh-ed25519 AAAAgithub\n", repo.CloneSecret.SSHHostKey)
		signer, err := ssh.ParsePrivateKey([]byte(repo.CloneSecret.SSHKey))
		require.NoError(t, err)
		public, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(created.Key))
		require.NoError(t, err)
		assert.Empty(t, comment)
		assert.Equal(t, signer.PublicKey().Marshal(), public.Marshal())
	})

	t.Run("host key is scanned if the API has none", func(t *testing.T) {
		var deleted []string
		var created *github.CreateDeployKeyRequest
		ctx := mockedContext(t, t.Context(), deployKeyMocks(t, &deleted, &created, &github.APIMeta{})...)
		repo := &model.Repo{Owner: "octocat", Name: "hello-world", CloneSSH: "ssh://git@ghe.example:2222/octocat/hello-world.git"}

		c := &client{API: defaultAPI, url: defaultURL, scanHostKey: func(_ context.Context, cloneSSH string) (string, error) {
			assert.Equal(t, repo.CloneSSH, cloneSSH)
			return "[ghe.example]:2222 ssh-ed25519 AAAAscan\n", nil
		}}
		require.NoError(t, c.Activate(ctx, user, repo, "https://ci.example.com/api/hook?access_token=new"))

		require.NotNil(t, repo.CloneSecret)
		assert.Equal(t, "[ghe.example]:2222 ssh-ed25519 AAAAscan\n", repo.CloneSecret.SSHHostKey)
	})

	t.Run("no ssh clone url keeps the user token", func(t *testing.T) {
		var deleted []string
		var created *github.CreateDeployKeyRequest
		ctx := mockedContext(t, t.Context(), deployKeyMocks(t, &deleted, &created, &github.APIMeta{})...)
		repo := &model.Repo{Owner: "octocat", Name: "hello-world", CloneSecret: &model.CloneSecret{SSHKey: "old"}}

		c := &client{API: defaultAPI, url: defaultURL}
		require.NoError(t, c.Activate(ctx, user, repo, "https://ci.example.com/api/hook?access_token=new"))

		assert.Nil(t, repo.CloneSecret)
		assert.Nil(t, created)
		assert.Equal(t, []string{"/repos/octocat/hello-world/keys/7"}, deleted)
	})
}

func TestDeactivateRemovesDeployKey(t *testing.T) {
	var deleted []string
	var created *github.CreateDeployKeyRequest
	ctx := mockedContext(t, t.Context(), deployKeyMocks(t, &deleted, &created, &github.APIMeta{})...)

	c := &client{API: defaultAPI, url: defaultURL}
	require.NoError(t, c.Deactivate(ctx, &model.User{AccessToken: "token"}, &model.Repo{Owner: "octocat", Name: "hello-world"}, "https://ci.example.com/api/hook"))
	assert.Equal(t, []string{"/repos/octocat/hello-world/keys/7"}, deleted)
}

func TestNetrcCloneSecret(t *testing.T) {
	c := &client{API: defaultAPI, url: defaultURL}
	repo := &model.Repo{Clone: "https://github.com/octocat/hello-world.git", CloneSecret: &model.CloneSecret{SSHKey: "private key", SSHHostKey: "host key"}}

	netrc, err := c.Netrc(&model.User{AccessToken: "token"}, repo)
	require.NoError(t, err)
	assert.Equal(t, &model.Netrc{Machine: "github.com", SSHKey: "private key", SSHHostKey: "host key", Type: model.ForgeTypeGithub}, netrc)

	repo.CloneSecret = nil
	netrc, err = c.Netrc(&model.User{AccessToken: "token"}, repo)
	require.NoError(t, err)
	assert.Equal(t, &model.Netrc{Machine: "github.com", Login: "token", Password: "x-oauth-basic", Type: model.ForgeTypeGithub}, netrc)
}
