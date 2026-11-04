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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/rs/zerolog/log"

	"go.woodpecker-ci.org/woodpecker/v3/server/forge/common"
	"go.woodpecker-ci.org/woodpecker/v3/server/model"
	shared_utils "go.woodpecker-ci.org/woodpecker/v3/shared/utils"
)

const (
	// Gitea versions with deploy tokens (go-gitea/gitea#37306).
	deployTokenConstraint = ">= 1.28.0+dev"
	// Netrc login for a deploy token, Gitea only checks the password.
	deployTokenLogin   = "woodpecker"
	cloneSecretTimeout = 30 * time.Second
	maxErrorBodyLength = 1024
)

// supportsDeployTokens reports whether the Gitea server can create deploy tokens.
func supportsDeployTokens(client *gitea.Client) bool {
	return client.CheckServerVersionConstraint(deployTokenConstraint) == nil
}

// cloneToken returns a new read-only deploy token for the repository, or an empty
// string if the server has no deploy tokens. Expired clone tokens are removed first.
func (c *Gitea) cloneToken(ctx context.Context, u *model.User, r *model.Repo) (string, error) {
	client, err := c.newClientToken(ctx, u.AccessToken)
	if err != nil {
		return "", err
	}
	if !supportsDeployTokens(client) {
		return "", nil
	}

	now := time.Now()
	c.deleteDeployKeys(ctx, client, r.Owner, r.Name, func(title string) bool {
		return common.CloneTokenExpired(title, now)
	})

	body, err := json.Marshal(map[string]any{
		"title":     common.NewCloneTokenName(common.CloneTokenExpiry(r, now)),
		"read_only": true,
	})
	if err != nil {
		return "", err
	}
	link := fmt.Sprintf("%s/api/v1/repos/%s/%s/keys/tokens", strings.TrimRight(c.url, "/"), url.PathEscape(r.Owner), url.PathEscape(r.Name))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, link, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+u.AccessToken)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyLength))
		return "", fmt.Errorf("create deploy token: %s: %s", resp.Status, msg)
	}
	var key struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return "", err
	}
	if key.Token == "" {
		return "", fmt.Errorf("create deploy token: empty token in response")
	}
	return key.Token, nil
}

// updateCloneSecret replaces the deploy key Woodpecker added to the repository.
// Gitea with deploy tokens gets no key, it uses a fresh token per pipeline instead.
func (c *Gitea) updateCloneSecret(ctx context.Context, client *gitea.Client, r *model.Repo) error {
	c.deleteDeployKeys(ctx, client, r.Owner, r.Name, func(title string) bool {
		return title == common.DeployKeyTitle
	})
	r.CloneSecret = nil

	if supportsDeployTokens(client) || r.CloneSSH == "" {
		return nil
	}

	hostKey, err := c.scanHostKey(ctx, r.CloneSSH)
	if err != nil {
		return err
	}
	private, authorized, err := common.GenerateDeployKey()
	if err != nil {
		return err
	}
	key, _, err := client.CreateDeployKey(r.Owner, r.Name, gitea.CreateKeyOption{
		Title:    common.DeployKeyTitle,
		Key:      authorized,
		ReadOnly: true,
	})
	if err != nil {
		return err
	}

	r.CloneSecret = &model.CloneSecret{
		SSHKey:     private,
		SSHHostKey: hostKey,
		KeyID:      strconv.FormatInt(key.ID, 10),
	}
	return nil
}

// deleteDeployKeys removes the deploy keys and deploy tokens whose title matches.
// Failures are only logged, a leftover key is removed on the next run.
func (c *Gitea) deleteDeployKeys(ctx context.Context, client *gitea.Client, owner, name string, match func(title string) bool) {
	keys, err := shared_utils.Paginate(func(page int) ([]*gitea.DeployKey, error) {
		keys, _, err := client.ListDeployKeys(owner, name, gitea.ListDeployKeysOptions{
			Page:     page,
			PageSize: c.perPage(ctx),
		})
		return keys, err
	}, -1)
	if err != nil {
		log.Warn().Err(err).Msgf("could not list deploy keys of %s/%s", owner, name)
		return
	}
	for _, key := range keys {
		if !match(key.Title) {
			continue
		}
		if _, err := client.DeleteDeployKey(owner, name, key.ID); err != nil {
			log.Warn().Err(err).Msgf("could not delete deploy key %q of %s/%s", key.Title, owner, name)
		}
	}
}
