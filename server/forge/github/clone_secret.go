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
	"strconv"

	"github.com/google/go-github/v93/github"
	"github.com/rs/zerolog/log"

	"go.woodpecker-ci.org/woodpecker/v3/server/forge/common"
	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

// addDeployKey adds a read-only deploy key to the repository and stores it in the clone secret.
// Activate removes the previous key before through Deactivate.
func (c *client) addDeployKey(ctx context.Context, client *github.Client, r *model.Repo) error {
	r.CloneSecret = nil
	if r.CloneSSH == "" {
		return nil
	}

	hostKey, err := c.sshHostKey(ctx, client, r.CloneSSH)
	if err != nil {
		return err
	}
	private, authorized, err := common.GenerateDeployKey()
	if err != nil {
		return err
	}
	key, _, err := client.Repositories.CreateKey(ctx, r.Owner, r.Name, github.CreateDeployKeyRequest{
		Title:    new(common.DeployKeyTitle),
		Key:      authorized,
		ReadOnly: new(true),
	})
	if err != nil {
		return err
	}

	r.CloneSecret = &model.CloneSecret{
		SSHKey:     private,
		SSHHostKey: hostKey,
		KeyID:      strconv.FormatInt(key.GetID(), 10),
	}
	return nil
}

// sshHostKey returns the known_hosts lines of the GitHub SSH server, from the API if it publishes them.
func (c *client) sshHostKey(ctx context.Context, client *github.Client, cloneSSH string) (string, error) {
	meta, _, err := client.Meta.Get(ctx)
	if err == nil && len(meta.SSHKeys) > 0 {
		return common.KnownHostsLines(cloneSSH, meta.SSHKeys)
	}
	scan := c.scanHostKey
	if scan == nil {
		scan = common.ScanSSHHostKey
	}
	return scan(ctx, cloneSSH)
}

// deleteDeployKeys removes the deploy keys Woodpecker added to the repository.
// Failures are only logged, a leftover key is removed on the next activation.
func deleteDeployKeys(ctx context.Context, client *github.Client, owner, name string) {
	opts := &github.ListOptions{PerPage: defaultPageSize}
	for {
		keys, resp, err := client.Repositories.ListKeys(ctx, owner, name, opts)
		if err != nil {
			log.Warn().Err(err).Msgf("could not list deploy keys of %s/%s", owner, name)
			return
		}
		for _, key := range keys {
			if key.GetTitle() != common.DeployKeyTitle {
				continue
			}
			if _, err := client.Repositories.DeleteKey(ctx, owner, name, key.GetID()); err != nil {
				log.Warn().Err(err).Msgf("could not delete deploy key %d of %s/%s", key.GetID(), owner, name)
			}
		}
		if resp.NextPage == 0 {
			return
		}
		opts.Page = resp.NextPage
	}
}
