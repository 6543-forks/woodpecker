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

package forgejo

import (
	"context"
	"strconv"

	"codeberg.org/mvdkleijn/forgejo-sdk/forgejo/v3"
	"github.com/rs/zerolog/log"

	"go.woodpecker-ci.org/woodpecker/v3/server/forge/common"
	"go.woodpecker-ci.org/woodpecker/v3/server/model"
	shared_utils "go.woodpecker-ci.org/woodpecker/v3/shared/utils"
)

// updateCloneSecret replaces the read-only deploy key Woodpecker added to the repository.
func (c *Forgejo) updateCloneSecret(ctx context.Context, client *forgejo.Client, r *model.Repo) error {
	c.deleteDeployKeys(ctx, client, r.Owner, r.Name)
	r.CloneSecret = nil

	if r.CloneSSH == "" {
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
	key, _, err := client.CreateDeployKey(r.Owner, r.Name, forgejo.CreateKeyOption{
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

// deleteDeployKeys removes the deploy keys Woodpecker added to the repository.
// Failures are only logged, a leftover key is removed on the next activation.
func (c *Forgejo) deleteDeployKeys(ctx context.Context, client *forgejo.Client, owner, name string) {
	keys, err := shared_utils.Paginate(func(page int) ([]*forgejo.DeployKey, error) {
		keys, _, err := client.ListDeployKeys(owner, name, forgejo.ListDeployKeysOptions{
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
		if key.Title != common.DeployKeyTitle {
			continue
		}
		if _, err := client.DeleteDeployKey(owner, name, key.ID); err != nil {
			log.Warn().Err(err).Msgf("could not delete deploy key %q of %s/%s", key.Title, owner, name)
		}
	}
}
