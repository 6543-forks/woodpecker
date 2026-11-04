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
	"crypto/rsa"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v93/github"

	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

const (
	// GitHub accepts app JWTs valid for at most ten minutes, the start is set back for clock drift.
	appJWTLifetime   = 9 * time.Minute
	appJWTClockDrift = time.Minute
	appTokenTimeout  = 30 * time.Second
)

// parseAppKey returns the private key of a GitHub App.
func parseAppKey(appID int64, pemKey string) (*rsa.PrivateKey, error) {
	if appID <= 0 {
		return nil, errors.New("a GitHub App private key needs the app id")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemKey))
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub App private key: %w", err)
	}
	return key, nil
}

// newAppClient returns a client authenticated as the GitHub App.
func (c *client) newAppClient(ctx context.Context) (*github.Client, error) {
	now := time.Now()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    strconv.FormatInt(c.appID, 10),
		IssuedAt:  jwt.NewNumericDate(now.Add(-appJWTClockDrift)),
		ExpiresAt: jwt.NewNumericDate(now.Add(appJWTLifetime)),
	}).SignedString(c.appKey)
	if err != nil {
		return nil, err
	}
	return c.newClientToken(ctx, signed)
}

// appInstalled reports whether the GitHub App can access the repository.
func (c *client) appInstalled(ctx context.Context, r *model.Repo) bool {
	if c.appKey == nil {
		return false
	}
	client, err := c.newAppClient(ctx)
	if err != nil {
		return false
	}
	_, _, err = client.Apps.GetRepositoryInstallation(ctx, r.Owner, r.Name)
	return err == nil
}

// installationToken returns a token of the GitHub App installation that can
// only read the contents of the repository. It expires after one hour.
func (c *client) installationToken(ctx context.Context, r *model.Repo) (string, error) {
	client, err := c.newAppClient(ctx)
	if err != nil {
		return "", err
	}
	installation, _, err := client.Apps.GetRepositoryInstallation(ctx, r.Owner, r.Name)
	if err != nil {
		return "", err
	}

	opts := &github.InstallationTokenOptions{
		Permissions: &github.InstallationPermissions{Contents: new("read")},
	}
	if id, err := strconv.ParseInt(string(r.ForgeRemoteID), 10, 64); err == nil {
		opts.RepositoryIDs = []int64{id}
	} else {
		opts.Repositories = []string{r.Name}
	}
	token, _, err := client.Apps.CreateInstallationToken(ctx, installation.GetID(), opts)
	if err != nil {
		return "", err
	}
	if token.GetToken() == "" {
		return "", errors.New("installation token is empty")
	}
	return token.GetToken(), nil
}
