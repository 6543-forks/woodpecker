// Copyright 2024 Woodpecker Authors
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

package msdevops

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/microsoft/azure-devops-go-api/azuredevops"
	"github.com/microsoft/azure-devops-go-api/azuredevops/core"
	"github.com/microsoft/azure-devops-go-api/azuredevops/git"

	"go.woodpecker-ci.org/woodpecker/v2/server/forge"
	"go.woodpecker-ci.org/woodpecker/v2/server/forge/common"
	"go.woodpecker-ci.org/woodpecker/v2/server/forge/types"
	forge_types "go.woodpecker-ci.org/woodpecker/v2/server/forge/types"
	"go.woodpecker-ci.org/woodpecker/v2/server/model"
)

const (
	defaultBaseURL = "https://dev.azure.com"
)

type MSDevOps struct {
	url          string
	clientID     string
	clientSecret string
	client       *azuredevops.Connection
}

// Opts defines configuration options.
type Opts struct {
	URL          string // Azure DevOps server url. Defaults to https://dev.azure.com if empty
	ClientID     string // OAuth2 Client ID
	ClientSecret string // OAuth2 Client Secret
}

// New returns a Forge implementation that integrates with Microsoft Azure DevOps.
// If no URL is provided, it will use https://dev.azure.com as the default.
func New(opts Opts) (forge.Forge, error) {
	url := opts.URL
	if url == "" {
		url = defaultBaseURL
	}

	// Ensure URL has no trailing slash
	url = strings.TrimRight(url, "/")

	connection := azuredevops.NewPatConnection(url, opts.ClientSecret)

	return &MSDevOps{
		url:          url,
		clientID:     opts.ClientID,
		clientSecret: opts.ClientSecret,
		client:       connection,
	}, nil
}

// Name returns the string name of this driver.
func (c *MSDevOps) Name() string {
	return "msdevops"
}

// URL returns the root URL for Azure DevOps.
func (c *MSDevOps) URL() string {
	return c.url
}

func (c *MSDevOps) Login(ctx context.Context, req *forge_types.OAuthRequest) (*model.User, string, error) {
	// TODO: Implement OAuth2 flow
	return nil, "", types.ErrNotImplemented
}

func (c *MSDevOps) Auth(ctx context.Context, token, secret string) (string, error) {
	// Create a client connection using the token
	conn := azuredevops.NewPatConnection(c.url, token)
	coreClient, err := core.NewClient(ctx, conn)
	if err != nil {
		return "", err
	}

	// Get authenticated user details
	connData, err := coreClient.GetConnectionData(ctx)
	if err != nil {
		return "", err
	}

	return *connData.AuthenticatedUser.ProviderDisplayName, nil
}

func (c *MSDevOps) Teams(ctx context.Context, u *model.User) ([]*model.Team, error) {
	return nil, types.ErrNotImplemented
}

func (c *MSDevOps) Repo(ctx context.Context, u *model.User, remoteID model.ForgeRemoteID, owner, name string) (*model.Repo, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	sRemoteID := string(remoteID)

	repo, err := gitClient.GetRepository(ctx, git.GetRepositoryArgs{
		RepositoryId: &sRemoteID,
		Project:      &owner,
	})
	if err != nil {
		return nil, err
	}

	return convertRepo(repo), nil
}

func (c *MSDevOps) Repos(ctx context.Context, u *model.User) ([]*model.Repo, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	repos, err := gitClient.GetRepositories(ctx, git.GetRepositoriesArgs{})
	if err != nil {
		return nil, err
	}
	if repos == nil {
		return nil, fmt.Errorf("we got a nil pointer which should never happen")
	}

	result := make([]*model.Repo, 0, len(*repos))
	for i, repo := range *repos {
		result[i] = convertRepo(&repo)
	}

	return result, nil
}

func (c *MSDevOps) File(ctx context.Context, u *model.User, r *model.Repo, b *model.Pipeline, f string) ([]byte, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	item, err := gitClient.GetItem(ctx, git.GetItemArgs{
		RepositoryId: string(r.ForgeRemoteID),
		Path:         &f,
		Version:      &b.Commit,
	})
	if err != nil {
		return nil, err
	}

	return []byte(*item.Content), nil
}

func (c *MSDevOps) Dir(ctx context.Context, u *model.User, r *model.Repo, b *model.Pipeline, f string) ([]*forge_types.FileMeta, error) {
	return nil, types.ErrNotImplemented
}

func (c *MSDevOps) Status(ctx context.Context, u *model.User, r *model.Repo, b *model.Pipeline, w *model.Workflow) error {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return err
	}

	state := convertStatus(w.State)
	_, err = gitClient.CreateCommitStatus(ctx, git.CreateCommitStatusArgs{
		Project:      &r.Owner,
		RepositoryId: string(r.ForgeRemoteID),
		CommitId:     &b.Commit,
		GitCommitStatusToCreate: &git.GitCommitStatus{
			State:       &state,
			Description: &w.Title,
			TargetUrl:   &b.Link,
		},
	})

	return err
}

func (c *MSDevOps) Netrc(u *model.User, r *model.Repo) (*model.Netrc, error) {
	host, err := common.ExtractHostFromCloneURL(r.Clone)
	if err != nil {
		return nil, err
	}

	return &model.Netrc{
		Machine:  host,
		Login:    u.Login,
		Password: u.Token,
	}, nil
}

func (c *MSDevOps) Activate(ctx context.Context, u *model.User, r *model.Repo, link string) error {
	// TODO: Implement webhook creation
	return types.ErrNotImplemented
}

func (c *MSDevOps) Deactivate(ctx context.Context, u *model.User, r *model.Repo, link string) error {
	// TODO: Implement webhook deletion
	return types.ErrNotImplemented
}

func (c *MSDevOps) Branches(ctx context.Context, u *model.User, r *model.Repo, p *model.ListOptions) ([]string, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	refs, err := gitClient.GetRefs(ctx, git.GetRefsArgs{
		RepositoryId: string(r.ForgeRemoteID),
		Filter:       strings.NewString("heads/"),
	})
	if err != nil {
		return nil, err
	}

	branches := make([]string, len(refs))
	for i, ref := range refs {
		branches[i] = strings.TrimPrefix(*ref.Name, "refs/heads/")
	}

	return branches, nil
}

func (c *MSDevOps) BranchHead(ctx context.Context, u *model.User, r *model.Repo, branch string) (*model.Commit, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	refs, err := gitClient.GetRefs(ctx, git.GetRefsArgs{
		RepositoryId: string(r.ForgeRemoteID),
		Filter:       strings.NewString("heads/" + branch),
	})
	if err != nil || len(refs) == 0 {
		return nil, err
	}

	return &model.Commit{
		SHA: *refs[0].ObjectId,
	}, nil
}

func (c *MSDevOps) PullRequests(ctx context.Context, u *model.User, r *model.Repo, p *model.ListOptions) ([]*model.PullRequest, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	prs, err := gitClient.GetPullRequests(ctx, git.GetPullRequestsArgs{
		RepositoryId: string(r.ForgeRemoteID),
		SearchCriteria: &git.GitPullRequestSearchCriteria{
			Status: &git.PullRequestStatusValues.Active,
		},
	})
	if err != nil {
		return nil, err
	}

	result := make([]*model.PullRequest, len(prs))
	for i, pr := range prs {
		result[i] = &model.PullRequest{
			Index: model.ForgeRemoteID(fmt.Sprint(*pr.PullRequestId)),
			Title: *pr.Title,
		}
	}

	return result, nil
}

func (c *MSDevOps) Hook(ctx context.Context, r *http.Request) (*model.Repo, *model.Pipeline, error) {
	// TODO: Implement webhook handling
	return nil, nil, types.ErrNotImplemented
}

func (c *MSDevOps) OrgMembership(ctx context.Context, u *model.User, org string) (*model.OrgPerm, error) {
	return nil, types.ErrNotImplemented
}

func (c *MSDevOps) Org(ctx context.Context, u *model.User, org string) (*model.Org, error) {
	return nil, types.ErrNotImplemented
}

// Helper functions for converting between Azure DevOps and Woodpecker types

func convertRepo(repo *git.GitRepository) *model.Repo {
	return &model.Repo{
		ForgeRemoteID: model.ForgeRemoteID(*repo.Id),
		Owner:         *repo.Project.Name,
		Name:          *repo.Name,
		FullName:      fmt.Sprintf("%s/%s", *repo.Project.Name, *repo.Name),
		Clone:         *repo.RemoteUrl,
		CloneSSH:      repo.SshUrl,
		Branch:        "main", // Default to main as Azure DevOps doesn't expose default branch in API
		SCMKind:       model.RepoGit,
		ForgeURL:      *repo.WebUrl,
	}
}

func convertStatus(status model.StatusValue) git.GitStatusState {
	switch status {
	case model.StatusPending, model.StatusBlocked:
		return git.GitStatusStatePending
	case model.StatusRunning:
		return git.GitStatusStateNotSet
	case model.StatusSuccess:
		return git.GitStatusStateSucceeded
	case model.StatusFailure, model.StatusKilled, model.StatusError:
		return git.GitStatusStateFailed
	default:
		return git.GitStatusStateNotSet
	}
}
