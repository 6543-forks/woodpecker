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
	"errors"
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

var ErrGotNilButNoErr = errors.New("client returned nil pointer instead of slice but did not respond with an error")

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
	connData, err := coreClient.GetConnectedServices(ctx, core.GetConnectedServicesArgs{})
	if err != nil {
		return "", err
	}
	if connData == nil {
		return "", ErrGotNilButNoErr
	}
	if len(*connData) == 0 {
		return "", fmt.Errorf("expect at least one connection data entry")
	}

	connDatas := *connData
	connDataEntry := connDatas[0]
	return *connDataEntry.AuthenticatedBy.DisplayName, nil
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

	repo, err := gitClient.GetRepository(ctx, git.GetRepositoryArgs{
		RepositoryId: toRepoID(remoteID),
		Project:      &owner,
	})
	if err != nil {
		return nil, err
	}
	if repo == nil {
		return nil, ErrGotNilButNoErr
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
		return nil, ErrGotNilButNoErr
	}

	result := make([]*model.Repo, 0, len(*repos))
	for i, repo := range *repos {
		result[i] = convertRepo(&repo)
	}

	return result, nil
}

func (c *MSDevOps) File(ctx context.Context, u *model.User, r *model.Repo, p *model.Pipeline, f string) ([]byte, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	item, err := gitClient.GetItem(ctx, git.GetItemArgs{
		RepositoryId: toRepoID(r.ForgeRemoteID),
		Path:         &f,
		VersionDescriptor: &git.GitVersionDescriptor{
			Version: &p.Ref,
		},
	})
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, ErrGotNilButNoErr
	}

	if *item.GitObjectType != git.GitObjectTypeValues.Blob {
		return nil, fmt.Errorf("got %s", *item.GitObjectType)
	}

	return []byte(*item.Content), nil
}

func (c *MSDevOps) Dir(ctx context.Context, u *model.User, r *model.Repo, p *model.Pipeline, f string) ([]*forge_types.FileMeta, error) {
	return nil, types.ErrNotImplemented
}

func (c *MSDevOps) Status(ctx context.Context, u *model.User, r *model.Repo, p *model.Pipeline, w *model.Workflow) error {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return err
	}

	state := convertStatus(w.State)
	targetURL := common.GetPipelineStatusURL(r, p, w)
	description := common.GetPipelineStatusDescription(w.State)
	context := common.GetPipelineStatusContext(r, p, w)
	contextGenre := "woodpecker"

	_, err = gitClient.CreateCommitStatus(ctx, git.CreateCommitStatusArgs{
		Project:      &r.Owner,
		RepositoryId: toRepoID(r.ForgeRemoteID),
		CommitId:     &p.Commit,
		GitCommitStatusToCreate: &git.GitStatus{
			State:       &state,
			Description: &description,
			TargetUrl:   &targetURL,
			Context: &git.GitStatusContext{
				Genre: &contextGenre,
				Name:  &context,
			},
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
	if p != nil && !p.All && p.Page > 1 {
		return nil, types.ErrNotImplemented
	}

	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	branchStats, err := gitClient.GetBranches(ctx, git.GetBranchesArgs{
		RepositoryId: toRepoID(r.ForgeRemoteID),
	})
	if err != nil {
		return nil, err
	}
	if branchStats == nil {
		return nil, ErrGotNilButNoErr
	}

	branches := make([]string, 0, len(*branchStats))
	for i, branch := range *branchStats {
		branches[i] = strings.TrimPrefix(*branch.Name, "refs/heads/")
	}

	return branches, nil
}

func (c *MSDevOps) BranchHead(ctx context.Context, u *model.User, r *model.Repo, branch string) (*model.Commit, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	filter := fmt.Sprintf("heads/%s", branch)

	refs, err := gitClient.GetRefs(ctx, git.GetRefsArgs{
		RepositoryId: toRepoID(r.ForgeRemoteID),
		Filter:       &filter,
	})
	if err != nil || refs == nil || len(refs.Value) == 0 {
		return nil, err
	}

	if refs.Value[0].ObjectId == nil {
		return nil, ErrGotNilButNoErr
	}

	return &model.Commit{
		SHA: *refs.Value[0].ObjectId,
	}, nil
}

func (c *MSDevOps) PullRequests(ctx context.Context, u *model.User, r *model.Repo, p *model.ListOptions) ([]*model.PullRequest, error) {
	conn := azuredevops.NewPatConnection(c.url, u.Token)
	gitClient, err := git.NewClient(ctx, conn)
	if err != nil {
		return nil, err
	}

	opts := git.GetPullRequestsArgs{
		RepositoryId: toRepoID(r.ForgeRemoteID),
		SearchCriteria: &git.GitPullRequestSearchCriteria{
			Status: &git.PullRequestStatusValues.Active,
		},
	}

	if p != nil && !p.All {
		skip := p.Page * p.PerPage
		opts.Skip = &skip
		opts.Top = &p.PerPage
	}

	prs, err := gitClient.GetPullRequests(ctx, opts)
	if err != nil {
		return nil, err
	}
	if prs == nil {
		return nil, ErrGotNilButNoErr
	}

	result := make([]*model.PullRequest, len(*prs))
	for i, pr := range *prs {
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
		ForgeRemoteID: model.ForgeRemoteID(repo.Id.String()),
		Owner:         *repo.Project.Name,
		Name:          *repo.Name,
		FullName:      fmt.Sprintf("%s/%s", *repo.Project.Name, *repo.Name),
		Clone:         *repo.RemoteUrl,
		CloneSSH:      *repo.SshUrl,
		Branch:        *repo.DefaultBranch,
		SCMKind:       model.RepoGit,
		ForgeURL:      *repo.WebUrl,
	}
}

func convertStatus(status model.StatusValue) git.GitStatusState {
	switch status {
	case model.StatusPending, model.StatusBlocked:
		return git.GitStatusStateValues.Pending
	case model.StatusRunning:
		return git.GitStatusStateValues.NotSet
	case model.StatusSuccess:
		return git.GitStatusStateValues.Succeeded
	case model.StatusFailure, model.StatusKilled:
		return git.GitStatusStateValues.Failed
	case model.StatusError:
		return git.GitStatusStateValues.Error
	default:
		return git.GitStatusStateValues.NotApplicable
	}
}

func toRepoID(frID model.ForgeRemoteID) *string {
	sfrID := string(frID)
	return &sfrID
}
