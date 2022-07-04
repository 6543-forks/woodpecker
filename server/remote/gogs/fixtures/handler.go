// Copyright 2018 Drone.IO Inc.
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

package fixtures

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler returns an http.Handler that is capable of handling a variety of mock
// Bitbucket requests and returning mock responses.
func Handler() http.Handler {
	gin.SetMode(gin.TestMode)

	e := gin.New()
	e.GET("/api/v1/repos/:owner/:name", getRepo)
	e.GET("/api/v1/repos/:owner/:name/raw/:commit/:file", getRepoFile)
	e.POST("/api/v1/repos/:owner/:name/hooks", createRepoHook)
	e.GET("/api/v1/user/repos", getUserRepos)

	return e
}

func getRepo(c *gin.Context) {
	switch c.Param("name") {
	case "repo_not_found":
		c.String(http.StatusNotFound, "")
	default:
		c.String(http.StatusOK, repoPayload)
	}
}

func getRepoFile(c *gin.Context) {
	switch {
	case c.Param("file") == "file_not_found":
		c.String(http.StatusNotFound, "")
	case c.Param("commit") == "v1.0.0" || c.Param("commit") == "9ecad50":
		c.String(http.StatusOK, repoFilePayload)
	default:
		c.String(http.StatusNotFound, "")
	}
}

func createRepoHook(c *gin.Context) {
	in := struct {
		Type string `json:"type"`
		Conf struct {
			Type string `json:"content_type"`
			URL  string `json:"url"`
		} `json:"config"`
	}{}
	_ = c.BindJSON(&in)
	if in.Type != "gogs" ||
		in.Conf.Type != "json" ||
		in.Conf.URL != "http://localhost" {
		c.String(http.StatusInternalServerError, "")
		return
	}

	c.String(http.StatusOK, "{}")
}

func getUserRepos(c *gin.Context) {
	switch c.Request.Header.Get("Authorization") {
	case "token repos_not_found":
		c.String(http.StatusNotFound, "")
	default:
		c.String(http.StatusOK, userRepoPayload)
	}
}

const repoPayload = `
{
  "owner": {
    "username": "test_name",
    "email": "octocat@github.com",
    "avatar_url": "https:\/\/secure.gravatar.com\/avatar\/8c58a0be77ee441bb8f8595b7f1b4e87"
  },
  "full_name": "test_name\/repo_name",
  "private": true,
  "html_url": "http:\/\/localhost\/test_name\/repo_name",
  "clone_url": "http:\/\/localhost\/test_name\/repo_name.git",
  "permissions": {
    "admin": true,
    "push": true,
    "pull": true
  }
}
`

const repoFilePayload = `{ platform: linux/amd64 }`

const userRepoPayload = `
[
  {
    "owner": {
      "username": "test_name",
      "email": "octocat@github.com",
      "avatar_url": "https:\/\/secure.gravatar.com\/avatar\/8c58a0be77ee441bb8f8595b7f1b4e87"
    },
    "full_name": "test_name\/repo_name",
    "private": true,
    "html_url": "http:\/\/localhost\/test_name\/repo_name",
    "clone_url": "http:\/\/localhost\/test_name\/repo_name.git",
    "permissions": {
      "admin": true,
      "push": true,
      "pull": true
    }
  }
]
`
