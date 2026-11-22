// Copyright 2022 Woodpecker Authors
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

package datastore

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/xorm"

	"go.woodpecker-ci.org/woodpecker/v3/server/model"
)

func TestWorkflowLoad(t *testing.T) {
	store, closer := newTestStore(t, new(model.Step), new(model.Pipeline), new(model.Workflow))
	defer closer()

	wf := &model.Workflow{
		PipelineID: 1,
		PID:        1,
		Name:       "woodpecker",
		Children: []*model.Step{
			{
				UUID:       "ea6d4008-8ace-4f8a-ad03-53f1756465d9",
				PipelineID: 1,
				PID:        2,
				PPID:       1,
				State:      "success",
			},
			{
				UUID:       "2bf387f7-2913-4907-814c-c9ada88707c0",
				PipelineID: 1,
				PID:        3,
				PPID:       1,
				Name:       "build",
				State:      "success",
			},
		},
	}
	assert.NoError(t, store.WorkflowsCreate([]*model.Workflow{wf}))
	workflowGet, err := store.WorkflowLoad(1)
	assert.NoError(t, err)
	assert.EqualValues(t, 1, workflowGet.PipelineID)
	assert.Equal(t, 1, workflowGet.PID)
	assert.Len(t, workflowGet.Children, 0)
}

func TestWorkflowGetTree(t *testing.T) {
	store, closer := newTestStore(t, new(model.Step), new(model.Pipeline), new(model.Workflow))
	defer closer()

	wf := &model.Workflow{
		PipelineID: 1,
		PID:        1,
		Name:       "woodpecker",
		DependsOn:  []string{"lint"},
		Children: []*model.Step{
			{
				UUID:       "ea6d4008-8ace-4f8a-ad03-53f1756465d9",
				PipelineID: 1,
				PID:        2,
				PPID:       1,
				Name:       "test",
				State:      "success",
			},
			{
				UUID:       "2bf387f7-2913-4907-814c-c9ada88707c0",
				PipelineID: 1,
				PID:        3,
				PPID:       1,
				Name:       "build",
				DependsOn:  []string{"test"},
				State:      "success",
			},
		},
	}
	assert.NoError(t, store.WorkflowsCreate([]*model.Workflow{wf}))

	workflowsGet, err := store.WorkflowGetTree(&model.Pipeline{ID: 1})
	assert.NoError(t, err)
	assert.Len(t, workflowsGet, 1)
	workflowGet := workflowsGet[0]
	assert.Equal(t, "woodpecker", workflowGet.Name)
	assert.Equal(t, []string{"lint"}, workflowGet.DependsOn)
	assert.Len(t, workflowGet.Children, 2)
	assert.Equal(t, 2, workflowGet.Children[0].PID)
	assert.Equal(t, 3, workflowGet.Children[1].PID)
	assert.Equal(t, []string{"test"}, workflowGet.Children[1].DependsOn)
}

func TestWorkflowUpdate(t *testing.T) {
	store, closer := newTestStore(t, new(model.Step), new(model.Pipeline), new(model.Workflow))
	defer closer()

	wf := &model.Workflow{
		PipelineID: 1,
		PID:        1,
		Name:       "woodpecker",
		State:      "pending",
	}
	assert.NoError(t, store.WorkflowsCreate([]*model.Workflow{wf}))
	workflowGet, err := store.WorkflowLoad(1)
	assert.NoError(t, err)

	assert.Equal(t, model.StatusValue("pending"), workflowGet.State)

	wf.State = "success"

	assert.NoError(t, store.WorkflowUpdate(wf))
	workflowGet, err = store.WorkflowLoad(1)
	assert.NoError(t, err)
	assert.Equal(t, model.StatusValue("success"), workflowGet.State)
}

func TestWorkflowsReplaceRetriesSQLiteLocks(t *testing.T) {
	// Rollback journaling lets a reader block COMMIT after the writes succeed.
	dsn := "file:" + filepath.Join(t.TempDir(), "workflows.db") + "?_busy_timeout=0&_journal_mode=DELETE"
	engine, err := xorm.NewEngine("sqlite3", dsn)
	require.NoError(t, err)
	defer engine.Close()
	require.NoError(t, engine.Sync(new(model.Workflow), new(model.Step), new(model.LogEntry), new(model.AgentSnapshot)))

	s := storage{engine: engine}
	pipeline := &model.Pipeline{ID: 1}
	require.NoError(t, s.WorkflowsCreate([]*model.Workflow{{PipelineID: 1, PID: 1, Name: "old"}}))

	other, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer other.Close()
	holder, err := other.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer holder.Rollback() //nolint:errcheck
	// Keep a shared read lock while WorkflowsReplace writes and commits.
	var count int
	require.NoError(t, holder.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM workflows").Scan(&count))

	hook := &pipelineLockHook{releaseOn: "COMMIT", release: holder.Rollback}
	engine.AddHook(hook)
	err = s.WorkflowsReplace(pipeline, []*model.Workflow{{
		PipelineID: 1, PID: 1, Name: "new",
		Children: []*model.Step{{PipelineID: 1, PID: 2, PPID: 1, Name: "step"}},
	}})

	require.True(t, hook.released, "the first failed attempt must release the competing lock")
	require.ErrorContains(t, hook.commitErr, "database is locked", "the lock must occur at COMMIT")
	require.NoError(t, err, "replacing workflows must retry after a transient lock")
	require.Greater(t, hook.attempts, 1, "retry must start a fresh transaction")

	workflows, err := s.WorkflowGetTree(pipeline)
	require.NoError(t, err)
	require.Len(t, workflows, 1)
	assert.Equal(t, "new", workflows[0].Name)
	assert.Len(t, workflows[0].Children, 1)
}
