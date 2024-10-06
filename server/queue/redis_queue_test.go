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

package queue

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.woodpecker-ci.org/woodpecker/v2/server/model"
)

func TestRedisQueue(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_CON")
	if redisURL == "" {
		t.Skip("TEST_REDIS_CON environment variable not set, skipping Redis queue tests")
	}

	ctx := context.Background()
	q, err := NewRedisQueue(ctx, redisURL)
	require.NoError(t, err)

	redisQueue, ok := q.(*redisQueue)
	require.True(t, ok)

	// Clear the Redis database before running tests
	err = redisQueue.client.FlushDB(ctx).Err()
	require.NoError(t, err)

	t.Run("Push and Poll", func(t *testing.T) {
		task := &model.Task{ID: "1", Labels: map[string]string{"os": "linux"}}
		err := q.Push(ctx, task)
		require.NoError(t, err)

		polledTask, err := q.Poll(ctx, 1, func(t *model.Task) bool { return true })
		require.NoError(t, err)
		assert.Equal(t, task.ID, polledTask.ID)
	})

	t.Run("PushAtOnce", func(t *testing.T) {
		tasks := []*model.Task{
			{ID: "2", Labels: map[string]string{"os": "linux"}},
			{ID: "3", Labels: map[string]string{"os": "windows"}},
		}
		err := q.PushAtOnce(ctx, tasks)
		require.NoError(t, err)

		for i := 0; i < 2; i++ {
			_, err := q.Poll(ctx, 1, func(t *model.Task) bool { return true })
			require.NoError(t, err)
		}
	})

	t.Run("Extend", func(t *testing.T) {
		task := &model.Task{ID: "4", Labels: map[string]string{"os": "linux"}}
		err := q.Push(ctx, task)
		require.NoError(t, err)

		polledTask, err := q.Poll(ctx, 1, func(t *model.Task) bool { return true })
		require.NoError(t, err)

		err = q.Extend(ctx, 1, polledTask.ID)
		require.NoError(t, err)
	})

	t.Run("Done", func(t *testing.T) {
		task := &model.Task{ID: "5", Labels: map[string]string{"os": "linux"}}
		err := q.Push(ctx, task)
		require.NoError(t, err)

		polledTask, err := q.Poll(ctx, 1, func(t *model.Task) bool { return true })
		require.NoError(t, err)

		err = q.Done(ctx, polledTask.ID, model.StatusSuccess)
		require.NoError(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		task := &model.Task{ID: "6", Labels: map[string]string{"os": "linux"}}
		err := q.Push(ctx, task)
		require.NoError(t, err)

		polledTask, err := q.Poll(ctx, 1, func(t *model.Task) bool { return true })
		require.NoError(t, err)

		err = q.Error(ctx, polledTask.ID, assert.AnError)
		require.NoError(t, err)
	})

	t.Run("Info", func(t *testing.T) {
		task := &model.Task{ID: "7", Labels: map[string]string{"os": "linux"}}
		err := q.Push(ctx, task)
		require.NoError(t, err)

		info := q.Info(ctx)
		assert.Equal(t, 1, info.Stats.Pending)
	})

	t.Run("Pause and Resume", func(t *testing.T) {
		task := &model.Task{ID: "8", Labels: map[string]string{"os": "linux"}}
		err := q.Push(ctx, task)
		require.NoError(t, err)

		q.Pause()
		info := q.Info(ctx)
		assert.True(t, info.Paused)

		// Try to poll while paused
		done := make(chan struct{})
		go func() {
			_, err := q.Poll(ctx, 1, func(t *model.Task) bool { return true })
			require.NoError(t, err)
			close(done)
		}()

		select {
		case <-done:
			t.Fatal("Poll should not return while queue is paused")
		case <-time.After(time.Second):
			// Expected behavior
		}

		q.Resume()
		info = q.Info(ctx)
		assert.False(t, info.Paused)

		// Poll should now succeed
		select {
		case <-done:
			// Expected behavior
		case <-time.After(time.Second):
			t.Fatal("Poll should return after queue is resumed")
		}
	})

	t.Run("KickAgentWorkers", func(t *testing.T) {
		// Clear the queue before starting this test
		err = redisQueue.client.FlushDB(ctx).Err()
		require.NoError(t, err)

		task1 := &model.Task{ID: "9", Labels: map[string]string{"os": "linux"}}
		task2 := &model.Task{ID: "10", Labels: map[string]string{"os": "linux"}}
		err := q.PushAtOnce(ctx, []*model.Task{task1, task2})
		require.NoError(t, err)

		// Poll both tasks
		_, err = q.Poll(ctx, 1, func(t *model.Task) bool { return true })
		require.NoError(t, err)
		_, err = q.Poll(ctx, 1, func(t *model.Task) bool { return true })
		require.NoError(t, err)

		// Check initial state
		info := q.Info(ctx)
		assert.Equal(t, 0, info.Stats.Pending)
		assert.Equal(t, 2, info.Stats.Running)

		// Kick workers for agent 1
		q.KickAgentWorkers(1)

		// Wait a short time for the kick operation to complete
		time.Sleep(100 * time.Millisecond)

		// Check that both tasks are back in the pending queue
		info = q.Info(ctx)
		assert.Equal(t, 2, info.Stats.Pending, "Expected both tasks to be moved back to pending")
		assert.Equal(t, 0, info.Stats.Running, "Expected no tasks to be running")

		// Verify that the tasks can be polled again
		polledTask1, err := q.Poll(ctx, 2, func(t *model.Task) bool { return true })
		require.NoError(t, err)
		assert.NotEqual(t, int64(1), polledTask1.AgentID, "Task should not be assigned to the kicked agent")

		polledTask2, err := q.Poll(ctx, 2, func(t *model.Task) bool { return true })
		require.NoError(t, err)
		assert.NotEqual(t, int64(1), polledTask2.AgentID, "Task should not be assigned to the kicked agent")

		// Final check
		info = q.Info(ctx)
		assert.Equal(t, 0, info.Stats.Pending, "Expected no pending tasks after polling")
		assert.Equal(t, 2, info.Stats.Running, "Expected both tasks to be running")
	})
}

func TestRedisQueueNewFail(t *testing.T) {
	_, err := NewRedisQueue(context.Background(), "invalid://localhost:6379")
	assert.Error(t, err)
}
