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
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"go.woodpecker-ci.org/woodpecker/v2/server/model"
	"go.woodpecker-ci.org/woodpecker/v2/shared/constant"
)

const (
	pendingQueueKey = "woodpecker:queue:pending"
	runningQueueKey = "woodpecker:queue:running"
	taskDataPrefix  = "woodpecker:task:"
	taskLockPrefix  = "woodpecker:lock:"
	pauseKey        = "woodpecker:queue:paused"
	taskExpiration  = 24 * time.Hour
	lockExpiration  = 10 * time.Second
	pollInterval    = 100 * time.Millisecond
)

type redisQueue struct {
	client    *redis.Client
	ctx       context.Context
	extension time.Duration
}

// NewRedisQueue creates a new Queue implementation backed by Redis.
func NewRedisQueue(ctx context.Context, redisURL string) (Queue, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opt)
	return &redisQueue{
		client:    client,
		ctx:       ctx,
		extension: constant.TaskTimeout,
	}, nil
}

func (q *redisQueue) Push(ctx context.Context, task *model.Task) error {
	return q.PushAtOnce(ctx, []*model.Task{task})
}

func (q *redisQueue) PushAtOnce(ctx context.Context, tasks []*model.Task) error {
	pipe := q.client.Pipeline()

	for _, task := range tasks {
		taskJSON, err := json.Marshal(task)
		if err != nil {
			return fmt.Errorf("failed to marshal task: %w", err)
		}

		pipe.Set(ctx, taskDataPrefix+task.ID, taskJSON, taskExpiration)
		pipe.RPush(ctx, pendingQueueKey, task.ID)
	}

	_, err := pipe.Exec(ctx)
	return err
}

func (q *redisQueue) Poll(ctx context.Context, agentID int64, f FilterFn) (*model.Task, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
			paused, err := q.client.Get(ctx, pauseKey).Bool()
			if err != nil && err != redis.Nil {
				return nil, fmt.Errorf("failed to check pause state: %w", err)
			}
			if paused {
				continue
			}

			taskID, err := q.client.LPop(ctx, pendingQueueKey).Result()
			if err == redis.Nil {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("failed to pop task from queue: %w", err)
			}

			task, err := q.getTask(ctx, taskID)
			if err != nil {
				return nil, err
			}

			if !f(task) {
				// Task doesn't match filter, put it back in the queue
				if err := q.Push(ctx, task); err != nil {
					return nil, fmt.Errorf("failed to push back unmatched task: %w", err)
				}
				continue
			}

			task.AgentID = agentID
			if err := q.lockTask(ctx, task); err != nil {
				return nil, fmt.Errorf("failed to lock task: %w", err)
			}

			return task, nil
		}
	}
}

func (q *redisQueue) Pause() {
	err := q.client.Set(q.ctx, pauseKey, true, 0).Err()
	if err != nil {
		log.Error().Err(err).Msg("failed to set pause state")
	}
}

func (q *redisQueue) Resume() {
	err := q.client.Del(q.ctx, pauseKey).Err()
	if err != nil {
		log.Error().Err(err).Msg("failed to clear pause state")
	}
}

func (q *redisQueue) Info(ctx context.Context) InfoT {
	info := InfoT{}

	pendingIDs, err := q.client.LRange(ctx, pendingQueueKey, 0, -1).Result()
	if err != nil {
		log.Error().Err(err).Msg("failed to get pending tasks")
	}

	runningIDs, err := q.client.LRange(ctx, runningQueueKey, 0, -1).Result()
	if err != nil {
		log.Error().Err(err).Msg("failed to get running tasks")
	}

	info.Stats.Pending = len(pendingIDs)
	info.Stats.Running = len(runningIDs)

	for _, id := range pendingIDs {
		task, err := q.getTask(ctx, id)
		if err != nil {
			log.Error().Err(err).Str("id", id).Msg("failed to get pending task")
			continue
		}
		info.Pending = append(info.Pending, task)
	}

	for _, id := range runningIDs {
		task, err := q.getTask(ctx, id)
		if err != nil {
			log.Error().Err(err).Str("id", id).Msg("failed to get running task")
			continue
		}
		info.Running = append(info.Running, task)
	}

	paused, err := q.client.Get(ctx, pauseKey).Bool()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("failed to get pause state")
	}
	info.Paused = paused

	return info
}

func (q *redisQueue) Extend(ctx context.Context, agentID int64, id string) error {
	return q.client.Expire(ctx, taskLockPrefix+id, q.extension).Err()
}

func (q *redisQueue) Done(ctx context.Context, id string, exitStatus model.StatusValue) error {
	pipe := q.client.Pipeline()
	pipe.Del(ctx, taskDataPrefix+id)
	pipe.Del(ctx, taskLockPrefix+id)
	pipe.LRem(ctx, runningQueueKey, 0, id)
	_, err := pipe.Exec(ctx)
	return err
}

func (q *redisQueue) Error(ctx context.Context, id string, err error) error {
	return q.Done(ctx, id, model.StatusError)
}

func (q *redisQueue) ErrorAtOnce(ctx context.Context, ids []string, err error) error {
	pipe := q.client.Pipeline()
	for _, id := range ids {
		pipe.Del(ctx, taskDataPrefix+id)
		pipe.Del(ctx, taskLockPrefix+id)
		pipe.LRem(ctx, runningQueueKey, 0, id)
	}
	_, pipeErr := pipe.Exec(ctx)
	return pipeErr
}

func (q *redisQueue) Evict(ctx context.Context, id string) error {
	return q.EvictAtOnce(ctx, []string{id})
}

func (q *redisQueue) EvictAtOnce(ctx context.Context, ids []string) error {
	pipe := q.client.Pipeline()
	for _, id := range ids {
		pipe.Del(ctx, taskDataPrefix+id)
		pipe.LRem(ctx, pendingQueueKey, 0, id)
		pipe.LRem(ctx, runningQueueKey, 0, id)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (q *redisQueue) Wait(ctx context.Context, id string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
			exists, err := q.client.Exists(ctx, taskLockPrefix+id).Result()
			if err != nil {
				return fmt.Errorf("failed to check task lock: %w", err)
			}
			if exists == 0 {
				return nil
			}
		}
	}
}

func (q *redisQueue) KickAgentWorkers(agentID int64) {
	ctx := q.ctx

	// Get all running tasks
	runningIDs, err := q.client.LRange(ctx, runningQueueKey, 0, -1).Result()
	if err != nil {
		log.Error().Err(err).Msg("failed to get running tasks")
		return
	}

	pipe := q.client.Pipeline()

	for _, id := range runningIDs {
		task, err := q.getTask(ctx, id)
		if err != nil {
			log.Error().Err(err).Str("id", id).Msg("failed to get running task")
			continue
		}

		if task.AgentID == agentID {
			// Remove task from running queue
			pipe.LRem(ctx, runningQueueKey, 0, id)

			// Add task back to pending queue
			pipe.RPush(ctx, pendingQueueKey, id)

			// Remove the lock
			pipe.Del(ctx, taskLockPrefix+id)

			// Update task data (reset AgentID)
			task.AgentID = 0
			taskJSON, err := json.Marshal(task)
			if err != nil {
				log.Error().Err(err).Str("id", id).Msg("failed to marshal task")
				continue
			}
			pipe.Set(ctx, taskDataPrefix+id, taskJSON, taskExpiration)
		}
	}

	// Execute all commands in the pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		log.Error().Err(err).Int64("agent_id", agentID).Msg("failed to kick agent workers")
	}
}

func (q *redisQueue) lockTask(ctx context.Context, task *model.Task) error {
	locked, err := q.client.SetNX(ctx, taskLockPrefix+task.ID, "locked", lockExpiration).Result()
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("task is already locked")
	}

	pipe := q.client.Pipeline()
	pipe.RPush(ctx, runningQueueKey, task.ID)
	taskJSON, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("failed to marshal task: %w", err)
	}
	pipe.Set(ctx, taskDataPrefix+task.ID, taskJSON, taskExpiration)
	_, err = pipe.Exec(ctx)
	return err
}

func (q *redisQueue) getTask(ctx context.Context, id string) (*model.Task, error) {
	taskJSON, err := q.client.Get(ctx, taskDataPrefix+id).Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get task data: %w", err)
	}

	var task model.Task
	if err := json.Unmarshal(taskJSON, &task); err != nil {
		return nil, fmt.Errorf("failed to unmarshal task: %w", err)
	}

	return &task, nil
}
