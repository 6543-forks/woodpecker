// Copyright 2022 Woodpecker Authors
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

package model

// swagger:model cron_job
type CronJob struct {
	ID        int64  `json:"id"                  xorm:"pk autoincr"`
	Title     string `json:"title"               xorm:"UNIQUE(s) INDEX"`
	RepoID    int64  `json:"repo_id"             xorm:"repo_id UNIQUE(s) INDEX"`
	CreatorID int64  `json:"creator_id"           xorm:"creator_id INDEX"`
	NextExec  int64
	Schedule  string // @weekly, 3min, ...
	Created   int64  `json:"created_at"          xorm:"created NOT NULL DEFAULT 0"`
	Branch    string `json:"branch"`
}

// TableName return database table name for xorm
func (CronJob) TableName() string {
	return "cron_jobs"
}
