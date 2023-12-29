// Copyright 2023 Woodpecker Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compiler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	backend_types "go.woodpecker-ci.org/woodpecker/v2/pipeline/backend/types"
)

func TestConvertDAGToStages(t *testing.T) {
	steps := map[string]*dagCompilerStep{
		"step1": {
			step:      &backend_types.Step{},
			dependsOn: []string{"step3"},
		},
		"step2": {
			step:      &backend_types.Step{},
			dependsOn: []string{"step1"},
		},
		"step3": {
			step:      &backend_types.Step{},
			dependsOn: []string{"step2"},
		},
	}
	_, err := convertDAGToStages(steps, "")
	assert.ErrorIs(t, err, &ErrStepDependencyCycle{})

	steps = map[string]*dagCompilerStep{
		"step1": {
			step:      &backend_types.Step{},
			dependsOn: []string{"step2"},
		},
		"step2": {
			step: &backend_types.Step{},
		},
	}
	_, err = convertDAGToStages(steps, "")
	assert.NoError(t, err)

	steps = map[string]*dagCompilerStep{
		"a": {
			step: &backend_types.Step{},
		},
		"b": {
			step:      &backend_types.Step{},
			dependsOn: []string{"a"},
		},
		"c": {
			step:      &backend_types.Step{},
			dependsOn: []string{"a"},
		},
		"d": {
			step:      &backend_types.Step{},
			dependsOn: []string{"b", "c"},
		},
	}
	_, err = convertDAGToStages(steps, "")
	assert.NoError(t, err)

	steps = map[string]*dagCompilerStep{
		"step1": {
			step:      &backend_types.Step{},
			dependsOn: []string{"not-existing-step"},
		},
	}
	_, err = convertDAGToStages(steps, "")
	assert.ErrorIs(t, err, &ErrStepMissingDependency{})

	steps = map[string]*dagCompilerStep{
		"echo env": {
			position:  0,
			name:      "echo env",
			group:     "",
			dependsOn: []string{""},
			step: &backend_types.Step{
				Name:  "test_step_0",
				UUID:  "01HJDPEW6R7J0JBE3F1T7Q0TYX",
				Type:  "commands",
				Alias: "echo env",
				Image: "bash",
			},
		},
		"echo 1": {
			position:  1,
			name:      "echo 1",
			group:     "",
			dependsOn: []string{"echo env", "echo 2"},
			step: &backend_types.Step{
				Name:  "test_step_1",
				UUID:  "01HJDPF770QGRZER8RF79XVS4M",
				Type:  "commands",
				Alias: "echo 1",
				Image: "bash",
			},
		},
		"echo 2": {
			position: 2,
			name:     "echo 2",
			group:    "",
			step: &backend_types.Step{
				Name:  "test_step_2",
				UUID:  "01HJDPFF5RMEYZW0YTGR1Y1ZR0",
				Type:  "commands",
				Alias: "echo 2",
				Image: "bash",
			},
		},
	}
	stages, err := convertDAGToStages(steps, "test")
	assert.NoError(t, err)
	assert.EqualValues(t, []*backend_types.Stage{{
		Name:  "test_stage_0",
		Alias: "test_stage_0",
		Steps: []*backend_types.Step{{
			Name:  "test_step_0",
			UUID:  "01HJDPEW6R7J0JBE3F1T7Q0TYX",
			Type:  "commands",
			Alias: "echo env",
			Image: "bash",
		}, {
			Name:  "test_step_2",
			UUID:  "01HJDPFF5RMEYZW0YTGR1Y1ZR0",
			Type:  "commands",
			Alias: "echo 2",
			Image: "bash",
		}},
	}, {
		Name:  "test_stage_1",
		Alias: "test_stage_1",
		Steps: []*backend_types.Step{{
			Name:  "test_step_1",
			UUID:  "01HJDPF770QGRZER8RF79XVS4M",
			Type:  "commands",
			Alias: "echo 1",
			Image: "bash",
		}},
	}}, stages)
}
