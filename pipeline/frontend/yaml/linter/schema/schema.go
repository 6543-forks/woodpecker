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

package schema

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"codeberg.org/6543/go-yaml2json"
	"codeberg.org/6543/xyaml"
	json_schema "github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

//go:embed schema.json
var schemaDefinition []byte

// Lint lints an io.Reader against the Woodpecker `schema.json`.
func Lint(r io.Reader) ([]json_schema.ResultError, error) {
	schemaLoader := json_schema.NewBytesLoader(schemaDefinition)

	// read yaml config
	rBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to load yml file %w", err)
	}

	// resolve sequence merges
	yamlDoc := new(yaml.Node)
	if err := xyaml.Unmarshal(rBytes, yamlDoc); err != nil {
		return nil, fmt.Errorf("failed to parse yml file %w", err)
	}

	// convert to json
	jsonDoc, err := yaml2json.ConvertNode(yamlDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert yaml %w", err)
	}

	documentLoader := json_schema.NewBytesLoader(jsonDoc)
	result, err := json_schema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return nil, fmt.Errorf("validation failed %w", err)
	}

	if !result.Valid() {
		return result.Errors(), fmt.Errorf("config not valid")
	}

	return nil, nil
}

func LintString(s string) ([]json_schema.ResultError, error) {
	return Lint(bytes.NewBufferString(s))
}
