package lint

import (
	"io"
	"strings"

	"github.com/woodpecker-ci/woodpecker/pipeline/schema"
)

func String(s string) ([]*Error, error) {
	sErrors, err := schema.Lint(strings.NewReader(s))
	if err != nil {
		return nil, err
	}
	return convertJsonSchemaErrors(sErrors), nil
}

func Reader(r io.ReadSeekCloser) ([]*Error, error) {
	sErrors, err := schema.Lint(r)
	if err != nil {
		return nil, err
	}
	return convertJsonSchemaErrors(sErrors), nil
}
