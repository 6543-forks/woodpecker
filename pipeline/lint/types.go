package lint

import (
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

type ErrorLevel uint

type Error struct {
	Line    int64
	Char    int64 // start position in line (optional)
	Msg     string
	Warning bool
	err     error
}

func (e Error) Error() string {
	level := "Error"
	if e.Warning {
		level = "Warn"
	}
	if e.err != nil {
		return fmt.Sprintf("[%s] L%d:C%d %v", level, e.Line, e.Char, e.err)
	}
	return fmt.Sprintf("[%s] L%d:C%d %s", level, e.Line, e.Char, e.Msg)
}

func convertJsonSchemaErrors(errs []gojsonschema.ResultError) []*Error {
	errors := make([]*Error, 0, len(errs))
	for i := range errs {
		errors[i] = &Error{
			Msg: fmt.Sprintln("In", errs[i].Field()+":", errs[i].Description()),
		}
	}
	return errors
}
