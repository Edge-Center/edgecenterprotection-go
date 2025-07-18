package edgecenterprotection_go

import (
	"errors"
	"fmt"
)

var (
	ErrMultipleResourcesWithTheSameName = errors.New("there are multiple resources with the same name")
	ErrResourceDoesntExist              = errors.New("resource doesn't exist")
)

// ArgError is an error that represents an error with an input to edgecloud. It
// identifies the argument and the cause (if possible).
type ArgError struct {
	arg    string
	reason string
}

var _ error = &ArgError{}

// NewArgError creates an InputError.
func NewArgError(arg, reason string) *ArgError {
	return &ArgError{
		arg:    arg,
		reason: reason,
	}
}

func (e *ArgError) Error() string {
	return fmt.Sprintf("%s is invalid because %s", e.arg, e.reason)
}
