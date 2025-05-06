package util

import (
	"errors"
	"strings"
)

// -----------------------------------------------------------------------------

type extendedError struct {
	message string
	err     error
}

// -----------------------------------------------------------------------------

// NewExtendedError creates a new error that wraps an error and includes the given message.
func NewExtendedError(err error, message string) error {
	return &extendedError{
		message: message,
		err:     err,
	}
}

// Error returns a string representation of the error.
func (w *extendedError) Error() string {
	sb := strings.Builder{}
	_, _ = sb.WriteString(w.message)
	for err := w.err; err != nil; {
		var childW *extendedError

		_, _ = sb.WriteString(" [err=")
		if errors.As(err, &childW) {
			_, _ = sb.WriteString(childW.message)
			err = childW.err
		} else {
			_, _ = sb.WriteString(err.Error())
			err = errors.Unwrap(err)
		}
		_, _ = sb.WriteString("]")
	}
	return sb.String()
}

// Unwrap returns the underlying error.
func (w *extendedError) Unwrap() error {
	return w.err
}
