package error

type Error struct {
	err string
}

func (err *Error) Error() string {
	return err.err
}

func New(text string) *Error {
	return &Error{err: text}
}
