package fairshare

import "fmt"

type SimpleJob func()

func (s SimpleJob) Execute() error {
	s()
	return nil
}

func (s SimpleJob) OnFailure(err error) {
	panic(fmt.Sprintf("SimpleJob can't fail, but it did: %v", err))
}

var _ Job = SimpleJob(nil)
