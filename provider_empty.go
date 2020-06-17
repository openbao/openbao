package jwtauth

// EmptyProvider is used mainly for testing, until real providers are added
type EmptyProvider struct{}

func (e *EmptyProvider) Initialize(jc *jwtConfig) error {
	return nil
}

func (e *EmptyProvider) SensitiveKeys() []string {
	return []string{}
}
