package integrationtest

import (
	"fmt"
	"math/rand"
	"time"
)

func randomWithPrefix(name string) string {
	return fmt.Sprintf("%s-%d", name, rand.New(rand.NewSource(time.Now().UnixNano())).Int())
}
