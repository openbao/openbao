package upgrade

import (
	"fmt"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testhelpers/upgrade"
)

func TestUpgrade_Scenarios(t *testing.T) {
	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("only running docker test when $BAO_BINARY present")
	}

	scenarios, err := upgrade.LoadScenariosFromDir("scenarios")
	if err != nil {
		t.Fatalf("failed to load scenarios: %v", err)
	}

	// TODO (P5): replace dummy loop
	for _, scenario := range scenarios {
		fmt.Printf("run scenario: %s\n", scenario.Name)
	}
}
