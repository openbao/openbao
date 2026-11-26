package upgrade

type UpgradeMode string

const (
	UpgradeModeInPlace UpgradeMode = "in-place"
	UpgradeModeRolling UpgradeMode = "rolling"
)

type ScenarioConfig struct {
	Name        string      `yaml:"name"`
	Nodes       int         `yaml:"nodes"`
	Storage     string      `yaml:"storage"`
	Seal        string      `yaml:"seal"`
	UpgradeMode UpgradeMode `yaml:"upgrade_mode"`
	Before      []string    `yaml:"before"`
	AfterNode   []string    `yaml:"after_node"`
	After       []string    `yaml:"after"`
}

// TODO (P5) implement Check Type instead of strings for [Before, AfterNode, After]
