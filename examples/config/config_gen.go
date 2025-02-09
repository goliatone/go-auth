//go:generate app-config -input ./app.json -output ./config_structs.go -pkg config --struct BaseConfig -extension overrides.yml
//go:generate config-getters -input ./config_structs.go -output config_getters.go
package config

import (
	"fmt"
	"time"
)

func (a BaseConfig) Validate() error {
	return nil
}

func (p Persistence) GetPingTimeout() time.Duration {
	dur, err := time.ParseDuration(p.PingTimeoutExpression)
	if err != nil {
		panic(
			fmt.Sprintf("unable to parse time: expr %s", p.PingTimeoutExpression),
		)
	}
	return dur
}
