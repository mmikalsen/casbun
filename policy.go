package casbun

import (
	"fmt"

	"github.com/uptrace/bun"
)

// CasbinPolicy defines the storage format following the definition below:
// https://casbin.org/docs/policy-storage#database-storage-format
type CasbinPolicy struct {
	bun.BaseModel `bun:"casbin_policies,alias:cp"`
	ID            int64  `bun:"id,pk,autoincrement"`
	PType         string `bun:"ptype,type:varchar(100),notnull"`
	V0            string `bun:"v0,type:varchar(100)"`
	V1            string `bun:"v1,type:varchar(100)"`
	V2            string `bun:"v2,type:varchar(100)"`
	V3            string `bun:"v3,type:varchar(100)"`
	V4            string `bun:"v4,type:varchar(100)"`
	V5            string `bun:"v5,type:varchar(100)"`
}

func (c CasbinPolicy) toSlice() []string {
	fields := []string{c.PType, c.V0, c.V1, c.V2, c.V3, c.V4, c.V5}
	return nonEmptyFields(fields)
}

func (c CasbinPolicy) filterValues() []string {
	fields := []string{c.V0, c.V1, c.V2, c.V3, c.V4, c.V5}
	return nonEmptyFields(fields)
}

func (c CasbinPolicy) filterValuesWithKey() map[string]string {
	values := make(map[string]string)
	for i, v := range []string{c.V0, c.V1, c.V2, c.V3, c.V4, c.V5} {
		if v != "" {
			values[fmt.Sprintf("v%d", i)] = v
		}
	}
	return values
}

func newCasbinPolicy(ptype string, rule []string) CasbinPolicy {
	c := CasbinPolicy{PType: ptype}
	for i := 0; i < len(rule) && i < 6; i++ {
		switch i {
		case 0:
			c.V0 = rule[i]
		case 1:
			c.V1 = rule[i]
		case 2:
			c.V2 = rule[i]
		case 3:
			c.V3 = rule[i]
		case 4:
			c.V4 = rule[i]
		case 5:
			c.V5 = rule[i]
		}
	}
	return c
}

func nonEmptyFields(fields []string) []string {
	result := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			result = append(result, f)
		}
	}
	return result
}
