package hash

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"hash/crc32"
)

// StringKey returns a schema.SchemaSetFunc able to hash a string value
// from map accessed by k.
func StringKey(k string) schema.SchemaSetFunc {
	return func(v interface{}) int {
		m, ok := v.(map[string]interface{})
		if !ok {
			return 0
		}
		if v, ok := m[k].(string); ok {
			hash := int(crc32.ChecksumIEEE([]byte(v)))
			if hash >= 0 {
				return hash
			}
			if -hash >= 0 {
				return -hash
			}
			// v == MinInt
			return 0
		}
		return 0
	}
}
