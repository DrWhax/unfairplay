package fairplay

import "fmt"

var currentSINFRequiredRights = [...]string{
	"veID", "plat", "aver", "tran", "sing", "song", "tool", "medi", "mode",
}

const maximumCurrentSINFRightsBytes = 256

func currentSINFRightsPayloadGeometry(rights []byte) error {
	if len(rights) < 80 || len(rights) > maximumCurrentSINFRightsBytes || len(rights)%8 != 0 {
		return fmt.Errorf("current SINF rights have invalid geometry: %d bytes", len(rights))
	}
	return nil
}

// currentSINFRightsGeometry validates the canonical named prefix and returns
// the number of named bytes. The final eight bytes are opaque native state.
// Additional named rights are accepted only after the established prefix.
func currentSINFRightsGeometry(rights []byte) (int, error) {
	if err := currentSINFRightsPayloadGeometry(rights); err != nil {
		return 0, err
	}
	namedBytes := len(rights) - 8
	seen := make(map[string]bool, namedBytes/8)
	for index := 0; index < namedBytes/8; index++ {
		nameBytes := rights[index*8 : index*8+4]
		for _, value := range nameBytes {
			if value < 0x20 || value > 0x7e {
				return 0, fmt.Errorf("current SINF right %d has an invalid name", index)
			}
		}
		name := string(nameBytes)
		if seen[name] {
			return 0, fmt.Errorf("current SINF rights contain duplicate %q", name)
		}
		seen[name] = true
		if index < len(currentSINFRequiredRights) && name != currentSINFRequiredRights[index] {
			return 0, fmt.Errorf("current SINF right %d is %q, want %q", index, name, currentSINFRequiredRights[index])
		}
		if index == len(currentSINFRequiredRights) && name != "hi32" {
			return 0, fmt.Errorf("current SINF right %d is %q, want %q", index, name, "hi32")
		}
	}
	return namedBytes, nil
}
