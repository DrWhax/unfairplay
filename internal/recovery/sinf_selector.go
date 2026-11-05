package recovery

import (
	"encoding/binary"
	"fmt"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

// validatedSINF binds the selector and unique private payload to the same
// fully validated schi. Recovery intentionally rejects duplicate priv atoms,
// even though the public selector parser does not interpret private payloads.
type validatedSINF struct {
	selector fairplay.SINFSelector
	private  []byte
}

func parseRecoverySINF(blob []byte) (validatedSINF, error) {
	selector, err := fairplay.ParseSINFSelector(blob)
	if err != nil {
		return validatedSINF{}, err
	}
	// ParseSINFSelector has already validated the entire root, children, and
	// schi atom lists, including bounds and uniqueness of the schi.
	var schiStart, schiEnd int
	for cursor := 8; cursor < len(blob); {
		end := cursor + int(binary.BigEndian.Uint32(blob[cursor:cursor+4]))
		if string(blob[cursor+4:cursor+8]) == "schi" {
			schiStart, schiEnd = cursor+8, end
		}
		cursor = end
	}
	var private []byte
	count := 0
	for cursor := schiStart; cursor < schiEnd; {
		end := cursor + int(binary.BigEndian.Uint32(blob[cursor:cursor+4]))
		if string(blob[cursor+4:cursor+8]) == "priv" {
			private = blob[cursor+8 : end]
			count++
		}
		cursor = end
	}
	if count != 1 {
		return validatedSINF{}, fmt.Errorf("SINF requires one %q atom, found %d", "priv", count)
	}
	return validatedSINF{selector: selector, private: private}, nil
}
