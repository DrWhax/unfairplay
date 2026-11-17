package fairplay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// ModelDumpField is one contiguous region of an enrollment model file.
type ModelDumpField struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Bytes  int    `json:"bytes"`
	Hex    string `json:"hex"`
}

// ModelDumpTable is one 256-byte substitution table.
type ModelDumpTable struct {
	Index    int    `json:"index"`
	Offset   int    `json:"offset"`
	Identity bool   `json:"identity"`
	Hex      string `json:"hex"`
}

// ModelDump is the complete decoded content of an enrollment model file,
// including its secret key material.
type ModelDump struct {
	Path                string           `json:"path"`
	SHA256              string           `json:"sha256"`
	Bytes               int              `json:"bytes"`
	Magic               string           `json:"magic"`
	Version             uint32           `json:"version"`
	DeclaredSize        uint32           `json:"declared_size"`
	ModelIdentity       string           `json:"model_identity"`
	Selector            *SINFSelector    `json:"selector,omitempty"`
	SelectorID          string           `json:"selector_id,omitempty"`
	SourceOffset        *int32           `json:"source_offset,omitempty"`
	SourceBytes         *uint32          `json:"source_bytes,omitempty"`
	FinalXOR            *byte            `json:"final_xor,omitempty"`
	Key                 string           `json:"key"`
	Whitening           string           `json:"whitening,omitempty"`
	InputDecodeTables   []ModelDumpTable `json:"input_decode_tables,omitempty"`
	OutputEncodeTables  []ModelDumpTable `json:"output_encode_tables,omitempty"`
	OutputMask          string           `json:"output_mask,omitempty"`
	PostDecodeTables    []ModelDumpTable `json:"post_decode_tables,omitempty"`
	Layout              []ModelDumpField `json:"layout"`
	UnaccountedTrailing int              `json:"unaccounted_trailing_bytes"`
	Raw                 string           `json:"raw,omitempty"`
}

// DumpEnrollmentModel validates the model exactly as decryption does and
// returns every field. The result contains the enrollment's secret key.
func DumpEnrollmentModel(path string, includeRaw bool) (ModelDump, error) {
	pack, err := readEnrollmentModel(path)
	if err != nil {
		return ModelDump{}, err
	}
	defer clear(pack)
	model, err := parseCurrentSINFModel(pack)
	if err != nil {
		return ModelDump{}, err
	}
	defer clearCurrentSINFModel(&model)

	digest := sha256.Sum256(pack)
	dump := ModelDump{
		Path:          path,
		SHA256:        hex.EncodeToString(digest[:]),
		Bytes:         len(pack),
		Magic:         strings.TrimRight(string(pack[:8]), "\x00"),
		Version:       model.version,
		DeclaredSize:  binary.LittleEndian.Uint32(pack[12:16]),
		ModelIdentity: hex.EncodeToString(model.modelIdentity[:]),
		Key:           hex.EncodeToString(model.key[:]),
	}
	layout := []ModelDumpField{}
	cursor := 0
	add := func(name string, n int) []byte {
		region := pack[cursor : cursor+n]
		layout = append(layout, ModelDumpField{Name: name, Offset: cursor, Bytes: n, Hex: hex.EncodeToString(region)})
		cursor += n
		return region
	}
	addTables := func(name string, n int) []ModelDumpTable {
		start := cursor
		region := add(name, n*256)
		tables := make([]ModelDumpTable, n)
		for i := range tables {
			row := region[i*256 : (i+1)*256]
			identity := true
			for v, b := range row {
				if int(b) != v {
					identity = false
					break
				}
			}
			tables[i] = ModelDumpTable{Index: i, Offset: start + i*256, Identity: identity, Hex: hex.EncodeToString(row)}
		}
		return tables
	}

	add("magic", 8)
	add("version", 4)
	add("declared_size", 4)
	add("model_identity", 32)
	if model.hasSelector {
		selector := model.selector
		dump.Selector = &selector
		dump.SelectorID = selector.Identifier()
		add("selector_user", 4)
		add("selector_key", 4)
	}
	if model.version == 3 {
		offset, size, xor := model.sourceOffset, model.sourceBytes, model.finalXOR
		dump.SourceOffset, dump.SourceBytes, dump.FinalXOR = &offset, &size, &xor
		add("source_offset", 4)
		add("source_bytes", 4)
		add("final_xor_and_padding", 4)
	}
	add("key", 16)
	if model.version < 3 {
		dump.Whitening = hex.EncodeToString(model.whitening[:])
		add("whitening", 16)
		dump.InputDecodeTables = addTables("input_decode_tables", 16)
	} else {
		dump.OutputEncodeTables = addTables("output_encode_tables", 16)
		dump.OutputMask = hex.EncodeToString(add("output_mask", currentSINFV3SourceBytes))
		dump.PostDecodeTables = addTables("post_decode_tables", 16)
	}
	dump.Layout = layout
	dump.UnaccountedTrailing = len(pack) - cursor
	if includeRaw {
		dump.Raw = hex.EncodeToString(pack)
	}
	return dump, nil
}

func clearCurrentSINFModel(model *currentSINFModel) {
	clear(model.key[:])
	clear(model.whitening[:])
	clear(model.inputDecode[:])
	clear(model.outputEncode[:])
	clear(model.outputMask[:])
	clear(model.postDecode[:])
}

// WriteModelDumpText writes a human-readable rendering of dump.
func WriteModelDumpText(w io.Writer, dump ModelDump) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Path:            %s\n", dump.Path)
	fmt.Fprintf(&b, "SHA-256:         %s\n", dump.SHA256)
	fmt.Fprintf(&b, "Size:            %d bytes (declared %d)\n", dump.Bytes, dump.DeclaredSize)
	fmt.Fprintf(&b, "Magic:           %s\n", dump.Magic)
	fmt.Fprintf(&b, "Version:         %d\n", dump.Version)
	fmt.Fprintf(&b, "Model identity:  %s\n", dump.ModelIdentity)
	if dump.Selector != nil {
		fmt.Fprintf(&b, "Selector:        user=%d (0x%08x) key=%d (0x%08x) id=%s\n",
			dump.Selector.User, dump.Selector.User, dump.Selector.Key, dump.Selector.Key, dump.SelectorID)
	}
	if dump.SourceOffset != nil {
		fmt.Fprintf(&b, "Source offset:   %d\n", *dump.SourceOffset)
		fmt.Fprintf(&b, "Source bytes:    %d\n", *dump.SourceBytes)
		fmt.Fprintf(&b, "Final XOR:       0x%02x\n", *dump.FinalXOR)
	}
	fmt.Fprintf(&b, "Key:             %s\n", dump.Key)
	if dump.Whitening != "" {
		fmt.Fprintf(&b, "Whitening:       %s\n", dump.Whitening)
	}
	writeTables := func(title string, tables []ModelDumpTable) {
		if len(tables) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, t := range tables {
			note := ""
			if t.Identity {
				note = " (identity)"
			}
			fmt.Fprintf(&b, "  [%2d] @0x%04x%s\n", t.Index, t.Offset, note)
			writeHexBlock(&b, t.Hex, "       ")
		}
	}
	writeTables("Input decode tables", dump.InputDecodeTables)
	writeTables("Output encode tables", dump.OutputEncodeTables)
	if dump.OutputMask != "" {
		fmt.Fprintf(&b, "\nOutput mask (%d bytes):\n", len(dump.OutputMask)/2)
		writeHexBlock(&b, dump.OutputMask, "       ")
	}
	writeTables("Post-decode tables", dump.PostDecodeTables)
	fmt.Fprintf(&b, "\nLayout:\n")
	for _, f := range dump.Layout {
		fmt.Fprintf(&b, "  0x%04x  %5d  %s\n", f.Offset, f.Bytes, f.Name)
	}
	if dump.UnaccountedTrailing != 0 {
		fmt.Fprintf(&b, "  WARNING: %d trailing bytes not covered by the layout\n", dump.UnaccountedTrailing)
	}
	if dump.Raw != "" {
		fmt.Fprintf(&b, "\nRaw file:\n")
		writeHexBlock(&b, dump.Raw, "  ")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeHexBlock(b *strings.Builder, hexString, indent string) {
	const lineBytes = 32
	for i := 0; i < len(hexString); i += lineBytes * 2 {
		end := min(i+lineBytes*2, len(hexString))
		line := hexString[i:end]
		b.WriteString(indent)
		for j := 0; j < len(line); j += 2 {
			if j != 0 {
				b.WriteByte(' ')
			}
			b.WriteString(line[j : j+2])
		}
		b.WriteByte('\n')
	}
}
