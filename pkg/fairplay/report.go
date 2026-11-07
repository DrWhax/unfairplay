package fairplay

type imageReport struct {
	Member                       string               `json:"member"`
	SINFMember                   string               `json:"sinf_member"`
	SUPFMember                   string               `json:"supf_member"`
	Architecture                 string               `json:"architecture"`
	CPUType                      uint32               `json:"cpu_type"`
	CPUSubtype                   uint32               `json:"cpu_subtype"`
	SliceOffset                  uint64               `json:"slice_offset"`
	SliceSize                    uint64               `json:"slice_size"`
	EncryptedSHA256              string               `json:"encrypted_sha256"`
	DecryptedSHA256              string               `json:"decrypted_sha256"`
	CryptOffset                  uint32               `json:"cryptoff"`
	CryptSize                    uint32               `json:"cryptsize"`
	Pages                        int                  `json:"pages"`
	FirstPlaintextPageSHA256     string               `json:"first_plaintext_page_sha256"`
	PlaintextValidation          string               `json:"plaintext_validation"`
	PreEncryptionCodeDirectories []codeDirectoryAudit `json:"pre_encryption_code_directories"`
	OrderedPageKeysSHA256        string               `json:"ordered_page_keys_sha256"`
	AppMaskSHA256                string               `json:"app_mask_sha256"`
	CodeDirectories              []codeDirectoryAudit `json:"code_directories"`
	CryptIDBefore                uint32               `json:"cryptid_before"`
	CryptIDAfter                 uint32               `json:"cryptid_after"`
	ExactMutationScope           bool                 `json:"exact_mutation_scope"`
}

type reportFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type decryptionReport struct {
	Schema            string          `json:"schema"`
	ModelBuild        string          `json:"model_build"`
	Input             reportFile      `json:"input"`
	Output            reportFile      `json:"output"`
	Provider          string          `json:"provider"`
	Oracle            map[string]any  `json:"oracle"`
	Licenses          []licenseReport `json:"licenses,omitempty"`
	EncryptedImages   int             `json:"encrypted_image_count"`
	DecryptedPages    int             `json:"decrypted_page_count"`
	Images            []*imageReport  `json:"images"`
	Complete          bool            `json:"complete"`
	PlaintextVerified bool            `json:"plaintext_verified"`
	SignatureVerified bool            `json:"signature_verified"`
	// Present only when --strip-account-data was requested.
	AccountData *accountDataReport `json:"account_data,omitempty"`
	Warnings    []string           `json:"warnings"`
}
