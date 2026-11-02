# Build-independent recovery plan

These are historical upstream research notes. See [README.md](README.md) for
the supported implementation and [QA.md](QA.md) for validation requirements.

## Goal

FairPlay enrollment must use one shared Go implementation. A macOS build must
not need translated assembly, a flattened CFG, handler addresses, register
scripts, or hard-coded stack offsets.

Different `fairplayd` binaries are treated as differently obfuscated versions
of the same algorithm unless dataflow evidence proves a real semantic change.

The final flow should be:

```text
SIDB + SINF + hardware identity
        -> typed Go enrollment algorithms
        -> portable enrollment model
        -> IPA decryption
```

## Design rules

- Algorithms accept typed values, slices, tables, and state structures.
- Algorithms do not accept instruction addresses or emulated ARM registers.
- Stage inputs are found by validated file/object structure, not build offsets.
- Build hashes are evidence labels, not algorithm selectors.
- A genuine changing table may be data. Changing CFGs, MBA constants,
  registers, selectors, and handler addresses are obfuscation noise.
- Unsupported input geometry fails closed.
- Native binaries, IDA, Binary Ninja, Python, and compact interpreters are
  research oracles only. They are not runtime dependencies.
- A new build must not require another generated CFG.

## Typed stage contracts

The intended stage boundary is:

```text
Account input
  SIDB records, hardware identity, installed SINF metadata

Bootstrap
  typed big-integer, SHA-1, table, and byte transformations

Selection
  validated modulus-sized source -> selected 16-byte state and frame

SIDB validation
  selected frame -> enrollment-bound SIDB decoder key
  SIDB container + decoder key -> decoded registry

SINF validation
  decoded SIDB registry + personalized SINF -> one tagged route and precursor

Model output
  precursor -> current SINF key/tables -> portable enrollment model
```

Every selection stage is deterministic. Authentication validates the selected
state, root and tagged route; it never authorizes trying another candidate.

## Current status

| Area | Status |
| --- | --- |
| Outer transform | Typed Go consumes the SIDB codec and hardware identity, using the stateful exit predicate to locate the payload. |
| Digest, pair, tail, writer | Typed Go algorithms are recovered and differential-tested. |
| Account entry | Replaced by structural X.509 parsing and pinned-CA SUPF authentication. The legacy account-entry CFG has been removed. |
| Bootstrap | Replaced by one typed semantic outer profile plus SIDB/hardware runtime fields. The legacy bootstrap CFG has been removed. |
| Selection | One modulus-sized source projection feeds the selected slot and typed state/key transforms. Authentication never retries another slot. |
| Enrollment frame | The frame and SIDB-key producer compose to standard AES-128 with fixed input whitening. Independent models are test-only. |
| SIDB | Codec termination determines the payload boundary. Variable-length bodies are decoded in typed Go at one hardware-derived root cursor. |
| SINF | Portable AES/model decoding exists. Native-tree payload-to-`valu` arithmetic, the account-derived class key, AES class join, deterministic tagged-route selection, and complete personalized-SINF authentication are typed Go. The native selector, candidate scan, SINF-entry CFG, and stack-offset material adapter have been removed. |
| SUPF | Variant-3 and variant-5 envelopes, architecture/page-key geometry, leaf certificates, and signed prefixes are parsed and authenticated in typed Go. Production pins the Apple FairPlay CA public key and no longer trusts a self-signed license certificate. |
| Build portability | Container size does not select the codec boundary. The recovered layout is reported and pinned by private QA; untested layouts fail closed. |

The legacy `executionProfile`, generated account/bootstrap/selection blocks,
emulated registers, compact interpreter, exact-build fallbacks, and native
memory-layout adapters have been removed. The production recovery package now
contains typed algorithms without runtime frame-AES or SIDB-key data profiles.

The compact frame-AES and SIDB-key models and the larger generalized and SPN
models remain independent test-only oracles. Production uses the exact AES-128
composition with fixed input whitening, checked by byte-domain, linear-map and
full-path differential tests.

New captures contain only structural enrollment inputs. Collection no longer
copies fairplayd, profiles its CFG, or records a daemon hash as a recovery
requirement. Recovery no longer accepts a reference-binary override. Legacy
capture manifests that contain the old diagnostic binary remain readable.

New enrollment models also no longer identify themselves with the 26A428
fairplayd hash. Their 32-byte identity field is now the SHA-256 of the semantic
domain string `unfairplay/typed-current-enrollment/v1`:
`a3aa881749848636d88a8b0ec02adb35b77101d0a001dea6a0671696d8595402`.
Model selection does not compare this value with a capture or host daemon;
the selector and complete personalized SINF authentication are authoritative.
Existing version-1, version-2, and version-3 models remain readable. A retained
pre-change version-2 model still verified the same 10 images and 11,004 pages,
with decrypted-IPA SHA-256
`0eafcbac1502c38aeaa069a627e2d6592f0f2a19b42222361c392a85d77f79ea`.

The prior per-enrollment SIDB DFA is no longer a semantic requirement. At the
pre-consumer boundary, sixteen encoded bytes decode to the complete AES-128
round-10 key. Reversing the standard key schedule reproduces the SIDB decoder
key. This was derived from 64 chosen-frame controls and then matched 17
independent recovered keys exactly. The affine byte encodings are still
26A428 oracle evidence until they are normalized across other builds.

The protected producer's latter half is also typed: one-byte differential
masks match the ordinary AES-128 schedule for rounds 6, 7, 8, and 9 exactly.
The Go schedule reversal now accepts any round from 0 through 10. No separate
round-specific white box or DFA is required after a semantic round key has
been recovered. The remaining unknown is the earlier frame-to-round-key
producer and its protected byte representation.

All nine generalized SIDB-key producer rounds are now separated from their
protected register representation. At each boundary, four complete 32-bit carriers were
identified while transient XOR shares were excluded. Every round is exactly a
baseline plus sixteen independent 8-to-32-bit XOR contribution tables, with
four input bytes feeding each four-byte output group. For every round, all
4,096 one-byte controls and 256 deterministic multi-byte controls matched the
typed `generalizedByteRound` shape. The independently recovered round digests
are:

```text
25b4b4e6 0ba5905a e896a7fe d2a1bf8b cdea5bf1
aa1f69d0 36867136 e797caf6 64556dd1
```

These native-boundary rounds are not the enrollment-frame suffix described
below. They sit later, between the selected enrollment frame and the SIDB AES
key. Their protected boundary encodings are now removed too. The enrollment
frame's final affine map composes into the producer's first layer. All nine
middle layers factor exactly as AES `InvMixColumns`. A global gauge solve reduces
every intervening nonlinear transition to the AES inverse S-box with a direct
round-key XOR; every one of the 36 factor domains collapses from 1,020 candidates
to four equivalent gauges. Output masks compose into the following key or final
constant. A second byte-order solve maps all nine round matrices to one fixed
`InvShiftRows + InvMixColumns` operation; only 16 equivalent global orderings
remain. The eight recovered keys are independent round constants rather than
an AES-128 key schedule. The former final 40-map affine layer factors exactly
into four byte-wise XOR graphs. One unique gauge per graph turns the preceding
sixteen protected substitutions into direct keyed AES inverse S-boxes; their
output masks fold into the final constants. The initial protected endpoint has
one unique normalization per byte: all
sixteen substitutions are direct AES inverse S-boxes with a zero key. Their
output masks fold into the first middle-round key. The test oracle is
therefore ten inverse-S-box layers from end to end. The checked test
profile is 528 bytes before gzip and 390 bytes compressed. It contains the
round constants, four XOR adjacency masks, and compact endpoint maps. The
former 43,392-byte affine-SPN profile is now a test-only 26A428 normalization
oracle.

The typed producer matched all one-byte and deterministic multi-byte controls
at every recovered boundary, then reproduced 17 independently DFA-recovered
AES keys exactly. The inverse-AES form additionally matched the former
affine-SPN oracle over 4,096 deterministic controls. A selected frame captured
on the independent 26B118 machine also produced the same key SHA-256 as a fresh
full DFA recovery. Production candidate enumeration now returns the semantic
state and derived SIDB key; the unused protected frame encoding has been
removed. No handler address, register carrier, stack slot, generated CFG, or
DFA participates in that derivation.

The downstream class join is no longer an opaque white box. Its exact natural
path was isolated to 60 protected blocks. Coherent faults at its round-8,
round-7, and round-6 state boundaries completed the independent AES recovery
in about four seconds. The external input encoding is identity and the output
encoding is exactly XOR `0x1b` at every byte. After removing that output mask,
the result is exactly `AES-128-ECB-decrypt(class_key, valu_ciphertext)`.
Production now has this operation as a typed Go function; the protected core
must not be shipped or recovered again.

The preceding `valu` producer is typed too. It consumes one 16-byte window
from the record's 20-byte `Payload || Tail` material. Each byte is XORed with
the corresponding position in one fixed 16-byte mask, wrapping when the
window crosses the payload boundary. Each resulting word then uses one
modular affine operation:

```text
semantic_word = 0xa46fd0ff * masked_window_word + 0xfe063531
                modulo 2^32
```

The former four apparent enrollment-specific word masks were a false boundary:
they are only rotations of the same fixed mask caused by different window
starts. The old layout uses offset 0; the independent current layout uses
offset 3 and naturally crosses into `Tail`. Both reproduce the exact protected
word entering the native arithmetic. The intermediate
XOR/add/multiply/mask MBA was removed. Its key identities were proved with
32-bit Z3 bit-vectors, and the direct operation matches the unreduced protected
arithmetic over 4,096 deterministic controls.

The native tree-family class key is derived from the hardware identity and SINF
selector using framed SHA-1, fixed-key AES, two workspaces, and a GF(2^8)
combination. AES encrypts the first sixteen digest bytes; its first eight
output bytes form one operand. The final two digest words initialize separate
workspaces: `seed = word % 32767`, `exponent = seed + 1`, and product cell `i`
starts as `((exponent+i) % 32767)^exponent mod 32767`. Exponent 32767 is retained.

One column-major pass uses three planes, the 45th-power distance factor,
wrapping 32-bit force accumulation and the three-output limb recurrence.
Its sample is `5^(Product + seed + Current) mod 32767`. The packed product
words combine with the AES operand through circular multiplication/XOR over
AES's GF(2^8) field; repeating the eight-byte result forms the class AES key.
The tree path does not enumerate fixed-class or suffix-seed candidates.

The earlier flat interpretation of the 630-byte control appeared to require a
separate account digest, workspace and mask-phase search. The corrected native
tree reaches the same physical window through the ordinary tree class key and
absolute-position mask. That flat family is no longer a production path; its
direct helpers remain only as testable historical code pending removal.

The independent older private control recovered from its 630-byte Mac SIDB,
IOMACAddress, installed license, and personalized IPA with no iPhone or iOS 16
material. The new typed model SHA-256 was
`6f9888452b6f9f0acf5466d32b71ee52f6b4ddca3d1e27027879b4f18336ef74`.
It decrypted one encrypted image and one page; decrypted-IPA SHA-256 was
`d71c1a150acc334b0dc0bf9532bc8501aa8c2020cb7d906b9b4cb5b212ce0f53`,
and logical-key SHA-256 matched the established independent result
`0cc0921e90789a30c7cce2ba80c75ced64dd334af31ff6744dc714923a14ac32`.

The decoded current registry is parsed as one bounded native tree at the
hardware-derived root cursor. Node lengths and child counts must fit and fill
their parent exactly. The exact tagged `user/key/valu` route supplies one
window with its absolute-position mask. The old length-only flat/footer
fallback is not a production candidate.

The current-SINF external codec is identity after normalization. Its protected
form XORed each byte with a position mask and then used an inverse table that
XORed the same mask again. Production now copies the authenticated private
source directly and emits zero whitening plus canonical identity tables for
backward-compatible version-2 models. The former semantic-profile object and
its 4,112 bytes of encoding data have been removed.

The outer loop derives the codec boundary from its stateful exit. Payload
alignment and trailer bounds are checked afterward. One modulus-sized source
projection feeds the selected state slot. Complete SINF authentication must
accept the single tagged route. The payload, tree depth and node count have
explicit resource bounds.

Current SINF parsing now accepts bounded rights payloads from 80 through 256
bytes in eight-byte units. The observed 440- and 448-byte private records and
synthetic appended-rights controls share one structural CBC/trailer parser.
macOS conversion separately requires the canonical named-right prefix, visible
and private rights equality, a zero partial-block trailer, and an exact CBC
round trip before reducing the record to the 440-byte target geometry. Direct
version-2 enrollment models decode the current IV-prefixed private record first,
then re-encode that authenticated plaintext with the legacy macOS CBC wrapper.
Older credential-wrapped version-2 models retain their compatibility path.

Go evaluates one tagged tree window with the directly derived class key. A SINF
prefix probe rejects an incorrect key quickly; complete personalized-SINF
authentication must then accept that same route. Four independent enrollment
controls pass complete model and IPA validation, and a fifth control covers an
ARMv6-only decryption.

SUPF authentication is typed and structural too. Variant 3 authenticates its
signed architecture/page-key prefix with RSA/SHA-1, while variant 5 uses
RSA/SHA-256. The embedded 1024-bit leaf certificate is checked against the
pinned Apple FairPlay Certification Authority public key before its key is
allowed to verify the prefix. The authority key was independently reconstructed
from three valid Apple certificate/signature pairs, reduced to one 1024-bit
modulus, and then verified against all ten FairPlay leaf certificates embedded
in the reference binary plus four v3/v5 licenses from two enrollment layouts.
The independent 26B118 private control still produced the byte-identical model
and decrypted IPA after this check was enabled.

The account-entry and bootstrap boundary has now collapsed too. A full live-in
audit found 3,671 bytes crossing from account entry to bootstrap, mostly native
X.509 objects, Montgomery scratch, descriptors, and pointers. Invalid signed
prefix and signature mutations both take the native rejection edge. Four valid
v5 licenses from e-Devlet, 9292, WhatsApp, and Airalo—including compact and
multi-page layouts—produce the exact same 167-word outer table, five state
words, optional word, and loop controls. A hardware mutation changes none of
those values; it changes only the explicit six-byte hardware input. Production
verifies the SUPF in ordinary Go, constructs the fixed semantic outer profile,
and runs the typed outer algorithm using the codec and hardware bytes. The old `fairplayd`, checkpoint,
account/bootstrap CFG, and stack-offset adapter dependencies have been removed.

The per-codec outer cycle is no longer a generated MBA circuit in production.
Its five 32-bit state updates are direct XORs of rotated codec and hardware
bytes. Its five wide continuation values reduce to the hardware index, two
selected hardware bytes, and two small affine index expressions. The direct
implementation matched the retained 764-line protected circuit exactly on
4,096 deterministic controls; that circuit now exists only as a test oracle.

On the independent 26B118 current-layout control, this zero-offset path still
produced byte-identical enrollment-model SHA-256
`98c29933c57e3425f22005bfaf43fac684ef6b671629f76361cb1dd502147575`,
decrypted 39 images and 10,080 pages, and retained decrypted-IPA SHA-256
`73fb374a683c2b10558ef8ab82b5833bdfab719a49a147597eb6dedf40fa325a`.
No native or extracted block ran.

Separately, the enrollment-frame suffix table algebra is now closed. All 144 input substitutions in its
nine generalized rounds are exactly affine-equivalent to the ordinary AES
S-box, exhaustively over the 256-byte domain. For each substitution, its four
output components are related by invertible affine byte maps. The final layer
contains four direct byte permutations and twelve shared outputs; all 36
nonlinear contributions to those shared outputs are also exactly
affine-equivalent to the AES S-box. The twelve shared outputs form four
four-byte groups. Each group reduces to an invertible 32x32 affine map followed
by four byte permutations. Composing those maps gives the complete suffix as
ten parallel AES-S-box layers separated by affine 128-bit stages, followed by
one affine output stage and sixteen byte encodings.

The remaining affine gauges are solved globally rather than selected one layer
at a time. Each of the 36 four-byte components initially has 1,020 exact AES
factorizations. Constraints at every shared byte boundary reduce every domain
to four equivalent gauges. A coherent choice exposes eight direct keyed AES
S-box transitions separated by nine sparse `GF(2^8)` mixing layers. The four
apparent output masks are fixed coordinate encodings, not new nonlinear
operations.

The test oracle executes that compact AES-S-box/MDS form. Its checked
profile is 4,940 bytes before gzip and 2,065 bytes compressed, down from the
51,592-byte affine SPN and the original 167,844-byte generalized table model.
The frame's unused diagnostic output encoding and protected dispatcher exit
word are no longer production state. Its final affine output is composed into
the SIDB-key producer bridge. The generalized and affine SPN models are
test-only independent oracles. Across 4,096 deterministic controls, the
compact form reproduces the exact affine-SPN state. A direct DarkPhoenix run
was also a useful negative: it reaches step 2 and fails the Tolhuizen condition
because the unreduced final layer is groupwise rather than bytewise. The gauge
solve explains that failure; another DFA run is not needed.

## Cross-build evidence

Local binaries already show that CFG identity is not a useful definition of
build support:

- The stable account-entry control matrix now spans five independently hashed
  releases:

  | Build | arm64e SHA-256 | `__text` SHA-256 | Words identical to 26A428 |
  | --- | --- | --- | ---: |
  | 22A380 | `b09ad07348949aa0dbcfad8058cf1871a95e45caed575c58db9f9c78ba600c66` | `9d9637c9c5e0e91c886a494b3c7c08c9554156b145992b4c1210ae06f3eb4e85` | 9,710 / 9,779 |
  | 23A344 | `07e2b83fbeee23df0a2262188d55f9bda19f0c0dec0a78b5839b74a6b940f546` | `d53d844510c676bf002671d6543221428dc9789d4065357b0db3a32ed7a92dfa` | 9,684 / 9,779 |
  | 24A335 | `df4986011a9dff6f8078dc99d9d0cd27d8fd0af248e2034145b30ebd6041d18b` | `466b359399c23243e21387465e2f1ae96e8870014b88bfdf92345e2b7f89cff3` | 9,684 / 9,779 |
  | 25G83 | `93b8db9c7140cedbd04a3bbbce297b68ba9060e8a4f39ef52a1017964f3da4c5` | `425d914b6164320bb06fb9ae891d522dd0aeab719ca577825f8076490be30f7e` | 9,684 / 9,779 |
  | 26A428 | `1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784` | `eb9214dd24610e71505223d41c7627575952de101e44d474dd2fc06bea9045a4` | reference |

  Every complete account-entry function has 9,779 instructions and normalized
  SHA-256
  `b0dc6ba4f1e4f57a4e9385c65774dfa5bf27040e4ee9f60c3e3128b10f463da2`.
  For 23A344 through 25G83, all 95 non-identical words are relocated
  references: 47 `ADRP`, 29 `LDR`, 18 `ADD`, and one `BL`. For 22A380, the
  corresponding counts are 21, 29, 18, and one. No arithmetic or control
  instruction differs. This is full static differential evidence for the
  account-entry implementation across four major-version boundaries. It does
  not yet prove equal runtime outputs or validate the downstream frame and
  SIDB-key stages.
- The recovered SHA-1, Montgomery, byte-mask, word-mask, selection-state, and
  SINF algorithms remain valid semantic operations.
- Therefore cross-build work is used to remove obfuscation-dependent details,
  not to add one implementation per binary.

The former downstream BinDiff anchor map is rejected. Its one-block matches
were mnemonic-shape false positives, not typed dataflow matches. The clearest
control is the proposed 25G83 frame candidate at `0x100a6ef30`: BinDiff paired
it with 26A428 `0x1002fbb24` at similarity `0.428845` and confidence
`0.622459`, but the correspondence fails at the semantic boundary. Where the
26A428 path reads the sixteen input bytes, 25G83 performs 32-bit shifts and
bit slicing into a stack word schedule. The proposed 25G83 path continues for
4,136 instructions into a multiword compression-shaped loop and never exposes
the reference function's sixteen-byte input/output geometry. Matching mnemonic
counts therefore do not locate a protected stage. The associated 22A380,
23A344, and 24A335 candidates are demoted too until structural dataflow proves
them independently.

Cross-build discovery must start from semantic invariants: one structurally
identified sixteen-byte input, one sixteen-byte output, complete causal
diffusion, and normalization to the typed Go stage. Function similarity,
address proximity, and flattened-handler roots may rank candidates, but cannot
promote one.

That structural search has now recovered a narrower, evidence-ranked set:

- The proven 26A428 suffix at `0x1002fbb24..0x1002ff8d8` and the 25G83 path at
  `0x100086a70..0x10008a834` both contain exactly 3,953 instructions. The
  25G83 path has the same complete sixteen-byte input/output geometry, a
  mnemonic-histogram overlap of 3,905/3,953, and a mnemonic sequence ratio of
  `0.736403`. This is a credible local frame-family candidate, but it is not a
  proved natural-path match and its semantic output still needs normalization
  against the typed Go stage.
- The 22A380, 23A344, and 24A335 images each contain roughly eighty protected
  functions with the same ten-round shape: 160 indexed 32-bit table loads,
  sixteen-byte input and output geometry, and complete causal diffusion.
  Representative members at 22A380 `0x100c1c824`, 23A344 `0x10071bc74`, and
  24A335 `0x1001a0704` execute deterministically in the exact offline images.
  This proves a shared white-box family, not that any representative is the
  enrollment-frame instance. Apple includes many alternate or decoy instances,
  so diffusion and table counts cannot select the semantic path.
- Pointer-table ranks, selector ordinals, and effective table-address order are
  randomized between 25G83 and 26A428. All three can drive valid-looking
  sixteen-byte transforms, but none normalizes to the typed frame core. They
  are therefore rejected as cross-build identities. The exact natural caller
  state must select the instance and its tables.
- The 25G83 predecessor chain is coherent after using its real dispatcher base
  rather than a table-rank guess. The unique bounded solution starts with state
  `-1`, uses table base `0x100f8e190`, selects loop state `0x6376`, applies exit
  mask `0xb2`, runs seven iterations through `0x1000d9778`, reaches descriptor
  caller `0x100034d60`, and naturally enters the 3,953-instruction frame at
  `0x100086a70`. This is further evidence for regenerated protected encodings,
  not a different enrollment algorithm. These addresses remain research-only.

The formerly top-ranked 22A380 candidate at
`0x10061d8c8..0x100623954` is rejected. It has attractive instruction counts,
sixteen-byte reads, and a `0.927677` mnemonic-histogram overlap, but changing
each apparent input byte caused zero output changes. This is the concrete
control showing why geometry and mnemonic similarity are insufficient without
causal mutation.

These are research controls, not build-specific production profiles. Promotion
requires showing that an exact natural path decodes to the same semantic Go
operation. The addresses, table order, selector values, register allocation,
and dispatcher encodings must not enter production.

A separate 64-byte-state plus 16-byte-input helper family is explicitly not
the frame. It appears at 22A380 `0x100b2e8a0`, 24A335 `0x100efd024`, and
25G83 `0x100bf2928`, and produces byte-identical chosen-control outputs across
those builds. Its sixteen 32-bit block loads and compression-shaped dataflow
make it a useful cross-build control, but its 64+16-to-16 contract is the wrong
semantic boundary. Do not promote it as enrollment evidence.

The five independently hashed builds remain static research controls. Further
build-by-build MBA tracing is not a beta gate: production consumes the semantic
input format and authenticates the resulting model instead of selecting an
implementation by binary identity.

## External beta evidence

SINF geometry is not the current failure boundary. The public reports and
private controls cover these current layouts:

| Total SINF bytes | `priv` bytes | `righ` bytes | `crdt`/`asdt` | Status |
| ---: | ---: | ---: | --- | --- |
| 1032 | 440 | 80 | absent | parsed |
| 1048 | 448 | 88 | absent | parsed |
| 1056 | 440 | 80 | present | parsed |

The structural invariant is `priv_bytes = 360 + righ_bytes`; the two optional
four-byte marker atoms add 24 bytes including atom headers. Bounded extended
rights are tested too. Reported failures occur after selector and SINF geometry
validation, so changing pinned total SINF sizes would not address them.

SIDB support is not yet independently general. Current evidence is:

| SIDB bytes | Evidence | Latest status |
| ---: | --- | --- |
| 630 / 993 / 1003 | three private controls | complete model and IPA validation |
| 638 | independent physical 25G83 Mac, same older account as the 630-byte control | corrected native tree selects one class precursor; enrollment recovery and complete installed-app IPA validation pass |
| 641 | issue #19, commit `1d0d12d` | old size inference failed; latest retest required |
| 3405 | issue #21, commit `1d0d12d` | old class search failed; latest retest required |
| 5494 | issue #17, commit `1d0d12d` | old geometry was ambiguous; latest retest required |
| 7180 | issue #19, commit `1d0d12d` | old legacy-class interpretation failed; latest retest required |
| 11724 | independent beta report after `abaaeff` | native boundary ran, but no decoded registry grammar matched; `cdf584c` diagnostics pending |

The independent 638-byte control exposed an overfit in the earlier registry
model and now provides a positive control for the corrected native tree.
The native evaluator and direct implementation both reach 284 outer iterations
and codec 26. The evaluator confirms that the resulting semantic object is the
full 592-byte body, not a truncated 576-byte older registry. Direct recovery's
slot 5 reproduces that body byte-for-byte.

The native protected reader resolves the grammar ambiguity. Corresponding
field reads in the 630- and 638-byte states move by six bytes. Its four-byte
outputs equal the registry bytes XORed with the already recovered 16-byte
position mask, including across that shift. The real 20-byte node header stores
the protected length at `+4` and child count at `+18`; the earlier `+2`/`+16`
fields were wrong. Maximal non-overlapping roots are discovered anywhere in
the decoded body, allowing disjoint candidates without a fixed prefix or
suffix size. The 630-, 638-, 993-, and 1003-byte controls each produce exactly
one native tree candidate and pass full IPA validation. A real migrated
multi-root state still needs a fresh beta retest.

The length-only flat fallback is removed from production candidate discovery.
It had reinterpreted wrong-key decryptions as hundreds of records and caused
the Appsterdam report's repeated 150,409,710-comparison searches. Flat geometry
was a compatibility coincidence, not a proved FairPlay format.

A fresh static check of 26A428 `0x10046119c..0x1004612b0` confirms the recovered
outer stop predicate instruction-for-instruction, including its accumulator
update and authenticated dispatch. The independent exact-body comparison now
proves the resulting source/key candidate reaches the native decoded body. The
corrected tree offsets, leaf payloads, mask phase, and selected class windows
also match the native read trace across the retained controls. This is strong
multi-input evidence, but not a claim that every untested SIDB family is
supported.

## Proof requirements

Every promoted transformation needs suitable evidence:

- exhaustive comparison for byte-sized domains;
- randomized differential tests against the exact Go oracle;
- Z3 or equivalent bit-vector proof for MBA identities where practical;
- comparison across independent binary builds;
- exact private QA hashes, image count, and decrypted page count;
- `go test ./...`, `go vet ./...`, and `go test -race ./...`.

## Next work

1. Retest 641-, 3405-, 5494-, 7180-, and 11724-byte enrollments on the exact
   version reported by `unfairplay --version`.
2. Recreate the private native class-key boundary control, then
   make it part of the manual QA matrix.
3. Promote a new structural family only after one personalized SINF selects a
   unique precursor and complete IPA validation succeeds. Add a synthetic
   regression and an opt-in private QA control.

Update this file whenever a stage becomes typed, an offset is removed, a
cross-build invariant is proved, or a completion requirement changes state.
