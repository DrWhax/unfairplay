package main

//go:generate go run gen_opcodes.go -- ../../internal/recovery/compact_kernel.go ../../internal/recovery/compact_cfg.go opcode_numbers_generated.go

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"flag"
	"fmt"
	"go/format"
	"io"
	"math"
	"math/bits"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DrWhax/unfairplay/internal/fairplay"
	"golang.org/x/arch/arm64/arm64asm"
)

var (
	subLSR32                     = regexp.MustCompile(`^sub w(\d+), w(\d+), w(\d+), lsr #(\d+)$`)
	commentPattern               = regexp.MustCompile(`^\s*// (0x[0-9a-f]+):\s+(.+)$`)
	movImmediate                 = regexp.MustCompile(`^mov ([wx])(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	movNegOne32                  = regexp.MustCompile(`^mov w(\d+), #-1$`)
	movNegative32                = regexp.MustCompile(`^mov w(\d+), #-(0x[0-9a-f]+|[0-9]+)$`)
	movNegative64                = regexp.MustCompile(`^mov x(\d+), #-(0x[0-9a-f]+|[0-9]+)$`)
	movRegister                  = regexp.MustCompile(`^mov ([wx])(\d+), [wx](\d+)$`)
	movKeep                      = regexp.MustCompile(`^movk ([wx])(\d+), #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(\d+))?$`)
	binary32                     = regexp.MustCompile(`^(eor|and|add|sub|orr|mul) w(\d+), w(\d+), w(\d+)(?:, (lsl|lsr|ror) #(\d+))?$`)
	binary64                     = regexp.MustCompile(`^(eor|add|sub|mul|and|orr) x(\d+), x(\d+), x(\d+)$`)
	binaryShift64                = regexp.MustCompile(`^(and|eor|add) x(\d+), x(\d+), x(\d+), lsl #(\d+)$`)
	addExtended                  = regexp.MustCompile(`^add ([xw])(\d+), [xw](\d+), w(\d+), (uxtb|uxth|uxtw|sxtw)(?: #(\d+))?$`)
	addASR32                     = regexp.MustCompile(`^add w(\d+), w(\d+), w(\d+), asr #(\d+)$`)
	addUXTH64                    = regexp.MustCompile(`^add x(\d+), x(\d+), w(\d+), uxth$`)
	addLSR64                     = regexp.MustCompile(`^add x(\d+), x(\d+), x(\d+), lsr #(\d+)$`)
	addImmediate32               = regexp.MustCompile(`^add w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(\d+))?$`)
	addImmediate64               = regexp.MustCompile(`^add x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	addImmediateShift64          = regexp.MustCompile(`^add x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+), lsl #(\d+)$`)
	subImmediate32               = regexp.MustCompile(`^sub w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(\d+))?$`)
	subImmediate64               = regexp.MustCompile(`^sub x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	subImmediateShift64          = regexp.MustCompile(`^sub x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+), lsl #(\d+)$`)
	addShiftRight32              = regexp.MustCompile(`^add w(\d+), w(\d+), w(\d+), lsr #(\d+)$`)
	subShift64                   = regexp.MustCompile(`^sub x(\d+), x(\d+), x(\d+), lsl #(\d+)$`)
	subLSR64                     = regexp.MustCompile(`^sub x(\d+), x(\d+), x(\d+), lsr #(\d+)$`)
	subExtended32                = regexp.MustCompile(`^sub w(\d+), w(\d+), w(\d+), uxtb$`)
	xorImmediate32               = regexp.MustCompile(`^eor w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	andImmediate32               = regexp.MustCompile(`^and w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	andImmediate64               = regexp.MustCompile(`^and x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	xorNotImmediate64            = regexp.MustCompile(`^eor x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	xorLSR64                     = regexp.MustCompile(`^eor x(\d+), x(\d+), x(\d+), lsr #(\d+)$`)
	xorROR64                     = regexp.MustCompile(`^eor x(\d+), x(\d+), x(\d+), ror #(\d+)$`)
	logicalImmediate64           = regexp.MustCompile(`^(orr|eor) x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	orImmediate32                = regexp.MustCompile(`^orr w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	orShift64                    = regexp.MustCompile(`^orr x(\d+), x(\d+), x(\d+), lsl #(\d+)$`)
	andShiftRight32              = regexp.MustCompile(`^and w(\d+), w(\d+), w(\d+), lsr #(\d+)$`)
	shiftLeft32                  = regexp.MustCompile(`^lsl w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	shiftLeft64                  = regexp.MustCompile(`^lsl x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	shiftLeftReg32               = regexp.MustCompile(`^lsl w(\d+), w(\d+), w(\d+)$`)
	shiftLeftReg64               = regexp.MustCompile(`^lsl x(\d+), x(\d+), x(\d+)$`)
	addSP                        = regexp.MustCompile(`^add x(\d+), sp, #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(\d+))?$`)
	loadSP                       = regexp.MustCompile(`^ldr ([wx])(\d+), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	loadSPBare                   = regexp.MustCompile(`^ldr ([wx])(\d+), \[sp\]$`)
	loadBase                     = regexp.MustCompile(`^ldr w(\d+), \[x(\d+), #(0x[0-9a-f]+|[0-9]+)\]$`)
	loadBase32                   = regexp.MustCompile(`^ldr w(\d+), \[x(\d+)\]$`)
	loadBaseImm64                = regexp.MustCompile(`^ldr x(\d+), \[x(\d+), #(0x[0-9a-f]+|[0-9]+)\]$`)
	loadBase64                   = regexp.MustCompile(`^ldr x(\d+), \[x(\d+)\]$`)
	loadSXTW64                   = regexp.MustCompile(`^ldr x(\d+), \[x(\d+), w(\d+), sxtw(?: #(\d+))?\]$`)
	loadUXTW32                   = regexp.MustCompile(`^ldr w(\d+), \[x(\d+), w(\d+), uxtw(?: #(\d+))?\]$`)
	loadUXTW8                    = regexp.MustCompile(`^ldrb w(\d+), \[x(\d+), w(\d+), uxtw\]$`)
	loadSXTW8                    = regexp.MustCompile(`^ldrb w(\d+), \[x(\d+), w(\d+), sxtw\]$`)
	loadBaseImm8                 = regexp.MustCompile(`^ldrb w(\d+), \[x(\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	loadSPImm8                   = regexp.MustCompile(`^ldrb w(\d+), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	loadXIndex8                  = regexp.MustCompile(`^ldrb w(\d+), \[x(\d+), x(\d+)\]$`)
	loadPostIndex8               = regexp.MustCompile(`^ldrb w(\d+), \[x(\d+)\], #(0x[0-9a-f]+|[0-9]+)$`)
	loadXIndex                   = regexp.MustCompile(`^ldr ([wx])(\d+), \[x(\d+), x(\d+)\]$`)
	loadSXTW32                   = regexp.MustCompile(`^ldr w(\d+), \[x(\d+), w(\d+), sxtw(?: #(\d+))?\]$`)
	loadUXTW64                   = regexp.MustCompile(`^ldr x(\d+), \[x(\d+), w(\d+), uxtw #(\d+)\]$`)
	storeSP                      = regexp.MustCompile(`^str w(\d+), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeSPZero32                = regexp.MustCompile(`^str (w(?:\d+)|wzr), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeSP64                    = regexp.MustCompile(`^str x(\d+), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeSP64Zero                = regexp.MustCompile(`^str (x(?:\d+)|xzr), \[sp(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	storeSPBare                  = regexp.MustCompile(`^str ([wx])(\d+), \[sp\]$`)
	storeBaseZero32              = regexp.MustCompile(`^str (w(?:\d+)|wzr), \[x(\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	storeBase                    = regexp.MustCompile(`^str w(\d+), \[x(\d+)\]$`)
	storeBase64                  = regexp.MustCompile(`^str (x(?:\d+)|xzr), \[x(\d+)\]$`)
	storeBaseImm                 = regexp.MustCompile(`^str w(\d+), \[x(\d+), #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeBaseImm64               = regexp.MustCompile(`^str (x(?:\d+)|xzr), \[x(\d+), #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeUXTW8                   = regexp.MustCompile(`^strb (w(?:\d+)|wzr), \[x(\d+), w(\d+), uxtw\]$`)
	storeBaseImm8                = regexp.MustCompile(`^strb (w(?:\d+)|wzr), \[x(\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	storeSPImm8                  = regexp.MustCompile(`^strb (w(?:\d+)|wzr), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeUXTW32                  = regexp.MustCompile(`^str w(\d+), \[x(\d+), w(\d+), uxtw #(\d+)\]$`)
	storeSXTW32                  = regexp.MustCompile(`^str (w(?:\d+)|wzr), \[x(\d+), w(\d+), sxtw(?: #(\d+))?\]$`)
	storeXIndex                  = regexp.MustCompile(`^str ([wx])((?:\d+)|zr), \[x(\d+), x(\d+)\]$`)
	loadXIndexShift32            = regexp.MustCompile(`^ldr w(\d+), \[x(\d+), x(\d+), lsl #(\d+)\]$`)
	storeXIndexShift32           = regexp.MustCompile(`^str w(\d+), \[x(\d+), x(\d+), lsl #(\d+)\]$`)
	loadPreIndex32               = regexp.MustCompile(`^ldr w(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]!$`)
	loadPreIndex64               = regexp.MustCompile(`^ldr x(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]!$`)
	storePreIndex64              = regexp.MustCompile(`^str (x(?:\d+)|xzr), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]!$`)
	storePreIndex32              = regexp.MustCompile(`^str w(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]!$`)
	storePostIndex32             = regexp.MustCompile(`^str ([xw])(\d+), \[x(\d+)\], #(-?(?:0x[0-9a-f]+|[0-9]+))$`)
	loadSignedWord               = regexp.MustCompile(`^ldursw x(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	loadSignedWordGeneral        = regexp.MustCompile(`^ldrsw x(\d+), \[(sp|x\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	loadHalfXIndex               = regexp.MustCompile(`^ldrh w(\d+), \[x(\d+), x(\d+)\]$`)
	loadSPHalf                   = regexp.MustCompile(`^ldrh w(\d+), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeXIndex8                 = regexp.MustCompile(`^strb (w(?:\d+)|wzr), \[x(\d+), x(\d+)\]$`)
	extract32                    = regexp.MustCompile(`^extr w(\d+), w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	not32                        = regexp.MustCompile(`^mvn w(\d+), w(\d+)$`)
	orNotLSL32                   = regexp.MustCompile(`^orn w(\d+), w(\d+), w(\d+)(?:, lsl #(\d+))?$`)
	rotateRight32                = regexp.MustCompile(`^ror w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	rotateRight64                = regexp.MustCompile(`^ror x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	shiftRight32                 = regexp.MustCompile(`^lsr w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	shiftRight64                 = regexp.MustCompile(`^lsr x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	shiftRightZero64             = regexp.MustCompile(`^lsr x(\d+), xzr, #(0x[0-9a-f]+|[0-9]+)$`)
	shiftRightArithmetic32       = regexp.MustCompile(`^asr w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	shiftRightArithmeticReg32    = regexp.MustCompile(`^asr w(\d+), w(\d+), w(\d+)$`)
	shiftRightArithmetic64       = regexp.MustCompile(`^asr x(\d+), x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	shiftRightReg32              = regexp.MustCompile(`^lsr w(\d+), w(\d+), w(\d+)$`)
	shiftRightReg64              = regexp.MustCompile(`^lsr x(\d+), x(\d+), x(\d+)$`)
	unsignedLong32               = regexp.MustCompile(`^umull x(\d+), w(\d+), w(\d+)$`)
	unsignedHigh64               = regexp.MustCompile(`^umulh x(\d+), x(\d+), x(\d+)$`)
	multiplyAdd32                = regexp.MustCompile(`^madd w(\d+), w(\d+), w(\d+), w(\d+)$`)
	multiplyAdd64                = regexp.MustCompile(`^madd x(\d+), x(\d+), x(\d+), x(\d+)$`)
	multiplySub32                = regexp.MustCompile(`^msub w(\d+), w(\d+), w(\d+), w(\d+)$`)
	unsignedDivide32             = regexp.MustCompile(`^udiv w(\d+), w(\d+), w(\d+)$`)
	unsignedDivide64             = regexp.MustCompile(`^udiv x(\d+), x(\d+), x(\d+)$`)
	adds64                       = regexp.MustCompile(`^adds x(\d+), x(\d+), x(\d+)$`)
	adds32                       = regexp.MustCompile(`^adds w(\d+), w(\d+), w(\d+)$`)
	subsRegister                 = regexp.MustCompile(`^subs ([xw])(\d+), [xw](\d+), [xw](\d+)$`)
	subsImmediate                = regexp.MustCompile(`^subs ([xw])(\d+), [xw](\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	signedLong32                 = regexp.MustCompile(`^smull x(\d+), w(\d+), w(\d+)$`)
	adc32                        = regexp.MustCompile(`^adc w(\d+), (w\d+|wzr), (w\d+|wzr)$`)
	compareNegative64            = regexp.MustCompile(`^cmn x(\d+), x(\d+)$`)
	compareNegativeImm32         = regexp.MustCompile(`^cmn w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	compareNegativeImm64         = regexp.MustCompile(`^cmn x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	compareImmediate32           = regexp.MustCompile(`^cmp w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	compareImmediate64           = regexp.MustCompile(`^cmp x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	conditionSetHI               = regexp.MustCompile(`^cset w(\d+), hi$`)
	conditionSetLO               = regexp.MustCompile(`^cset w(\d+), lo$`)
	conditionSetEQ               = regexp.MustCompile(`^cset w(\d+), eq$`)
	compareRegister32            = regexp.MustCompile(`^cmp w(\d+), w(\d+)$`)
	compareRegister64            = regexp.MustCompile(`^cmp x(\d+), x(\d+)$`)
	compareExtByte32             = regexp.MustCompile(`^cmp w(\d+), w(\d+), (uxtb|sxtb)$`)
	compareLSR32                 = regexp.MustCompile(`^cmp w(\d+), w(\d+), lsr #(\d+)$`)
	conditionalCompare           = regexp.MustCompile(`^ccmp ([xw])(\d+), ([xw](?:\d+)|#(?:0x[0-9a-f]+|[0-9]+)), #(0x[0-9a-f]+|\d+), ([a-z]+)$`)
	selectZeroEq32               = regexp.MustCompile(`^csel w(\d+), wzr, w(\d+), eq$`)
	branchAuth                   = regexp.MustCompile(`^braa x\d+, x\d+$`)
	addressPage                  = regexp.MustCompile(`^adrp x(\d+), #(0x[0-9a-f]+)$`)
	stackAdjust                  = regexp.MustCompile(`^(add|sub) sp, sp, #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(\d+))?$`)
	unscaledLoad                 = regexp.MustCompile(`^ldur ([wx])(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	unscaledStore                = regexp.MustCompile(`^stur ([wx])((?:\d+)|zr), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	unscaledByteLoad             = regexp.MustCompile(`^ldurb w(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	signedByteLoad               = regexp.MustCompile(`^ldrsb w(\d+), \[x(\d+)(?:, #(-?(?:0x[0-9a-f]+|[0-9]+)))?\]$`)
	unscaledByteStore            = regexp.MustCompile(`^sturb w(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	halfLoad                     = regexp.MustCompile(`^ldrh w(\d+), \[x(\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	unscaledHalfLoad             = regexp.MustCompile(`^ldurh w(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	halfStore                    = regexp.MustCompile(`^strh (w(?:\d+)|wzr), \[x(\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	pairOffset                   = regexp.MustCompile(`^(ldp|stp) ([xw](?:\d+)|[xw]zr), ([xw](?:\d+)|[xw]zr), \[(sp|x\d+)(?:, #(-?(?:0x[0-9a-f]+|[0-9]+)))?\](!)?$`)
	pairPostIndex                = regexp.MustCompile(`^(ldp|stp) ([xw](?:\d+)|[xw]zr), ([xw](?:\d+)|[xw]zr), \[(sp|x\d+)\], #(-?(?:0x[0-9a-f]+|[0-9]+))$`)
	bitClear                     = regexp.MustCompile(`^bic ([wx])(\d+), [wx](\d+), [wx](\d+)(?:, lsl #(\d+))?$`)
	signExtendByte               = regexp.MustCompile(`^sxtb w(\d+), w(\d+)$`)
	signExtendWord               = regexp.MustCompile(`^sxtw x(\d+), w(\d+)$`)
	signExtendHalf               = regexp.MustCompile(`^sxth w(\d+), w(\d+)$`)
	negate                       = regexp.MustCompile(`^neg ([wx])(\d+), [wx](\d+)$`)
	testRegister64               = regexp.MustCompile(`^tst x(\d+), x(\d+)$`)
	testRegister                 = regexp.MustCompile(`^tst w(\d+), w(\d+)$`)
	testImmediate                = regexp.MustCompile(`^tst w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	conditionSet                 = regexp.MustCompile(`^cset w(\d+), ([a-z]+)$`)
	conditionSelect              = regexp.MustCompile(`^csel ([wx])(\d+), ([wx](?:\d+)|[wx]zr), ([wx](?:\d+)|[wx]zr), ([a-z]+)$`)
	conditionIncrement           = regexp.MustCompile(`^cinc ([wx])(\d+), [wx](\d+), ([a-z]+)$`)
	conditionNegate              = regexp.MustCompile(`^cneg w(\d+), w(\d+), ([a-z]+)$`)
	conditionalCompareNegative   = regexp.MustCompile(`^ccmn w(\d+), #(0x[0-9a-f]+|[0-9]+), #(0x[0-9a-f]+|\d+), ([a-z]+)$`)
	andSetFlags                  = regexp.MustCompile(`^ands w(\d+), w(\d+), w(\d+)$`)
	andSetFlagsImmediate         = regexp.MustCompile(`^ands w(\d+), w(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	bitClearSetFlags             = regexp.MustCompile(`^bics (w(?:\d+)|wzr), w(\d+), w(\d+)$`)
	andSetFlagsLSR               = regexp.MustCompile(`^ands w(\d+), w(\d+), w(\d+), lsr #(\d+)$`)
	bitClearSetFlagsLSR          = regexp.MustCompile(`^bics (w(?:\d+)|wzr), w(\d+), w(\d+), lsr #(\d+)$`)
	conditionalCompareNegative64 = regexp.MustCompile(`^ccmn x(\d+), #(0x[0-9a-f]+|[0-9]+), #(0x[0-9a-f]+|\d+), ([a-z]+)$`)
	gnuNegativeMov64             = regexp.MustCompile(`^mov x(\d+), #(0x[0-9a-f]+)$`)
	gnuVectorRange               = regexp.MustCompile(`\{v(\d+)\.16b-v(\d+)\.16b\}`)
	gnuShiftedCompare            = regexp.MustCompile(`^(cmp|cmn) ([xw]\d+), #(0x[0-9a-f]+|\d+), lsl #(0x[0-9a-f]+|\d+)$`)
	conditionSelectIncrement32   = regexp.MustCompile(`^csinc w(\d+), (w(?:\d+)|wzr), (w(?:\d+)|wzr), ([a-z]+)$`)
	testImmediate64              = regexp.MustCompile(`^tst x(\d+), #(0x[0-9a-f]+|[0-9]+)$`)
	exclusiveOrNot32             = regexp.MustCompile(`^eon w(\d+), w(\d+), w(\d+)$`)
	countLeadingZeroes           = regexp.MustCompile(`^clz w(\d+), w(\d+)$`)
	compareAndSwap               = regexp.MustCompile(`^casal w(\d+), w(\d+), \[x(\d+)\]$`)
	moveFromStackPointer         = regexp.MustCompile(`^mov x(\d+), sp$`)
	storeSignedHalf              = regexp.MustCompile(`^sturh w(\d+), \[x(\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	unsignedMultiplyAddLong      = regexp.MustCompile(`^umaddl x(\d+), w(\d+), w(\d+), x(\d+)$`)
	multiplyNegate64             = regexp.MustCompile(`^mneg ([xw])(\d+), [xw](\d+), [xw](\d+)$`)
	multiplySub64                = regexp.MustCompile(`^msub x(\d+), x(\d+), x(\d+), x(\d+)$`)
	signedBitfieldInsert64       = regexp.MustCompile(`^sbfiz x(\d+), x(\d+), #(\d+|0x[0-9a-f]+), #(\d+|0x[0-9a-f]+)$`)
	storeUXTW64                  = regexp.MustCompile(`^str (x(?:\d+)|xzr), \[x(\d+), w(\d+), uxtw #(\d+)\]$`)
	storePostIndex8              = regexp.MustCompile(`^strb (w(?:\d+)|wzr), \[x(\d+)\], #(-?(?:0x[0-9a-f]+|[0-9]+))$`)
	vectorDup32                  = regexp.MustCompile(`^dup v(\d+)\.(\d+)s, w(\d+)$`)
	loadVector                   = regexp.MustCompile(`^ldr ([qds])(\d+), \[(sp|x\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	pairLoadVector               = regexp.MustCompile(`^ldp q(\d+), q(\d+), \[(sp|x\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	storeVector                  = regexp.MustCompile(`^stur ([qds])(\d+), \[(sp|x\d+), #(-?(?:0x[0-9a-f]+|[0-9]+))\]$`)
	vectorImmediate              = regexp.MustCompile(`^movi v(\d+)\.(\d+)([bhsd]), #([0-9a-fx]+)(?:, lsl #(\d+))?$`)
	vectorBinary                 = regexp.MustCompile(`^(add|sub|mul|eor) v(\d+)\.(\d+)([bhsd]), v(\d+)\.\d+[bhsd], v(\d+)\.\d+[bhsd]$`)
	vectorMAC                    = regexp.MustCompile(`^(mla|mls) v(\d+)\.(\d+)([bhsd]), v(\d+)\.\d+[bhsd], v(\d+)\.\d+[bhsd]$`)
	vectorUnsignedShiftLong      = regexp.MustCompile(`^(ushll|ushll2) v(\d+)\.(\d+)([hsd]), v(\d+)\.\d+([bhs]), #(\d+|0x[0-9a-f]+)$`)
	vectorUnsignedExtendLong     = regexp.MustCompile(`^(uxtl|uxtl2) v(\d+)\.(\d+)([hsd]), v(\d+)\.(\d+)([bhs])$`)
	vectorMove64                 = regexp.MustCompile(`^fmov d(\d+), d(\d+)$`)
	vectorUnsignedMultiplyLong   = regexp.MustCompile(`^(umull|umull2) v(\d+)\.(\d+)([sd]), v(\d+)\.\d+([hs]), v(\d+)\.\d+[hs]$`)
	vectorEor3                   = regexp.MustCompile(`^eor3 v(\d+)\.16b, v(\d+)\.16b, v(\d+)\.16b, v(\d+)\.16b$`)
	pairStoreVector              = regexp.MustCompile(`^stp q(\d+), q(\d+), \[x(\d+), #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeVectorRegular           = regexp.MustCompile(`^str ([qds])(\d+), \[x(\d+)(?:, #(0x[0-9a-f]+|[0-9]+))?\]$`)
	vectorTable1                 = regexp.MustCompile(`^tbl v(\d+)\.16b, \{v(\d+)\.16b\}, v(\d+)\.16b$`)
	vectorTable4                 = regexp.MustCompile(`^tbl v(\d+)\.16b, \{v(\d+)\.16b, v(\d+)\.16b, v(\d+)\.16b, v(\d+)\.16b\}, v(\d+)\.16b$`)
	vectorExtractNarrow          = regexp.MustCompile(`^xtn v(\d+)\.(\d+)([bhs]), v(\d+)\.\d+[hsd]$`)
	vectorShiftRightNarrow       = regexp.MustCompile(`^shrn v(\d+)\.(\d+)([bhs]), v(\d+)\.\d+[hsd], #(\d+|0x[0-9a-f]+)$`)
	vectorUnzipEven              = regexp.MustCompile(`^uzp1 v(\d+)\.(\d+)([bhsd]), v(\d+)\.\d+[bhsd], v(\d+)\.\d+[bhsd]$`)
	vectorNegateFloat64          = regexp.MustCompile(`^fneg d(\d+), d(\d+)$`)
	vectorUnsignedShiftRight     = regexp.MustCompile(`^ushr v(\d+)\.(\d+)([bhsd]), v(\d+)\.\d+[bhsd], #(\d+|0x[0-9a-f]+)$`)
	vectorToW                    = regexp.MustCompile(`^mov w(\d+), v(\d+)\.s\[(\d+)\]$`)
	vectorToWZero                = regexp.MustCompile(`^fmov w(\d+), s(\d+)$`)
	vectorUnsignedShift          = regexp.MustCompile(`^ushl v(\d+)\.(\d+)([bhsd]), v(\d+)\.\d+[bhsd], v(\d+)\.\d+[bhsd]$`)
	vectorMove128                = regexp.MustCompile(`^mov v(\d+)\.16b, v(\d+)\.16b$`)
	wToVectorLane                = regexp.MustCompile(`^mov v(\d+)\.s\[(\d+)\], w(\d+)$`)
	pointerAuthZero              = regexp.MustCompile(`^paciza x\d+$`)
	moveStackPointer             = regexp.MustCompile(`^mov sp, x(\d+)$`)
	subStackFromX                = regexp.MustCompile(`^sub sp, x(\d+), #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(\d+))?$`)
	unsignedBitfield             = regexp.MustCompile(`^(ubfiz|ubfx) ([xw])(\d+), [xw](\d+), #(\d+|0x[0-9a-f]+), #(\d+|0x[0-9a-f]+)$`)
	bitfieldInsert               = regexp.MustCompile(`^(bfi|bfxil) w(\d+), w(\d+), #(\d+|0x[0-9a-f]+), #(\d+|0x[0-9a-f]+)$`)
	bitfieldInsert64             = regexp.MustCompile(`^bfi x(\d+), x(\d+), #(\d+|0x[0-9a-f]+), #(\d+|0x[0-9a-f]+)$`)
	bitClearLSR32                = regexp.MustCompile(`^bic w(\d+), w(\d+), w(\d+), lsr #(\d+)$`)
	compareNegativeLSL64         = regexp.MustCompile(`^cmn x(\d+), x(\d+), lsl #(\d+)$`)
	compareUXTH32                = regexp.MustCompile(`^cmp w(\d+), w(\d+), uxth$`)
	exclusiveOrNot64             = regexp.MustCompile(`^eon x(\d+), x(\d+), x(\d+)$`)
	xorASR32                     = regexp.MustCompile(`^eor w(\d+), w(\d+), w(\d+), asr #(\d+)$`)
	loadPostIndex                = regexp.MustCompile(`^ldr ([wx])(\d+), \[x(\d+)\], #(0x[0-9a-f]+|[0-9]+)$`)
	loadHalfUXTW                 = regexp.MustCompile(`^ldrh w(\d+), \[x(\d+), w(\d+), uxtw #(\d+)\]$`)
	loadHalfXIndexShift          = regexp.MustCompile(`^ldrh w(\d+), \[x(\d+), x(\d+), lsl #(\d+)\]$`)
	orShiftRight32               = regexp.MustCompile(`^orr w(\d+), w(\d+), w(\d+), lsr #(\d+)$`)
	reverse32                    = regexp.MustCompile(`^rev w(\d+), w(\d+)$`)
	signedBitfield32             = regexp.MustCompile(`^(sbfiz|sbfx) w(\d+), w(\d+), #(\d+|0x[0-9a-f]+), #(\d+|0x[0-9a-f]+)$`)
	storeSPHalf                  = regexp.MustCompile(`^strh w(\d+), \[sp, #(0x[0-9a-f]+|[0-9]+)\]$`)
	storeHalfPostIndex           = regexp.MustCompile(`^strh w(\d+), \[x(\d+)\], #(-?(?:0x[0-9a-f]+|[0-9]+))$`)
	subUXTH32                    = regexp.MustCompile(`^sub w(\d+), w(\d+), w(\d+), uxth$`)
	orNotShift                   = regexp.MustCompile(`^orn ([xw])(\d+), [xw](\d+), [xw](\d+)(?:, (lsl|lsr) #(\d+))?$`)
	not64                        = regexp.MustCompile(`^mvn x(\d+), x(\d+)$`)
	noopInstruction              = regexp.MustCompile(`^(?:pacibsp|nop|hint #(0x[0-9a-f]+|\d+))$`)
	blockFunction                = regexp.MustCompile(`^func ([A-Za-z_][A-Za-z0-9_]*)(?:\([^)]*\))`)
	branchDirect                 = regexp.MustCompile(`^b #(0x[0-9a-f]+)$`)
	branchConditional            = regexp.MustCompile(`^b\.([a-z]+) #(0x[0-9a-f]+)$`)
	branchLink                   = regexp.MustCompile(`^bl #(0x[0-9a-f]+)$`)
	branchCompareZero            = regexp.MustCompile(`^(cbz|cbnz) ([xw])(\d+), #(0x[0-9a-f]+)$`)
	branchTestBit                = regexp.MustCompile(`^(tbz|tbnz) [xw](\d+), #(0x[0-9a-f]+|\d+), #(0x[0-9a-f]+)$`)
	branchRegister               = regexp.MustCompile(`^(?:br|braa|brab|braaz|brabz) x(\d+)(?:, x\d+)?$`)
	callRegister                 = regexp.MustCompile(`^(?:blr|blraa|blrab|blraaz|blrabz) x(\d+)(?:, x\d+)?$`)
	callRegisterZero             = regexp.MustCompile(`^(?:blraaz|blrabz) x(\d+)$`)
	returnRegister               = regexp.MustCompile(`^ret(?:(?:aa)|(?:ab))?$`)
	literalReturn                = regexp.MustCompile(`^\s*return (0x[0-9a-f]+), false, nil$`)
	literalStopReturn            = regexp.MustCompile(`^\s*return (0x[0-9a-f]+), true, nil$`)
	identifier                   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func number(value string) (uint64, error) {
	base := 10
	if strings.HasPrefix(value, "0x") {
		base, value = 16, strings.TrimPrefix(value, "0x")
	}
	return strconv.ParseUint(value, base, 64)
}

func signedNumber(value string) (int64, error) {
	negative := strings.HasPrefix(value, "-")
	if negative {
		value = strings.TrimPrefix(value, "-")
	}
	result, err := number(value)
	if err != nil || result > 0x7fff+uint64(boolInt(negative)) {
		return 0, fmt.Errorf("signed immediate %q is outside int16", value)
	}
	if negative {
		return -int64(result), nil
	}
	return int64(result), nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func conditionConstant(name string) (string, bool) {
	value, ok := compactConditionConstant(name)
	if !ok {
		return "", false
	}
	return "uint8(" + value + ")", true
}

func compactConditionConstant(name string) (string, bool) {
	constants := map[string]string{
		"eq": "compactConditionEQ", "ne": "compactConditionNE",
		"hs": "compactConditionHS", "cs": "compactConditionHS",
		"lo": "compactConditionLO", "cc": "compactConditionLO",
		"mi": "compactConditionMI", "pl": "compactConditionPL",
		"vs": "compactConditionVS", "vc": "compactConditionVC",
		"hi": "compactConditionHI", "ls": "compactConditionLS",
		"ge": "compactConditionGE", "lt": "compactConditionLT",
		"gt": "compactConditionGT", "le": "compactConditionLE",
	}
	value, ok := constants[name]
	return value, ok
}

func registerNumber(value string) (string, bool) {
	if value == "wzr" || value == "xzr" {
		return "31", true
	}
	if len(value) < 2 || value[0] != 'w' && value[0] != 'x' {
		return "", false
	}
	if _, err := strconv.ParseUint(value[1:], 10, 8); err != nil {
		return "", false
	}
	return value[1:], true
}

func baseRegisterNumber(value string) (string, bool) {
	if value == "sp" {
		return "31", true
	}
	if !strings.HasPrefix(value, "x") {
		return "", false
	}
	return registerNumber(value)
}

func compactPairInstruction(match []string, mode uint8) (string, bool, error) {
	first, firstOK := registerNumber(match[2])
	second, secondOK := registerNumber(match[3])
	base, baseOK := baseRegisterNumber(match[4])
	if !firstOK || !secondOK || !baseOK || match[2][0] != match[3][0] {
		return "", false, fmt.Errorf("invalid register in pair operation")
	}
	offset := int64(0)
	var err error
	if match[5] != "" {
		offset, err = signedNumber(match[5])
	}
	if err != nil {
		return "", false, err
	}
	op := "compactPairLoad32"
	if match[1] == "stp" {
		op = "compactPairStore32"
	}
	if match[2][0] == 'x' {
		op = "compactPairLoad64"
		if match[1] == "stp" {
			op = "compactPairStore64"
		}
	}
	return fields(op, "destination", first, "left", base, "right", second, "accumulator", fmt.Sprint(mode), "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
}

func fields(operation string, values ...string) string {
	result := "{op: " + operation
	for index := 0; index+1 < len(values); index += 2 {
		result += ", " + values[index] + ": " + values[index+1]
	}
	return result + "},"
}

func immediate32Fields(value uint64) []string {
	return []string{
		"right", fmt.Sprintf("%#x", byte(value>>16)),
		"accumulator", fmt.Sprintf("%#x", byte(value>>24)),
		"immediate", fmt.Sprintf("%#x", uint16(value)),
	}
}

func immediate48Fields(value uint64) []string {
	return []string{
		"left", fmt.Sprintf("%#x", byte(value>>16)),
		"right", fmt.Sprintf("%#x", byte(value>>24)),
		"accumulator", fmt.Sprintf("%#x", byte(value>>32)),
		"shift", fmt.Sprintf("%#x", byte(value>>40)),
		"immediate", fmt.Sprintf("%#x", uint16(value)),
	}
}

func compactInstruction(disassembly string) (string, bool, error) {
	if match := testRegister64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactTestRegister64", "left", match[1], "right", match[2]), false, nil
	}

	if noopInstruction.MatchString(disassembly) || pointerAuthZero.MatchString(disassembly) {
		return fields("compactNoop"), false, nil
	}
	if match := moveStackPointer.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMovSP", "left", match[1]), false, nil
	}
	if match := moveFromStackPointer.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMovFromSP", "destination", match[1]), false, nil
	}
	if match := subStackFromX.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[2])
		shift := uint64(0)
		var shiftErr error
		if match[3] != "" {
			shift, shiftErr = number(match[3])
		}
		if immediateErr != nil || shiftErr != nil || immediate > 0xffff || shift > 63 {
			return "", false, fmt.Errorf("invalid stack subtraction %q", disassembly)
		}
		return fields("compactSubSPFromX", "left", match[1], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := addressPage.FindStringSubmatch(disassembly); match != nil {
		value, err := number(match[2])
		if err != nil || value >= 1<<48 {
			return "", false, fmt.Errorf("invalid ADRP address %q", match[2])
		}
		return fields("compactMovImm48", append([]string{"destination", match[1]}, immediate48Fields(value)...)...), false, nil
	}
	if match := stackAdjust.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[2])
		shift := uint64(0)
		var shiftErr error
		if match[3] != "" {
			shift, shiftErr = number(match[3])
		}
		if immediateErr != nil || shiftErr != nil || immediate > 0xffff || shift > 63 {
			return "", false, fmt.Errorf("invalid stack adjustment %q", disassembly)
		}
		op := "compactAddSPImm"
		if match[1] == "sub" {
			op = "compactSubSPImm"
		}
		return fields(op, "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := unsignedBitfield.FindStringSubmatch(disassembly); match != nil {
		lsb, lsbErr := number(match[5])
		width, widthErr := number(match[6])
		limit := uint64(32)
		op := "compactUBFIZ32"
		if match[2] == "x" {
			limit, op = 64, "compactUBFIZ64"
		}
		if match[1] == "ubfx" {
			op = "compactUBFX32"
			if match[2] == "x" {
				op = "compactUBFX64"
			}
		}
		if lsbErr != nil || widthErr != nil || lsb >= limit || width == 0 || width > limit-lsb || width > 0xffff {
			return "", false, fmt.Errorf("invalid bitfield operation %q", disassembly)
		}
		return fields(op, "destination", match[3], "left", match[4], "shift", fmt.Sprint(lsb), "immediate", fmt.Sprintf("%#x", width)), false, nil
	}
	if match := bitfieldInsert.FindStringSubmatch(disassembly); match != nil {
		lsb, lsbErr := number(match[4])
		width, widthErr := number(match[5])
		if lsbErr != nil || widthErr != nil || lsb >= 32 || width == 0 || width > 32-lsb {
			return "", false, fmt.Errorf("invalid bitfield insert %q", disassembly)
		}
		op := "compactBFI32"
		if match[1] == "bfxil" {
			op = "compactBFXIL32"
		}
		return fields(op, "destination", match[2], "left", match[3], "shift", fmt.Sprint(lsb), "immediate", fmt.Sprintf("%#x", width)), false, nil
	}
	if match := bitfieldInsert64.FindStringSubmatch(disassembly); match != nil {
		lsb, lsbErr := number(match[3])
		width, widthErr := number(match[4])
		if lsbErr != nil || widthErr != nil || lsb >= 64 || width == 0 || width > 64-lsb {
			return "", false, fmt.Errorf("invalid 64-bit BFI %q", disassembly)
		}
		return fields("compactBFI64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(lsb), "immediate", fmt.Sprintf("%#x", width)), false, nil
	}
	if match := signedBitfield32.FindStringSubmatch(disassembly); match != nil {
		lsb, lsbErr := number(match[4])
		width, widthErr := number(match[5])
		if lsbErr != nil || widthErr != nil || lsb >= 32 || width == 0 || width > 32-lsb {
			return "", false, fmt.Errorf("invalid signed bitfield operation %q", disassembly)
		}
		op := "compactSBFIZ32"
		if match[1] == "sbfx" {
			op = "compactSBFX32"
		}
		return fields(op, "destination", match[2], "left", match[3], "shift", fmt.Sprint(lsb), "immediate", fmt.Sprintf("%#x", width)), false, nil
	}
	if match := unscaledLoad.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[4])
		if err != nil {
			return "", false, err
		}
		op := "compactLoadSignedOffset32"
		if match[1] == "x" {
			op = "compactLoadSignedOffset64"
		}
		return fields(op, "destination", match[2], "left", match[3], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := unscaledStore.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[4])
		if err != nil {
			return "", false, err
		}
		op := "compactStoreSignedOffset32"
		if match[1] == "x" {
			op = "compactStoreSignedOffset64"
		}
		source := match[2]
		if source == "zr" {
			source = "31"
		}
		return fields(op, "destination", source, "left", match[3], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := unscaledByteLoad.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactLoadSignedOffset8", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := signedByteLoad.FindStringSubmatch(disassembly); match != nil {
		offset := int64(0)
		var err error
		if match[3] != "" {
			offset, err = signedNumber(match[3])
		}
		if err != nil {
			return "", false, err
		}
		return fields("compactLoadSignedByte32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := unscaledByteStore.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactStoreSignedOffset8", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := pairOffset.FindStringSubmatch(disassembly); match != nil {
		mode := uint8(0)
		if match[6] == "!" {
			mode = 1
		}
		return compactPairInstruction(match, mode)
	}
	if match := pairPostIndex.FindStringSubmatch(disassembly); match != nil {
		return compactPairInstruction(match, 2)
	}
	if match := halfLoad.FindStringSubmatch(disassembly); match != nil {
		offset := uint64(0)
		var err error
		if match[3] != "" {
			offset, err = number(match[3])
		}
		if err != nil || offset > 0xffff {
			return "", false, fmt.Errorf("invalid halfword load %q", disassembly)
		}
		op := "compactLoadHalf32"
		if offset != 0 {
			op = "compactLoadSignedOffsetHalf32"
		}
		return fields(op, "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", offset)), false, nil
	}
	if match := unscaledHalfLoad.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactLoadSignedOffsetHalf32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := halfStore.FindStringSubmatch(disassembly); match != nil {
		offset := uint64(0)
		var err error
		if match[3] != "" {
			offset, err = number(match[3])
		}
		if err != nil || offset > 0xffff {
			return "", false, fmt.Errorf("invalid halfword store %q", disassembly)
		}
		op := "compactStoreHalf32"
		if offset != 0 {
			op = "compactStoreSignedOffsetHalf32"
		}
		source, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid halfword store %q", disassembly)
		}
		return fields(op, "destination", source, "left", match[2], "immediate", fmt.Sprintf("%#x", offset)), false, nil
	}
	if match := storeSPHalf.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SP halfword store %q", disassembly)
		}
		return fields("compactStoreSPHalf32", "destination", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeHalfPostIndex.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactStoreHalfPostIndex32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := bitClear.FindStringSubmatch(disassembly); match != nil {
		op := "compactBic32"
		if match[1] == "x" {
			op = "compactBic64"
		}
		shift := "0"
		if match[5] != "" {
			shift = match[5]
		}
		return fields(op, "destination", match[2], "left", match[3], "right", match[4], "shift", shift), false, nil
	}
	if match := bitClearLSR32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactBicLSR32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := signExtendByte.FindStringSubmatch(disassembly); match != nil {
		return fields("compactSXT8To32", "destination", match[1], "left", match[2]), false, nil
	}
	if match := signExtendWord.FindStringSubmatch(disassembly); match != nil {
		return fields("compactSXT32To64", "destination", match[1], "left", match[2]), false, nil
	}
	if match := signExtendHalf.FindStringSubmatch(disassembly); match != nil {
		return fields("compactSXT16To32", "destination", match[1], "left", match[2]), false, nil
	}
	if match := negate.FindStringSubmatch(disassembly); match != nil {
		op := "compactNeg32"
		if match[1] == "x" {
			op = "compactNeg64"
		}
		return fields(op, "destination", match[2], "left", match[3]), false, nil
	}
	if match := testRegister.FindStringSubmatch(disassembly); match != nil {
		return fields("compactTst32", "left", match[1], "right", match[2]), false, nil
	}
	if match := testImmediate.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffffffff {
			return "", false, fmt.Errorf("invalid TST immediate %q", match[2])
		}
		return fields("compactTstImm32", append([]string{"left", match[1]}, immediate32Fields(immediate)...)...), false, nil
	}
	if match := conditionIncrement.FindStringSubmatch(disassembly); match != nil {
		condition, ok := conditionConstant(match[4])
		if !ok {
			return "", false, fmt.Errorf("unsupported CINC condition %q", match[4])
		}
		op := "compactCInc32"
		if match[1] == "x" {
			op = "compactCInc64"
		}
		return fields(op, "destination", match[2], "left", match[3], "shift", condition), false, nil
	}
	if match := conditionNegate.FindStringSubmatch(disassembly); match != nil {
		condition, ok := conditionConstant(match[3])
		if !ok {
			return "", false, fmt.Errorf("unsupported CNEG condition %q", match[3])
		}
		return fields("compactCNeg32", "destination", match[1], "left", match[2], "shift", condition), false, nil
	}
	if match := movNegOne32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMovNegOne32", "destination", match[1]), false, nil
	}
	if match := movNegative32.FindStringSubmatch(disassembly); match != nil {
		magnitude, err := number(match[2])
		if err != nil || magnitude > 0xffffffff {
			return "", false, fmt.Errorf("invalid negative MOV immediate %q", match[2])
		}
		value := uint64(uint32(0 - uint32(magnitude)))
		return fields("compactMovImm32Wide", append([]string{"destination", match[1]}, immediate32Fields(value)...)...), false, nil
	}
	if match := movNegative64.FindStringSubmatch(disassembly); match != nil {
		magnitude, err := number(match[2])
		if err != nil {
			return "", false, fmt.Errorf("invalid negative 64-bit MOV immediate %q", match[2])
		}
		if magnitude > 0xffff {
			for shift := uint64(16); shift <= 48; shift += 16 {
				if magnitude == uint64(uint16(magnitude>>shift))<<shift {
					return fields("compactMovNegImm16Shift64", "destination", match[1], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", uint16(magnitude>>shift))), false, nil
				}
			}
			repeated := uint64(uint16(magnitude - 1))
			pattern := repeated | repeated<<16 | repeated<<32 | repeated<<48
			if magnitude == pattern+1 {
				return fields("compactMovNegRepeat16PlusOne", "destination", match[1], "immediate", fmt.Sprintf("%#x", repeated)), false, nil
			}
			if magnitude < 1<<48 {
				return fields("compactMovNegImm48", append([]string{"destination", match[1]}, immediate48Fields(magnitude)...)...), false, nil
			}
			return "", false, fmt.Errorf("unsupported negative 64-bit MOV immediate %q", match[2])
		}
		return fields("compactMovNegImm64", "destination", match[1], "immediate", fmt.Sprintf("%#x", magnitude)), false, nil
	}
	if match := movImmediate.FindStringSubmatch(disassembly); match != nil {
		value, err := number(match[3])
		if err != nil || match[1] == "w" && value > 0xffffffff {
			return "", false, fmt.Errorf("invalid MOV immediate %q", match[3])
		}
		op := "compactMovImm32"
		if match[1] == "x" {
			if value > 0xffff {
				if value == 0x7fffffffffffffff {
					return fields("compactMovMaxInt", "destination", match[2]), false, nil
				}
				if value == 0x7ffffffffffffffe {
					return fields("compactMovMaxIntMinusOne", "destination", match[2]), false, nil
				}
				repeated := uint64(uint16(value))
				if value == repeated|repeated<<16|repeated<<32|repeated<<48 {
					return fields("compactMovImm64Repeat16", "destination", match[2], "immediate", fmt.Sprintf("%#x", uint16(value))), false, nil
				}
				for shift := uint64(16); shift <= 48; shift += 16 {
					if value == uint64(uint16(value>>shift))<<shift {
						return fields("compactMovImm64Shift", "destination", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", uint16(value>>shift))), false, nil
					}
				}
				return "", false, fmt.Errorf("unsupported 64-bit MOV immediate %q", match[3])
			}
			op = "compactMovImm64"
		} else if value > 0xffff {
			if value&0xffff != 0 {
				return fields("compactMovImm32Wide", append([]string{"destination", match[2]}, immediate32Fields(value)...)...), false, nil
			}
			op, value = "compactMovImm32High", value>>16
		}
		return fields(op, "destination", match[2], "immediate", fmt.Sprintf("%#x", value)), false, nil
	}
	if match := movRegister.FindStringSubmatch(disassembly); match != nil {
		op := "compactMov32"
		if match[1] == "x" {
			op = "compactMov64"
		}
		return fields(op, "destination", match[2], "left", match[3]), false, nil
	}
	if match := movKeep.FindStringSubmatch(disassembly); match != nil {
		value, valueErr := number(match[3])
		shift := uint64(0)
		var shiftErr error
		if match[4] != "" {
			shift, shiftErr = number(match[4])
		}
		if valueErr != nil || shiftErr != nil || value > 0xffff || shift > 63 {
			return "", false, fmt.Errorf("invalid MOVK %q", disassembly)
		}
		op := "compactMovK32"
		if match[1] == "x" {
			op = "compactMovK64"
		}
		return fields(op, "destination", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", value)), false, nil
	}
	if match := addExtended.FindStringSubmatch(disassembly); match != nil {
		mode := "0"
		if match[5] == "uxtw" {
			mode = "1"
		} else if match[5] == "sxtw" {
			mode = "2"
		} else if match[5] == "uxth" {
			mode = "3"
		}
		shift := "0"
		if match[6] != "" {
			shift = match[6]
		}
		op := "compactAddExt32"
		if match[1] == "x" {
			op = "compactAddExt64"
		}
		return fields(op, "destination", match[2], "left", match[3], "right", match[4], "accumulator", mode, "shift", shift), false, nil
	}
	if match := addASR32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAddASR32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := addUXTH64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAddUXTH64", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := addLSR64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAddLSR64", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := subLSR32.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[4])
		if err != nil || shift > 31 {
			return "", false, fmt.Errorf("invalid SUB shift %q", disassembly)
		}
		return fields("compactSubLSR32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := binary32.FindStringSubmatch(disassembly); match != nil {
		opcodes := map[string]string{
			"eor": "compactXor32", "and": "compactAnd32", "add": "compactAdd32",
			"sub": "compactSub32", "orr": "compactOr32", "mul": "compactMul32",
		}
		op := opcodes[match[1]]
		extra := []string{}
		if match[5] != "" {
			if match[1] != "and" && match[1] != "eor" && match[1] != "add" && match[1] != "sub" && match[1] != "orr" {
				return "", false, fmt.Errorf("unsupported shifted binary operation %q", disassembly)
			}
			switch {
			case match[1] == "and" && match[5] == "lsl":
				op = "compactAndLSL32"
			case match[1] == "and" && match[5] == "lsr":
				op = "compactAndLSR32"
			case match[1] == "eor" && match[5] == "lsl":
				op = "compactXorLSL32"
			case match[1] == "eor" && match[5] == "lsr":
				op = "compactXorLSR32"
			case match[1] == "add" && match[5] == "lsl":
				op = "compactAddLSL32"
			case match[1] == "add" && match[5] == "lsr":
				op = "compactAddLSR32"
			case match[1] == "sub" && match[5] == "lsl":
				op = "compactSubLSL32"
			case match[1] == "orr" && match[5] == "lsl":
				op = "compactOrLSL32"
			case match[1] == "orr" && match[5] == "lsr":
				op = "compactOrLSR32"
			case match[1] == "eor" && match[5] == "ror":
				op = "compactXorROR32"
			case match[1] == "orr" && match[5] == "ror":
				op = "compactOrROR32"
			default:
				return "", false, fmt.Errorf("unsupported shifted binary operation %q", disassembly)
			}
			extra = append(extra, "shift", match[6])
		}
		return fields(op, append([]string{"destination", match[2], "left", match[3], "right", match[4]}, extra...)...), false, nil
	}
	if match := binary64.FindStringSubmatch(disassembly); match != nil {
		opcodes := map[string]string{
			"eor": "compactXor64", "add": "compactAdd64", "sub": "compactSub64",
			"mul": "compactMul64", "and": "compactAnd64", "orr": "compactOr64",
		}
		op := opcodes[match[1]]
		return fields(op, "destination", match[2], "left", match[3], "right", match[4]), false, nil
	}
	if match := binaryShift64.FindStringSubmatch(disassembly); match != nil {
		op := "compactAndLSL64"
		if match[1] == "eor" {
			op = "compactXorLSL64"
		} else if match[1] == "add" {
			op = "compactAddLSL64"
		}
		return fields(op, "destination", match[2], "left", match[3], "right", match[4], "shift", match[5]), false, nil
	}
	if match := addImmediate32.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[3])
		shift := uint64(0)
		var shiftErr error
		if match[4] != "" {
			shift, shiftErr = number(match[4])
		}
		if immediateErr != nil || shiftErr != nil || immediate > 0xffff || shift > 31 {
			return "", false, fmt.Errorf("invalid immediate ADD %q", disassembly)
		}
		return fields("compactAddImmShift32", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := addImmediate64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit immediate ADD %q", disassembly)
		}
		return fields("compactAddImm64", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := addImmediateShift64.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[3])
		shift, shiftErr := number(match[4])
		if immediateErr != nil || shiftErr != nil || immediate > 0xffff || shift > 63 {
			return "", false, fmt.Errorf("invalid shifted 64-bit ADD %q", disassembly)
		}
		return fields("compactAddImmShift64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := subImmediate32.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[3])
		shift := uint64(0)
		var shiftErr error
		if match[4] != "" {
			shift, shiftErr = number(match[4])
		}
		if immediateErr != nil || shiftErr != nil || immediate > 0xffff || shift > 31 {
			return "", false, fmt.Errorf("invalid immediate SUB %q", disassembly)
		}
		return fields("compactSubImmShift32", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := subImmediate64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit immediate SUB %q", disassembly)
		}
		return fields("compactSubImm64", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := subImmediateShift64.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[3])
		shift, shiftErr := number(match[4])
		if immediateErr != nil || shiftErr != nil || immediate > 0xffff || shift > 63 {
			return "", false, fmt.Errorf("invalid shifted 64-bit SUB %q", disassembly)
		}
		return fields("compactSubImmShift64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := subShift64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactSubLSL64", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := subLSR64.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[4])
		if err != nil || shift > 63 {
			return "", false, fmt.Errorf("invalid right-shifted 64-bit SUB %q", disassembly)
		}
		return fields("compactSubLSR64", "destination", match[1], "left", match[2], "right", match[3], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := subExtended32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactSubExt32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := subUXTH32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactSubUXTH32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := xorImmediate32.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffffffff {
			return "", false, fmt.Errorf("invalid immediate EOR %q", disassembly)
		}
		return fields("compactXorImm32", append([]string{"destination", match[1], "left", match[2]}, immediate32Fields(immediate)...)...), false, nil
	}
	if match := andImmediate32.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffffffff {
			return "", false, fmt.Errorf("invalid immediate AND %q", disassembly)
		}
		return fields("compactAndImm32", append([]string{"destination", match[1], "left", match[2]}, immediate32Fields(immediate)...)...), false, nil
	}
	if match := andImmediate64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil {
			return "", false, err
		}
		if immediate <= 0xffff {
			return fields("compactAndImm64", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
		}
		for shift := uint64(8); shift <= 48; shift += 8 {
			if immediate == uint64(uint16(immediate>>shift))<<shift {
				return fields("compactAndImmShift64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", uint16(immediate>>shift))), false, nil
			}
		}
		inverted := ^immediate
		for shift := uint64(0); shift <= 48; shift += 8 {
			if inverted == uint64(uint16(inverted>>shift))<<shift {
				return fields("compactAndNotImm16Shift64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", uint16(inverted>>shift))), false, nil
			}
		}
		return compactLogicalMaskFields("and", match[1], match[2], immediate)
	}
	if match := logicalImmediate64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[4])
		if err != nil {
			return "", false, fmt.Errorf("invalid 64-bit logical immediate %q", disassembly)
		}
		if immediate > 0xffff {
			if match[1] == "eor" && immediate == 0x3ffffffffffffff0 {
				return fields("compactXorSelectionMask64", "destination", match[2], "left", match[3]), false, nil
			}
			if match[1] == "orr" && immediate == 0xffffffff00000000 {
				return fields("compactOrHigh32Imm64", "destination", match[2], "left", match[3]), false, nil
			}
			for shift := uint64(8); shift <= 48; shift += 8 {
				if match[1] == "eor" && immediate == uint64(uint16(immediate>>shift))<<shift {
					return fields("compactXorImm16Shift64", "destination", match[2], "left", match[3], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", uint16(immediate>>shift))), false, nil
				}
			}
			inverted := ^immediate
			if match[1] == "eor" {
				for shift := uint64(0); shift <= 48; shift += 8 {
					if inverted == uint64(uint16(inverted>>shift))<<shift {
						return fields("compactXorNotImm16Shift64", "destination", match[2], "left", match[3], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", uint16(inverted>>shift))), false, nil
					}
				}
			}
			return compactLogicalMaskFields(match[1], match[2], match[3], immediate)
		}
		op := "compactOrImm64"
		if match[1] == "eor" {
			op = "compactXorImm64"
		}
		return fields(op, "destination", match[2], "left", match[3], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := xorLSR64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactXorLSR64", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := xorROR64.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[4])
		if err != nil || shift > 63 {
			return "", false, fmt.Errorf("invalid EOR rotate %q", disassembly)
		}
		return fields("compactXorROR64", "destination", match[1], "left", match[2], "right", match[3], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := orImmediate32.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffffffff {
			return "", false, fmt.Errorf("invalid 32-bit ORR immediate %q", disassembly)
		}
		return fields("compactOrImm32", append([]string{"destination", match[1], "left", match[2]}, immediate32Fields(immediate)...)...), false, nil
	}
	if match := orShift64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactOrLSL64", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := andShiftRight32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAndLSR32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := shiftLeft32.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 31 {
			return "", false, fmt.Errorf("invalid LSL %q", disassembly)
		}
		return fields("compactLSLImm32", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := shiftLeft64.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 63 {
			return "", false, fmt.Errorf("invalid 64-bit LSL %q", disassembly)
		}
		return fields("compactLSLImm64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := shiftLeftReg32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLSLReg32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := shiftLeftReg64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLSLReg64", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := addSP.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[2])
		shift := uint64(0)
		var shiftErr error
		if match[3] != "" {
			shift, shiftErr = number(match[3])
		}
		if immediateErr != nil || shiftErr != nil || immediate > 0xffff || shift > 63 {
			return "", false, fmt.Errorf("invalid SP add %q", disassembly)
		}
		return fields("compactAddSPShiftImm64", "destination", match[1], "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadSP.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SP load %q", disassembly)
		}
		op := "compactLoadSP32"
		if match[1] == "x" {
			op = "compactLoadSP64"
		}
		return fields(op, "destination", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadSPBare.FindStringSubmatch(disassembly); match != nil {
		op := "compactLoadSP32"
		if match[1] == "x" {
			op = "compactLoadSP64"
		}
		return fields(op, "destination", match[2]), false, nil
	}
	if match := loadBase.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid base load %q", disassembly)
		}
		return fields("compactLoadBaseImm32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadBase32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadBase32", "destination", match[1], "left", match[2]), false, nil
	}
	if match := loadBaseImm64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit base load %q", disassembly)
		}
		return fields("compactLoadBaseImm64", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadBase64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadBase64", "destination", match[1], "left", match[2]), false, nil
	}
	if match := loadSXTW64.FindStringSubmatch(disassembly); match != nil {
		if match[4] == "" {
			match[4] = "0"
		}
		return fields("compactLoadSXTW64", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := loadUXTW32.FindStringSubmatch(disassembly); match != nil {
		shift := "0"
		if match[4] != "" {
			shift = match[4]
		}
		return fields("compactLoadUXTW32", "destination", match[1], "left", match[2], "right", match[3], "shift", shift), false, nil
	}
	if match := loadUXTW8.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadUXTW8", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := loadSXTW8.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadSXTW8", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := loadBaseImm8.FindStringSubmatch(disassembly); match != nil {
		immediate := uint64(0)
		var err error
		if match[3] != "" {
			immediate, err = number(match[3])
		}
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid byte load %q", disassembly)
		}
		return fields("compactLoadBaseImm8", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadSPImm8.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SP byte load %q", disassembly)
		}
		return fields("compactLoadSPImm8", "destination", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadXIndex8.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadXIndex8", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := loadPostIndex8.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid post-index load %q", disassembly)
		}
		return fields("compactLoadPostIndex8", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadPostIndex.FindStringSubmatch(disassembly); match != nil {
		encoded, err := number(match[4])
		if err != nil {
			return "", false, err
		}
		offset := int64(encoded)
		if offset < -0x8000 || offset > 0x7fff {
			return "", false, fmt.Errorf("post-index offset is outside int16 in %q", disassembly)
		}
		op := "compactLoadPostIndex32"
		if match[1] == "x" {
			op = "compactLoadPostIndex64"
		}
		return fields(op, "destination", match[2], "left", match[3], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := loadXIndex.FindStringSubmatch(disassembly); match != nil {
		op := "compactLoadXIndex32"
		if match[1] == "x" {
			op = "compactLoadXIndex64"
		}
		return fields(op, "destination", match[2], "left", match[3], "right", match[4]), false, nil
	}
	if match := loadXIndexShift32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadXIndexShift32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := loadPreIndex32.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactLoadPreIndex32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := loadPreIndex64.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactLoadPreIndex64", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := loadSignedWord.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactLoadSignedWord64", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := loadSignedWordGeneral.FindStringSubmatch(disassembly); match != nil {
		base, ok := baseRegisterNumber(match[2])
		immediate := uint64(0)
		var err error
		if match[3] != "" {
			immediate, err = number(match[3])
		}
		if !ok || err != nil || immediate > 0x7fff {
			return "", false, fmt.Errorf("invalid signed word load %q", disassembly)
		}
		return fields("compactLoadSignedWordBase64", "destination", match[1], "left", base, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadHalfXIndex.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadHalfXIndex32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := loadHalfUXTW.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadHalfUXTW32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := loadHalfXIndexShift.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadHalfXIndexShift32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := loadSPHalf.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SP halfword load %q", disassembly)
		}
		return fields("compactLoadSPHalf32", "destination", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := loadSXTW32.FindStringSubmatch(disassembly); match != nil {
		if match[4] == "" {
			match[4] = "0"
		}
		return fields("compactLoadSXTW32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := loadUXTW64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLoadUXTW64", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := storeSP.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SP store %q", disassembly)
		}
		return fields("compactStoreSP32", "left", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeSPZero32.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		immediate, err := number(match[2])
		if !ok || err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid zero-capable SP store %q", disassembly)
		}
		return fields("compactStoreSP32", "left", source, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeSP64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit SP store %q", disassembly)
		}
		return fields("compactStoreSP64", "left", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeSP64Zero.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		immediate := uint64(0)
		var err error
		if match[2] != "" {
			immediate, err = number(match[2])
		}
		if !ok || err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SP zero-capable store %q", disassembly)
		}
		return fields("compactStoreSP64", "left", source, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeSPBare.FindStringSubmatch(disassembly); match != nil {
		op := "compactStoreSP32"
		if match[1] == "x" {
			op = "compactStoreSP64"
		}
		return fields(op, "left", match[2]), false, nil
	}
	if match := storeBase.FindStringSubmatch(disassembly); match != nil {
		return fields("compactStoreBase32", "destination", match[1], "left", match[2]), false, nil
	}
	if match := storeBase64.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid 64-bit base store %q", disassembly)
		}
		return fields("compactStoreBase64", "destination", source, "left", match[2]), false, nil
	}
	if match := storeBaseImm.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid base store %q", disassembly)
		}
		return fields("compactStoreBaseImm32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeBaseZero32.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		immediate := uint64(0)
		var err error
		if match[3] != "" {
			immediate, err = number(match[3])
		}
		if !ok || err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid zero-capable store %q", disassembly)
		}
		return fields("compactStoreBaseImm32", "destination", source, "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeBaseImm64.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		immediate, err := number(match[3])
		if !ok || err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit base store %q", disassembly)
		}
		return fields("compactStoreBaseImm64", "destination", source, "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeUXTW8.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid byte indexed store %q", disassembly)
		}
		return fields("compactStoreUXTW8", "destination", source, "left", match[2], "right", match[3]), false, nil
	}
	if match := storeUXTW32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactStoreUXTW32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := storeSXTW32.FindStringSubmatch(disassembly); match != nil {
		if match[4] == "" {
			match[4] = "0"
		}
		source, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid signed-index store %q", disassembly)
		}
		return fields("compactStoreSXTW32", "destination", source, "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := storeUXTW64.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid 64-bit unsigned-index store %q", disassembly)
		}
		return fields("compactStoreUXTW64", "destination", source, "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := storeBaseImm8.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		immediate := uint64(0)
		var err error
		if match[3] != "" {
			immediate, err = number(match[3])
		}
		if !ok || err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid byte store %q", disassembly)
		}
		return fields("compactStoreBaseImm8", "destination", source, "left", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeSPImm8.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		immediate, err := number(match[2])
		if !ok || err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SP byte store %q", disassembly)
		}
		return fields("compactStoreSPImm8", "destination", source, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeXIndex.FindStringSubmatch(disassembly); match != nil {
		op := "compactStoreXIndex32"
		if match[1] == "x" {
			op = "compactStoreXIndex64"
		}
		source := match[2]
		if source == "zr" {
			source = "31"
		}
		return fields(op, "destination", source, "left", match[3], "right", match[4]), false, nil
	}
	if match := storePostIndex8.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		offset, err := signedNumber(match[3])
		if !ok || err != nil {
			return "", false, fmt.Errorf("invalid post-index byte store %q", disassembly)
		}
		return fields("compactStorePostIndex8", "destination", source, "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := storeXIndexShift32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactStoreXIndexShift32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := storePreIndex64.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		offset, err := signedNumber(match[3])
		if !ok || err != nil {
			return "", false, fmt.Errorf("invalid pre-index store %q", disassembly)
		}
		return fields("compactStorePreIndex64", "destination", source, "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := storePreIndex32.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactStorePreIndex32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := storePostIndex32.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[4])
		if err != nil {
			return "", false, err
		}
		op := "compactStorePostIndex32"
		if match[1] == "x" {
			op = "compactStorePostIndex64"
		}
		return fields(op, "destination", match[2], "left", match[3], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := storeSignedHalf.FindStringSubmatch(disassembly); match != nil {
		offset, err := signedNumber(match[3])
		if err != nil {
			return "", false, err
		}
		return fields("compactStoreSignedOffsetHalf32", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := vectorDup32.FindStringSubmatch(disassembly); match != nil {
		lanes, err := number(match[2])
		if err != nil || lanes == 0 || lanes > 4 {
			return "", false, fmt.Errorf("invalid vector DUP %q", disassembly)
		}
		return fields("compactVectorDup32", "destination", match[1], "left", match[3], "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := loadVector.FindStringSubmatch(disassembly); match != nil {
		bytes := 16
		if match[1] == "d" {
			bytes = 8
		} else if match[1] == "s" {
			bytes = 4
		}
		immediate := uint64(0)
		var err error
		if match[4] != "" {
			immediate, err = number(match[4])
		}
		base, ok := baseRegisterNumber(match[3])
		if err != nil || !ok || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid vector load %q", disassembly)
		}
		return fields("compactLoadVector", "destination", match[2], "left", base, "accumulator", fmt.Sprint(bytes), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := pairLoadVector.FindStringSubmatch(disassembly); match != nil {
		base, ok := baseRegisterNumber(match[3])
		immediate := uint64(0)
		var err error
		if match[4] != "" {
			immediate, err = number(match[4])
		}
		if !ok || err != nil || immediate > 0x7fff {
			return "", false, fmt.Errorf("invalid vector pair load %q", disassembly)
		}
		return fields("compactPairLoadVector", "destination", match[1], "right", match[2], "left", base, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeVector.FindStringSubmatch(disassembly); match != nil {
		bytes := 16
		if match[1] == "d" {
			bytes = 8
		} else if match[1] == "s" {
			bytes = 4
		}
		base, ok := baseRegisterNumber(match[3])
		offset, err := signedNumber(match[4])
		if !ok || err != nil {
			return "", false, fmt.Errorf("invalid vector store %q", disassembly)
		}
		return fields("compactStoreVector", "destination", match[2], "left", base, "accumulator", fmt.Sprint(bytes), "immediate", fmt.Sprintf("%#x", uint16(int16(offset)))), false, nil
	}
	if match := vectorImmediate.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[2])
		value, valueErr := number(match[4])
		shift := uint64(0)
		var shiftErr error
		if match[5] != "" {
			shift, shiftErr = number(match[5])
		}
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32, "d": 64}
		bits, ok := bitsBySuffix[match[3]]
		if lanesErr != nil || valueErr != nil || shiftErr != nil || !ok || lanes == 0 || lanes*bits > 128 || value > 0xffff || shift >= bits {
			return "", false, fmt.Errorf("invalid vector immediate %q", disassembly)
		}
		return fields("compactVectorImmediate", "destination", match[1], "left", fmt.Sprint(bits), "right", fmt.Sprint(lanes), "shift", fmt.Sprint(shift), "immediate", fmt.Sprintf("%#x", value)), false, nil
	}
	if match := vectorBinary.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[3])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32, "d": 64}
		bits, ok := bitsBySuffix[match[4]]
		opByName := map[string]uint8{"add": 0, "sub": 1, "mul": 2, "eor": 3}
		op, opOK := opByName[match[1]]
		if lanesErr != nil || !ok || !opOK || lanes == 0 || lanes*bits > 128 {
			return "", false, fmt.Errorf("invalid vector binary operation %q", disassembly)
		}
		return fields("compactVectorBinary", "destination", match[2], "left", match[5], "right", match[6], "accumulator", fmt.Sprint(op), "shift", fmt.Sprint(bits), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorMAC.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[3])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32, "d": 64}
		bits, ok := bitsBySuffix[match[4]]
		subtract := uint8(0)
		if match[1] == "mls" {
			subtract = 1
		}
		if lanesErr != nil || !ok || lanes == 0 || lanes*bits > 128 {
			return "", false, fmt.Errorf("invalid vector multiply-accumulate %q", disassembly)
		}
		return fields("compactVectorMAC", "destination", match[2], "left", match[5], "right", match[6], "accumulator", fmt.Sprint(subtract), "shift", fmt.Sprint(bits), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorUnsignedShiftLong.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[3])
		amount, amountErr := number(match[7])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32}
		inputBits, ok := bitsBySuffix[match[6]]
		high := uint8(0)
		if match[1] == "ushll2" {
			high = 1
		}
		if lanesErr != nil || amountErr != nil || !ok || lanes == 0 || lanes*inputBits*2 > 128 || amount >= inputBits {
			return "", false, fmt.Errorf("invalid vector unsigned shift-long %q", disassembly)
		}
		packed := uint16(lanes) | uint16(inputBits)<<8
		return fields("compactVectorUnsignedShiftLong", "destination", match[2], "left", match[5], "accumulator", fmt.Sprint(high), "shift", fmt.Sprint(amount), "immediate", fmt.Sprintf("%#x", packed)), false, nil
	}
	if match := vectorUnsignedExtendLong.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[3])
		inputLanes, inputLanesErr := number(match[6])
		inputBitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32}
		outputBitsBySuffix := map[string]uint64{"h": 16, "s": 32, "d": 64}
		inputBits, ok := inputBitsBySuffix[match[7]]
		outputBits := outputBitsBySuffix[match[4]]
		high := uint8(0)
		if match[1] == "uxtl2" {
			high = 1
		}
		wantInputLanes := lanes
		if high != 0 {
			wantInputLanes = lanes * 2
		}
		if lanesErr != nil || inputLanesErr != nil || !ok || outputBits != inputBits*2 || lanes == 0 || lanes*outputBits > 128 || inputLanes != wantInputLanes {
			return "", false, fmt.Errorf("invalid vector unsigned extend-long %q", disassembly)
		}
		packed := uint16(lanes) | uint16(inputBits)<<8
		return fields("compactVectorUnsignedShiftLong", "destination", match[2], "left", match[5], "accumulator", fmt.Sprint(high), "shift", "0", "immediate", fmt.Sprintf("%#x", packed)), false, nil
	}
	if match := vectorMove64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactVectorMove64", "destination", match[1], "left", match[2]), false, nil
	}
	if match := vectorUnsignedMultiplyLong.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[3])
		bitsBySuffix := map[string]uint64{"h": 16, "s": 32}
		inputBits, ok := bitsBySuffix[match[6]]
		high := uint8(0)
		if match[1] == "umull2" {
			high = 1
		}
		if lanesErr != nil || !ok || lanes == 0 || lanes*inputBits*2 > 128 {
			return "", false, fmt.Errorf("invalid vector unsigned multiply-long %q", disassembly)
		}
		return fields("compactVectorUnsignedMultiplyLong", "destination", match[2], "left", match[5], "right", match[7], "accumulator", fmt.Sprint(high), "shift", fmt.Sprint(inputBits), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorEor3.FindStringSubmatch(disassembly); match != nil {
		return fields("compactVectorEor3", "destination", match[1], "left", match[2], "right", match[3], "accumulator", match[4]), false, nil
	}
	if match := pairStoreVector.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[4])
		if err != nil || immediate > 0x7fff {
			return "", false, fmt.Errorf("invalid vector pair store %q", disassembly)
		}
		return fields("compactPairStoreVector", "destination", match[1], "left", match[3], "right", match[2], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := storeVectorRegular.FindStringSubmatch(disassembly); match != nil {
		bytes := 16
		if match[1] == "d" {
			bytes = 8
		} else if match[1] == "s" {
			bytes = 4
		}
		immediate := uint64(0)
		var err error
		if match[4] != "" {
			immediate, err = number(match[4])
		}
		if err != nil || immediate > 0x7fff {
			return "", false, fmt.Errorf("invalid vector store %q", disassembly)
		}
		return fields("compactStoreVector", "destination", match[2], "left", match[3], "accumulator", fmt.Sprint(bytes), "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := vectorTable1.FindStringSubmatch(disassembly); match != nil {
		return fields("compactVectorTable1", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := vectorTable4.FindStringSubmatch(disassembly); match != nil {
		first, firstErr := number(match[2])
		second, secondErr := number(match[3])
		third, thirdErr := number(match[4])
		fourth, fourthErr := number(match[5])
		if firstErr != nil || secondErr != nil || thirdErr != nil || fourthErr != nil || second != first+1 || third != first+2 || fourth != first+3 {
			return "", false, fmt.Errorf("non-contiguous vector table %q", disassembly)
		}
		return fields("compactVectorTable4", "destination", match[1], "left", match[2], "right", match[6]), false, nil
	}
	if match := vectorExtractNarrow.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[2])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32}
		outputBits, ok := bitsBySuffix[match[3]]
		if lanesErr != nil || !ok || lanes == 0 || lanes*outputBits > 64 {
			return "", false, fmt.Errorf("invalid vector narrow %q", disassembly)
		}
		return fields("compactVectorExtractNarrow", "destination", match[1], "left", match[4], "shift", fmt.Sprint(outputBits), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorShiftRightNarrow.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[2])
		amount, amountErr := number(match[5])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32}
		outputBits, ok := bitsBySuffix[match[3]]
		if lanesErr != nil || amountErr != nil || !ok || lanes == 0 || lanes*outputBits > 64 || amount >= outputBits*2 {
			return "", false, fmt.Errorf("invalid vector shift-right narrow %q", disassembly)
		}
		return fields("compactVectorShiftRightNarrow", "destination", match[1], "left", match[4], "accumulator", fmt.Sprint(outputBits), "shift", fmt.Sprint(amount), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorUnzipEven.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[2])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32, "d": 64}
		bits, ok := bitsBySuffix[match[3]]
		if lanesErr != nil || !ok || lanes == 0 || lanes*bits > 128 {
			return "", false, fmt.Errorf("invalid vector unzip %q", disassembly)
		}
		return fields("compactVectorUnzipEven", "destination", match[1], "left", match[4], "right", match[5], "shift", fmt.Sprint(bits), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorNegateFloat64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactVectorNegateFloat64", "destination", match[1], "left", match[2]), false, nil
	}
	if match := vectorUnsignedShiftRight.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[2])
		amount, amountErr := number(match[5])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32, "d": 64}
		bits, ok := bitsBySuffix[match[3]]
		if lanesErr != nil || amountErr != nil || !ok || lanes == 0 || lanes*bits > 128 || amount >= bits {
			return "", false, fmt.Errorf("invalid vector unsigned shift-right %q", disassembly)
		}
		return fields("compactVectorUnsignedShiftRight", "destination", match[1], "left", match[4], "accumulator", fmt.Sprint(bits), "shift", fmt.Sprint(amount), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorToW.FindStringSubmatch(disassembly); match != nil {
		lane, err := number(match[3])
		if err != nil || lane > 3 {
			return "", false, fmt.Errorf("invalid vector lane extract %q", disassembly)
		}
		return fields("compactVectorToW", "destination", match[1], "left", match[2], "immediate", fmt.Sprintf("%#x", lane)), false, nil
	}
	if match := vectorToWZero.FindStringSubmatch(disassembly); match != nil {
		return fields("compactVectorToW", "destination", match[1], "left", match[2]), false, nil
	}
	if match := vectorUnsignedShift.FindStringSubmatch(disassembly); match != nil {
		lanes, lanesErr := number(match[2])
		bitsBySuffix := map[string]uint64{"b": 8, "h": 16, "s": 32, "d": 64}
		bits, ok := bitsBySuffix[match[3]]
		if lanesErr != nil || !ok || lanes == 0 || lanes*bits > 128 {
			return "", false, fmt.Errorf("invalid vector unsigned shift %q", disassembly)
		}
		return fields("compactVectorUnsignedShift", "destination", match[1], "left", match[4], "right", match[5], "shift", fmt.Sprint(bits), "immediate", fmt.Sprintf("%#x", lanes)), false, nil
	}
	if match := vectorMove128.FindStringSubmatch(disassembly); match != nil {
		return fields("compactVectorMove128", "destination", match[1], "left", match[2]), false, nil
	}
	if match := wToVectorLane.FindStringSubmatch(disassembly); match != nil {
		lane, err := number(match[2])
		if err != nil || lane > 3 {
			return "", false, fmt.Errorf("invalid vector lane insert %q", disassembly)
		}
		return fields("compactWToVectorLane", "destination", match[1], "left", match[3], "immediate", fmt.Sprintf("%#x", lane)), false, nil
	}
	if match := storeXIndex8.FindStringSubmatch(disassembly); match != nil {
		source, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid byte X-index store %q", disassembly)
		}
		return fields("compactStoreXIndex8", "destination", source, "left", match[2], "right", match[3]), false, nil
	}
	if match := extract32.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[4])
		if err != nil || shift > 31 {
			return "", false, fmt.Errorf("invalid EXTR %q", disassembly)
		}
		return fields("compactExtract32", "destination", match[1], "left", match[2], "right", match[3], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := reverse32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactRev32", "destination", match[1], "left", match[2]), false, nil
	}
	if match := not32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactNot32", "destination", match[1], "left", match[2]), false, nil
	}
	if match := not64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactNot64", "destination", match[1], "left", match[2]), false, nil
	}
	if match := orNotShift.FindStringSubmatch(disassembly); match != nil {
		op := "compactOrNotShift32"
		if match[1] == "x" {
			op = "compactOrNotShift64"
		}
		mode, shift := "0", "0"
		if match[5] == "lsr" {
			mode = "1"
		}
		if match[6] != "" {
			shift = match[6]
		}
		return fields(op, "destination", match[2], "left", match[3], "right", match[4], "accumulator", mode, "shift", shift), false, nil
	}
	if match := orNotLSL32.FindStringSubmatch(disassembly); match != nil {
		shift := "0"
		if match[4] != "" {
			shift = match[4]
		}
		return fields("compactOrNotLSL32", "destination", match[1], "left", match[2], "right", match[3], "shift", shift), false, nil
	}
	if match := rotateRight32.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 31 {
			return "", false, fmt.Errorf("invalid ROR %q", disassembly)
		}
		return fields("compactRORImm32", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := rotateRight64.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 63 {
			return "", false, fmt.Errorf("invalid 64-bit rotate %q", disassembly)
		}
		return fields("compactRORImm64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := shiftRight32.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 31 {
			return "", false, fmt.Errorf("invalid LSR %q", disassembly)
		}
		return fields("compactLSRImm32", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := shiftRight64.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 63 {
			return "", false, fmt.Errorf("invalid 64-bit LSR %q", disassembly)
		}
		return fields("compactLSRImm64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := shiftRightZero64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMovImm64", "destination", match[1]), false, nil
	}
	if match := shiftRightArithmetic32.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 31 {
			return "", false, fmt.Errorf("invalid ASR %q", disassembly)
		}
		return fields("compactASRImm32", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := shiftRightArithmeticReg32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactASRReg32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := shiftRightArithmetic64.FindStringSubmatch(disassembly); match != nil {
		shift, err := number(match[3])
		if err != nil || shift > 63 {
			return "", false, fmt.Errorf("invalid 64-bit ASR %q", disassembly)
		}
		return fields("compactASRImm64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(shift)), false, nil
	}
	if match := shiftRightReg32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLSRReg32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := shiftRightReg64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactLSRReg64", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := unsignedLong32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactUMull32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := unsignedMultiplyAddLong.FindStringSubmatch(disassembly); match != nil {
		return fields("compactUMADDL", "destination", match[1], "left", match[2], "right", match[3], "accumulator", match[4]), false, nil
	}
	if match := signedLong32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactSMull32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := unsignedHigh64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactUMulH64", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := multiplyAdd32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMAdd32", "destination", match[1], "left", match[2], "right", match[3], "accumulator", match[4]), false, nil
	}
	if match := multiplyAdd64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMAdd64", "destination", match[1], "left", match[2], "right", match[3], "accumulator", match[4]), false, nil
	}
	if match := multiplySub32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMSub32", "destination", match[1], "left", match[2], "right", match[3], "accumulator", match[4]), false, nil
	}
	if match := multiplyNegate64.FindStringSubmatch(disassembly); match != nil {
		opcode := "compactMNeg64"
		if match[1] == "w" {
			opcode = "compactMNeg32"
		}
		return fields(opcode, "destination", match[2], "left", match[3], "right", match[4]), false, nil
	}
	if match := multiplySub64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactMSub64", "destination", match[1], "left", match[2], "right", match[3], "accumulator", match[4]), false, nil
	}
	if match := signedBitfieldInsert64.FindStringSubmatch(disassembly); match != nil {
		lsb, lsbErr := number(match[3])
		width, widthErr := number(match[4])
		if lsbErr != nil || widthErr != nil || lsb >= 64 || width == 0 || width > 64-lsb {
			return "", false, fmt.Errorf("invalid SBFIZ %q", disassembly)
		}
		return fields("compactSBFIZ64", "destination", match[1], "left", match[2], "shift", fmt.Sprint(lsb), "immediate", fmt.Sprintf("%#x", width)), false, nil
	}
	if match := unsignedDivide32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactUDiv32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := unsignedDivide64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactUDiv64", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := adds64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAdds64", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := adds32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAdds32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := subsRegister.FindStringSubmatch(disassembly); match != nil {
		op := "compactSubs32"
		if match[1] == "x" {
			op = "compactSubs64"
		}
		return fields(op, "destination", match[2], "left", match[3], "right", match[4]), false, nil
	}
	if match := subsImmediate.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[4])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid SUBS immediate %q", disassembly)
		}
		op := "compactSubsImm32"
		if match[1] == "x" {
			op = "compactSubsImm64"
		}
		return fields(op, "destination", match[2], "left", match[3], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := adc32.FindStringSubmatch(disassembly); match != nil {
		reg := func(value string) string {
			if value == "wzr" {
				return "31"
			}
			return strings.TrimPrefix(value, "w")
		}
		return fields("compactADC32", "destination", match[1], "left", reg(match[2]), "right", reg(match[3])), false, nil
	}
	if match := compareNegative64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCMN64", "left", match[1], "right", match[2]), false, nil
	}
	if match := compareNegativeLSL64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCMNLSL64", "left", match[1], "right", match[2], "shift", match[3]), false, nil
	}
	if match := compareNegativeImm32.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid immediate CMN %q", disassembly)
		}
		return fields("compactCMNImm32", "left", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := compareNegativeImm64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit immediate CMN %q", disassembly)
		}
		return fields("compactCMNImm64", "left", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := compareImmediate32.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid immediate CMP %q", disassembly)
		}
		return fields("compactCmpImm32", "left", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := compareImmediate64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit immediate CMP %q", disassembly)
		}
		return fields("compactCmpImm64", "left", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := conditionSetHI.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCSet32HI", "destination", match[1]), false, nil
	}
	if match := conditionSetLO.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCSet32LO", "destination", match[1]), false, nil
	}
	if match := conditionSetEQ.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCSet32EQ", "destination", match[1]), false, nil
	}
	if match := compareRegister32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCmp32", "left", match[1], "right", match[2]), false, nil
	}
	if match := compareRegister64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCmp64", "left", match[1], "right", match[2]), false, nil
	}
	if match := compareExtByte32.FindStringSubmatch(disassembly); match != nil {
		mode := "0"
		if match[3] == "sxtb" {
			mode = "1"
		}
		return fields("compactCmpExtByte32", "left", match[1], "right", match[2], "shift", mode), false, nil
	}
	if match := compareUXTH32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCmpUXTH32", "left", match[1], "right", match[2]), false, nil
	}
	if match := compareLSR32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCmpLSR32", "left", match[1], "right", match[2], "shift", match[3]), false, nil
	}
	if match := conditionalCompare.FindStringSubmatch(disassembly); match != nil {
		condition, ok := conditionConstant(match[5])
		nzcv, nzcvErr := number(match[4])
		if !ok || nzcvErr != nil || nzcv > 15 {
			return "", false, fmt.Errorf("invalid CCMP %q", disassembly)
		}
		width := match[1]
		if strings.HasPrefix(match[3], "#") {
			immediate, err := number(strings.TrimPrefix(match[3], "#"))
			if err != nil || immediate > 0xffff {
				return "", false, fmt.Errorf("invalid CCMP immediate %q", disassembly)
			}
			op := "compactCCmpImm32"
			if width == "x" {
				op = "compactCCmpImm64"
			}
			return fields(op, "left", match[2], "accumulator", fmt.Sprint(nzcv), "shift", condition, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
		}
		right, rightOK := registerNumber(match[3])
		if !rightOK || string(match[3][0]) != width {
			return "", false, fmt.Errorf("invalid CCMP register %q", disassembly)
		}
		op := "compactCCmpReg32"
		if width == "x" {
			op = "compactCCmpReg64"
		}
		return fields(op, "left", match[2], "right", right, "accumulator", fmt.Sprint(nzcv), "shift", condition), false, nil
	}
	if match := conditionalCompareNegative.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[2])
		nzcv, nzcvErr := number(match[3])
		condition, ok := conditionConstant(match[4])
		if immediateErr != nil || nzcvErr != nil || immediate > 0xffff || nzcv > 15 || !ok {
			return "", false, fmt.Errorf("invalid CCMN %q", disassembly)
		}
		return fields("compactCCmnImm32", "left", match[1], "accumulator", fmt.Sprint(nzcv), "shift", condition, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := andSetFlags.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAnds32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := andSetFlagsImmediate.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[3])
		if err != nil || immediate > 0xffffffff {
			return "", false, fmt.Errorf("invalid ANDS immediate %q", disassembly)
		}
		return fields("compactAndsImm32", append([]string{"destination", match[1], "left", match[2]}, immediate32Fields(immediate)...)...), false, nil
	}
	if match := bitClearSetFlags.FindStringSubmatch(disassembly); match != nil {
		destination, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid BICS %q", disassembly)
		}
		return fields("compactBics32", "destination", destination, "left", match[2], "right", match[3]), false, nil
	}
	if match := countLeadingZeroes.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCLZ32", "destination", match[1], "left", match[2]), false, nil
	}
	if match := andSetFlagsLSR.FindStringSubmatch(disassembly); match != nil {
		return fields("compactAndsLSR32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := bitClearSetFlagsLSR.FindStringSubmatch(disassembly); match != nil {
		destination, ok := registerNumber(match[1])
		if !ok {
			return "", false, fmt.Errorf("invalid shifted BICS %q", disassembly)
		}
		return fields("compactBicsLSR32", "destination", destination, "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := conditionalCompareNegative64.FindStringSubmatch(disassembly); match != nil {
		immediate, immediateErr := number(match[2])
		nzcv, nzcvErr := number(match[3])
		condition, ok := conditionConstant(match[4])
		if immediateErr != nil || nzcvErr != nil || immediate > 0xffff || nzcv > 15 || !ok {
			return "", false, fmt.Errorf("invalid 64-bit CCMN %q", disassembly)
		}
		return fields("compactCCmnImm64", "left", match[1], "accumulator", fmt.Sprint(nzcv), "shift", condition, "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := conditionSelectIncrement32.FindStringSubmatch(disassembly); match != nil {
		left, leftOK := registerNumber(match[2])
		right, rightOK := registerNumber(match[3])
		condition, conditionOK := conditionConstant(match[4])
		if !leftOK || !rightOK || !conditionOK {
			return "", false, fmt.Errorf("invalid CSINC %q", disassembly)
		}
		return fields("compactCSInc32", "destination", match[1], "left", left, "right", right, "shift", condition), false, nil
	}
	if match := testImmediate64.FindStringSubmatch(disassembly); match != nil {
		immediate, err := number(match[2])
		if err != nil || immediate > 0xffff {
			return "", false, fmt.Errorf("invalid 64-bit TST %q", disassembly)
		}
		return fields("compactTstImm64", "left", match[1], "immediate", fmt.Sprintf("%#x", immediate)), false, nil
	}
	if match := exclusiveOrNot32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactEon32", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := exclusiveOrNot64.FindStringSubmatch(disassembly); match != nil {
		return fields("compactEon64", "destination", match[1], "left", match[2], "right", match[3]), false, nil
	}
	if match := xorASR32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactXorASR32", "destination", match[1], "left", match[2], "right", match[3], "shift", match[4]), false, nil
	}
	if match := compareAndSwap.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCASAL32", "left", match[1], "right", match[2], "accumulator", match[3]), false, nil
	}
	if match := selectZeroEq32.FindStringSubmatch(disassembly); match != nil {
		return fields("compactCSELZeroEq32", "destination", match[1], "right", match[2]), false, nil
	}
	if match := conditionSet.FindStringSubmatch(disassembly); match != nil {
		canonical, ok := compactConditionConstant(match[2])
		if !ok {
			return "", false, fmt.Errorf("unsupported CSET condition %q", match[2])
		}
		switch canonical {
		case "compactConditionEQ":
			return fields("compactCSet32EQ", "destination", match[1]), false, nil
		case "compactConditionLO":
			return fields("compactCSet32LO", "destination", match[1]), false, nil
		case "compactConditionHI":
			return fields("compactCSet32HI", "destination", match[1]), false, nil
		default:
			return fields("compactCSet32", "destination", match[1], "shift", "uint8("+canonical+")"), false, nil
		}
	}
	if match := conditionSelect.FindStringSubmatch(disassembly); match != nil {
		left, leftOK := registerNumber(match[3])
		right, rightOK := registerNumber(match[4])
		condition, conditionOK := conditionConstant(match[5])
		if !leftOK || !rightOK || !conditionOK || match[1] != string(match[3][0]) || match[1] != string(match[4][0]) {
			return "", false, fmt.Errorf("invalid CSEL %q", disassembly)
		}
		op := "compactCSEL32"
		if match[1] == "x" {
			op = "compactCSEL64"
		}
		return fields(op, "destination", match[2], "left", left, "right", right, "shift", condition), false, nil
	}
	if branchAuth.MatchString(disassembly) {
		return "", true, nil
	}
	return "", false, fmt.Errorf("unsupported instruction %q", disassembly)
}

type annotatedInstruction struct {
	pc          uint64
	disassembly string
}

type annotatedBlock struct {
	name         string
	start        uint64
	instructions []annotatedInstruction
	returnTarget uint64
	stopTarget   uint64
}

func parseAnnotatedBlocks(source, prefix string) ([]annotatedBlock, error) {
	var blocks []annotatedBlock
	var current *annotatedBlock
	depth := 0
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		line := scanner.Text()
		if current == nil {
			match := blockFunction.FindStringSubmatch(line)
			if match == nil || !strings.HasPrefix(match[1], prefix) {
				continue
			}
			current = &annotatedBlock{name: match[1]}
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}
		if match := commentPattern.FindStringSubmatch(line); match != nil {
			pc, err := strconv.ParseUint(strings.TrimPrefix(match[1], "0x"), 16, 64)
			if err != nil {
				return nil, err
			}
			if len(current.instructions) == 0 {
				current.start = pc
			}
			current.instructions = append(current.instructions, annotatedInstruction{pc: pc, disassembly: match[2]})
		}
		if match := literalReturn.FindStringSubmatch(line); match != nil {
			target, err := number(match[1])
			if err != nil {
				return nil, err
			}
			current.returnTarget = target
		}
		if match := literalStopReturn.FindStringSubmatch(line); match != nil {
			target, err := number(match[1])
			if err != nil {
				return nil, err
			}
			current.stopTarget = target
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth == 0 {
			if len(current.instructions) != 0 {
				blocks = append(blocks, *current)
			}
			current = nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if current != nil {
		return nil, fmt.Errorf("unterminated generated block %s", current.name)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("input contains no functions with prefix %q", prefix)
	}
	var split []annotatedBlock
	for _, block := range blocks {
		split = append(split, splitAnnotatedCallBlocks(block)...)
	}
	return split, nil
}

// Generated source can place instructions after BL/BLRAA in the same logical
// function. A call is a CFG terminator whose return address is the next
// instruction, so preserve both halves as separate compact blocks.
func splitAnnotatedCallBlocks(block annotatedBlock) []annotatedBlock {
	start := 0
	var result []annotatedBlock
	for index, instruction := range block.instructions {
		if index == len(block.instructions)-1 {
			break
		}
		if !branchLink.MatchString(instruction.disassembly) &&
			!callRegister.MatchString(instruction.disassembly) &&
			!callRegisterZero.MatchString(instruction.disassembly) {
			continue
		}
		part := block
		part.start = block.instructions[start].pc
		part.instructions = append([]annotatedInstruction(nil), block.instructions[start:index+1]...)
		part.returnTarget = 0
		part.stopTarget = 0
		result = append(result, part)
		start = index + 1
	}
	if start == 0 {
		return []annotatedBlock{block}
	}
	if start < len(block.instructions) {
		part := block
		part.start = block.instructions[start].pc
		part.instructions = append([]annotatedInstruction(nil), block.instructions[start:]...)
		result = append(result, part)
	}
	return result
}

func compactTerminator(instruction annotatedInstruction) (string, error) {
	if match := branchDirect.FindStringSubmatch(instruction.disassembly); match != nil {
		return "terminator: compactBlockDirect, target: " + match[1], nil
	}
	if match := branchConditional.FindStringSubmatch(instruction.disassembly); match != nil {
		condition, ok := compactConditionConstant(match[1])
		if !ok {
			return "", fmt.Errorf("unsupported branch condition %q", match[1])
		}
		target, err := number(match[2])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("terminator: compactBlockConditional, condition: %s, target: %#x, alternate: %#x", condition, target, instruction.pc+4), nil
	}
	if match := branchLink.FindStringSubmatch(instruction.disassembly); match != nil {
		return "terminator: compactBlockCallDirect, target: " + match[1], nil
	}
	if match := branchCompareZero.FindStringSubmatch(instruction.disassembly); match != nil {
		condition := "compactConditionEQ"
		if match[1] == "cbnz" {
			condition = "compactConditionNE"
		}
		width := "32"
		if match[2] == "x" {
			width = "64"
		}
		return fmt.Sprintf("terminator: compactBlockCompareZero, condition: %s, register: %s, width: %s, target: %s, alternate: %#x", condition, match[3], width, match[4], instruction.pc+4), nil
	}
	if match := branchTestBit.FindStringSubmatch(instruction.disassembly); match != nil {
		condition := "compactConditionEQ"
		if match[1] == "tbnz" {
			condition = "compactConditionNE"
		}
		return fmt.Sprintf("terminator: compactBlockTestBit, condition: %s, register: %s, bit: %s, target: %s, alternate: %#x", condition, match[2], match[3], match[4], instruction.pc+4), nil
	}
	if match := branchRegister.FindStringSubmatch(instruction.disassembly); match != nil {
		return "terminator: compactBlockRegister, register: " + match[1], nil
	}
	if match := callRegister.FindStringSubmatch(instruction.disassembly); match != nil {
		return "terminator: compactBlockCallRegister, register: " + match[1], nil
	}
	if match := callRegisterZero.FindStringSubmatch(instruction.disassembly); match != nil {
		return "terminator: compactBlockCallRegister, register: " + match[1], nil
	}
	if returnRegister.MatchString(instruction.disassembly) {
		return "terminator: compactBlockReturn", nil
	}
	return "", fmt.Errorf("unsupported block terminator %q", instruction.disassembly)
}

type packedCompactInstruction struct {
	op                                    uint16
	destination, left, right, accumulator uint8
	shift                                 uint8
	immediate                             uint16
}

type packedCompactBlock struct {
	start                 uint64
	instructions          []packedCompactInstruction
	terminator, condition uint8
	register, width, bit  uint8
	target, alternate     uint64
}

var compactLiteralField = regexp.MustCompile(`([A-Za-z][A-Za-z0-9]*): ([^,}]+)`)

func compactLiteralNumber(value string) (uint64, error) {
	if strings.HasPrefix(value, "uint8(") && strings.HasSuffix(value, ")") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "uint8("), ")")
	}
	if condition, ok := runtimeCompactConditionNumbers[value]; ok {
		return uint64(condition), nil
	}
	return number(value)
}

func packedInstruction(literal string) (packedCompactInstruction, error) {
	var result packedCompactInstruction
	seen := make(map[string]bool)
	for _, match := range compactLiteralField.FindAllStringSubmatch(literal, -1) {
		name, value := match[1], match[2]
		if seen[name] {
			return result, fmt.Errorf("duplicate compact instruction field %q", name)
		}
		seen[name] = true
		if name == "op" {
			opcode, ok := runtimeCompactOpcodeNumbers[value]
			if !ok {
				return result, fmt.Errorf("unknown compact opcode %q", value)
			}
			result.op = opcode
			continue
		}
		numeric, err := compactLiteralNumber(value)
		if err != nil {
			return result, fmt.Errorf("invalid compact instruction field %s=%q", name, value)
		}
		switch name {
		case "destination", "left", "right", "accumulator", "shift":
			if numeric > 0xff {
				return result, fmt.Errorf("compact instruction field %s is too large", name)
			}
			pointer := map[string]*uint8{
				"destination": &result.destination, "left": &result.left, "right": &result.right,
				"accumulator": &result.accumulator, "shift": &result.shift,
			}[name]
			*pointer = uint8(numeric)
		case "immediate":
			if numeric > 0xffff {
				return result, fmt.Errorf("compact instruction immediate is too large")
			}
			result.immediate = uint16(numeric)
		default:
			return result, fmt.Errorf("unknown compact instruction field %q", name)
		}
	}
	if !seen["op"] {
		return result, fmt.Errorf("compact instruction has no opcode")
	}
	return result, nil
}

func packedBlock(start uint64, instructions []string, terminator string) (packedCompactBlock, error) {
	result := packedCompactBlock{start: start, instructions: make([]packedCompactInstruction, len(instructions))}
	for index, literal := range instructions {
		instruction, err := packedInstruction(literal)
		if err != nil {
			return result, fmt.Errorf("compact block %#x instruction %d: %w", start, index, err)
		}
		result.instructions[index] = instruction
	}
	seenTerminator := false
	for _, match := range compactLiteralField.FindAllStringSubmatch(terminator, -1) {
		name, value := match[1], match[2]
		if name == "terminator" {
			numeric, ok := runtimeCompactTerminatorNumbers[value]
			if !ok || numeric > 0xff {
				return result, fmt.Errorf("unknown compact terminator %q", value)
			}
			result.terminator, seenTerminator = uint8(numeric), true
			continue
		}
		numeric, err := compactLiteralNumber(value)
		if err != nil {
			return result, fmt.Errorf("invalid compact block field %s=%q", name, value)
		}
		switch name {
		case "condition", "register", "width", "bit":
			if numeric > 0xff {
				return result, fmt.Errorf("compact block field %s is too large", name)
			}
			pointer := map[string]*uint8{
				"condition": &result.condition, "register": &result.register,
				"width": &result.width, "bit": &result.bit,
			}[name]
			*pointer = uint8(numeric)
		case "target":
			result.target = numeric
		case "alternate":
			result.alternate = numeric
		default:
			return result, fmt.Errorf("unknown compact block field %q", name)
		}
	}
	if !seenTerminator {
		return result, fmt.Errorf("compact block %#x has no terminator", start)
	}
	return result, nil
}

func generateCompactCFG(name string, blocks []annotatedBlock, limit int, verboseSkips bool) ([]byte, []packedCompactBlock, int, map[string]int, error) {
	var literals []string
	var packed []packedCompactBlock
	skipped := 0
	reasons := make(map[string]int)
	for _, block := range blocks {
		if limit > 0 && len(packed) >= limit {
			break
		}
		if len(block.instructions) == 0 {
			skipped++
			reasons["empty block"]++
			continue
		}
		terminal := block.instructions[len(block.instructions)-1]
		body := block.instructions[:len(block.instructions)-1]
		terminator, err := compactTerminator(terminal)
		if err != nil && block.returnTarget != 0 {
			terminator = fmt.Sprintf("terminator: compactBlockDirect, target: %#x", block.returnTarget)
			body = block.instructions
			err = nil
		}
		if err != nil && block.stopTarget != 0 {
			terminator = fmt.Sprintf("terminator: compactBlockStopDirect, target: %#x", block.stopTarget)
			body = block.instructions
			err = nil
		}
		if err != nil {
			skipped++
			reason := "terminator " + strings.Fields(terminal.disassembly)[0]
			if verboseSkips {
				reason = "terminator " + terminal.disassembly
			}
			reasons[reason]++
			continue
		}
		expected := block.start
		var instructions []string
		compatible := true
		for _, entry := range body {
			if entry.pc != expected {
				compatible = false
				reasons["disjoint instruction addresses"]++
				break
			}
			literal, stop, err := compactInstruction(entry.disassembly)
			if err != nil || stop {
				compatible = false
				reason := "instruction " + strings.Fields(entry.disassembly)[0]
				if verboseSkips {
					reason = "instruction " + entry.disassembly
				}
				reasons[reason]++
				break
			}
			instructions = append(instructions, literal)
			expected += 4
		}
		terminalPC := terminal.pc
		if len(body) == len(block.instructions) {
			terminalPC += 4
		}
		if !compatible || terminalPC != expected {
			skipped++
			if compatible {
				reasons["disjoint terminator address"]++
			}
			continue
		}
		encodedBlock, err := packedBlock(block.start, instructions, terminator)
		if err != nil {
			return nil, nil, skipped, reasons, err
		}
		packed = append(packed, encodedBlock)
		if name != "" {
			literals = append(literals, fmt.Sprintf("%#x: {start: %#x, instructions: []compactInstruction{\n\t\t%s\n\t}, %s},", block.start, block.start, strings.Join(instructions, "\n\t\t"), terminator))
		}
	}
	if len(packed) == 0 {
		return nil, nil, skipped, reasons, fmt.Errorf("no generated blocks use the compact instruction set")
	}
	if name == "" {
		return nil, packed, skipped, reasons, nil
	}
	source := fmt.Sprintf("// Code generated by tools/compact-kernel; DO NOT EDIT.\npackage recovery\n\nvar %s = map[uint64]compactBlock{\n\t%s\n}\n", name, strings.Join(literals, "\n\t"))
	formatted, err := format.Source([]byte(source))
	return formatted, packed, skipped, reasons, err
}

func generateCompactCFGSource(name string, blocks []annotatedBlock, limit int, verboseSkips bool) ([]byte, int, map[string]int, error) {
	formatted, _, skipped, reasons, err := generateCompactCFG(name, blocks, limit, verboseSkips)
	return formatted, skipped, reasons, err
}

func pruneCompleteCFGSource(source, prefix string) ([]byte, error) {
	var output []string
	scanner := bufio.NewScanner(strings.NewReader(source))
	skippingSwitch, skippingFunction := false, false
	depth := 0
	for scanner.Scan() {
		line := scanner.Text()
		if skippingSwitch {
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth == 0 {
				skippingSwitch = false
			}
			continue
		}
		if skippingFunction {
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth == 0 {
				skippingFunction = false
			}
			continue
		}
		if strings.HasPrefix(line, "func "+prefix) {
			skippingFunction = true
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}
		if line == "\t\tswitch pc {" {
			output = append(output, "\t\treturn pc, blockCount, fmt.Errorf(\"bootstrap CFG reached unknown block %#x\", pc)")
			skippingSwitch = true
			depth = 1
			continue
		}
		output = append(output, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if skippingSwitch || skippingFunction {
		return nil, fmt.Errorf("unterminated generated CFG while pruning")
	}
	return format.Source([]byte(strings.Join(output, "\n") + "\n"))
}

func generateCompactSource(name string, annotated []annotatedInstruction) ([]byte, error) {
	if len(annotated) == 0 {
		return nil, fmt.Errorf("input contains no compact instructions")
	}
	start, expected := annotated[0].pc, annotated[0].pc
	var instructions, segments []string
	for _, entry := range annotated {
		if entry.pc != expected {
			segments = append(segments, fmt.Sprintf("{index: %d, address: %#x},", len(instructions), entry.pc))
		}
		literal, stop, err := compactInstruction(entry.disassembly)
		if err != nil {
			return nil, fmt.Errorf("%#x: %w", entry.pc, err)
		}
		expected = entry.pc + 4
		if !stop {
			instructions = append(instructions, literal)
		}
	}
	if len(instructions) == 0 {
		return nil, fmt.Errorf("input contains no compact instructions")
	}
	segmentSource := ""
	if len(segments) != 0 {
		segmentSource = "\n\tsegments: []compactSegment{\n\t\t" + strings.Join(segments, "\n\t\t") + "\n\t},"
	}
	source := fmt.Sprintf("// Code generated by tools/compact-kernel; DO NOT EDIT.\npackage recovery\n\nvar %s = compactKernel{\n\tstart: %#x,\n\tinstructions: []compactInstruction{\n\t\t%s\n\t},%s\n}\n", name, start, strings.Join(instructions, "\n\t\t"), segmentSource)
	return format.Source([]byte(source))
}

const (
	compactSeedProfileMagic          = "FPCFG1\x00\x00"
	compactSeedProfileVersion uint32 = 1
	maximumSeedProfileBytes          = 256 * 1024 * 1024
)

func compactProfileStarts(path string) (map[uint64]bool, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maximumSeedProfileBytes {
		return nil, fmt.Errorf("seed compact profile is too large")
	}
	if len(encoded) >= 2 && encoded[0] == 0x1f && encoded[1] == 0x8b {
		stream, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		decoded, readErr := io.ReadAll(io.LimitReader(stream, maximumSeedProfileBytes+1))
		closeErr := stream.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(decoded) > maximumSeedProfileBytes {
			return nil, fmt.Errorf("seed compact profile is too large")
		}
		encoded = decoded
	}
	if len(encoded) < 16+32 {
		return nil, fmt.Errorf("seed compact profile is truncated")
	}
	payload, checksum := encoded[:len(encoded)-32], encoded[len(encoded)-32:]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(checksum, digest[:]) {
		return nil, fmt.Errorf("seed compact profile checksum mismatch")
	}
	reader := bytes.NewReader(payload)
	var magic [8]byte
	var version, sectionCount uint32
	if _, err := io.ReadFull(reader, magic[:]); err != nil || string(magic[:]) != compactSeedProfileMagic ||
		binary.Read(reader, binary.LittleEndian, &version) != nil || version != compactSeedProfileVersion ||
		binary.Read(reader, binary.LittleEndian, &sectionCount) != nil || sectionCount == 0 || sectionCount > 255 {
		return nil, fmt.Errorf("invalid seed compact profile header")
	}
	starts := make(map[uint64]bool)
	seenSections := make(map[byte]bool)
	for range sectionCount {
		sectionID, err := reader.ReadByte()
		if err != nil || sectionID == 0 || seenSections[sectionID] {
			return nil, fmt.Errorf("invalid seed compact profile section")
		}
		seenSections[sectionID] = true
		var sectionReserved [7]byte
		var blockCount, reserved uint32
		if _, err := io.ReadFull(reader, sectionReserved[:]); err != nil || sectionReserved != [7]byte{} ||
			binary.Read(reader, binary.LittleEndian, &blockCount) != nil || blockCount == 0 ||
			binary.Read(reader, binary.LittleEndian, &reserved) != nil || reserved != 0 {
			return nil, fmt.Errorf("invalid seed compact profile section header")
		}
		previous := uint64(0)
		for index := uint32(0); index < blockCount; index++ {
			var address uint64
			var control [8]byte
			var target, alternate uint64
			var instructionCount uint32
			if err := binary.Read(reader, binary.LittleEndian, &address); err != nil || address == 0 || index != 0 && address <= previous {
				return nil, fmt.Errorf("invalid seed compact profile block address %#x after %#x in section %d at index %d", address, previous, sectionID, index)
			}
			if err := ioReadFull(reader, control[:]); err != nil || control[5] != 0 || control[6] != 0 || control[7] != 0 {
				return nil, fmt.Errorf("invalid seed compact profile block control at %#x", address)
			}
			if err := binary.Read(reader, binary.LittleEndian, &target); err != nil {
				return nil, fmt.Errorf("read seed compact profile target at %#x: %w", address, err)
			}
			if err := binary.Read(reader, binary.LittleEndian, &alternate); err != nil {
				return nil, fmt.Errorf("read seed compact profile alternate at %#x: %w", address, err)
			}
			if err := binary.Read(reader, binary.LittleEndian, &instructionCount); err != nil {
				return nil, fmt.Errorf("read seed compact profile instruction count at %#x: %w", address, err)
			}
			if err := binary.Read(reader, binary.LittleEndian, &reserved); err != nil || reserved != 0 {
				return nil, fmt.Errorf("invalid seed compact profile block header at %#x", address)
			}
			previous = address
			starts[address] = true
			instructionBytes := int64(instructionCount) * 10
			if instructionBytes < 0 || instructionBytes > int64(reader.Len()) {
				return nil, fmt.Errorf("seed compact profile instructions are truncated")
			}
			if _, err := reader.Seek(instructionBytes, io.SeekCurrent); err != nil {
				return nil, err
			}
		}
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("seed compact profile has trailing data")
	}
	return starts, nil
}

func marshalCompactBlocks(sectionID byte, blocks []packedCompactBlock) ([]byte, error) {
	if sectionID == 0 || len(blocks) == 0 || len(blocks) > int(^uint32(0)) {
		return nil, fmt.Errorf("invalid compact output geometry")
	}
	var payload bytes.Buffer
	payload.WriteString(compactSeedProfileMagic)
	_ = binary.Write(&payload, binary.LittleEndian, compactSeedProfileVersion)
	_ = binary.Write(&payload, binary.LittleEndian, uint32(1))
	payload.WriteByte(sectionID)
	payload.Write(make([]byte, 7))
	_ = binary.Write(&payload, binary.LittleEndian, uint32(len(blocks)))
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	previous := uint64(0)
	for index, block := range blocks {
		if block.start == 0 || index != 0 && block.start <= previous || len(block.instructions) > int(^uint32(0)) ||
			int(block.terminator) >= len(runtimeCompactTerminatorNumbers) || int(block.condition) >= len(runtimeCompactConditionNumbers) {
			return nil, fmt.Errorf("invalid compact output block %#x", block.start)
		}
		previous = block.start
		_ = binary.Write(&payload, binary.LittleEndian, block.start)
		payload.Write([]byte{block.terminator, block.condition, block.register, block.width, block.bit, 0, 0, 0})
		_ = binary.Write(&payload, binary.LittleEndian, block.target)
		_ = binary.Write(&payload, binary.LittleEndian, block.alternate)
		_ = binary.Write(&payload, binary.LittleEndian, uint32(len(block.instructions)))
		_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
		for _, instruction := range block.instructions {
			if instruction.op >= runtimeCompactOpcodeCount {
				return nil, fmt.Errorf("compact output block %#x has invalid opcode %d", block.start, instruction.op)
			}
			_ = binary.Write(&payload, binary.LittleEndian, instruction.op)
			payload.Write([]byte{instruction.destination, instruction.left, instruction.right, instruction.accumulator, instruction.shift, 0})
			_ = binary.Write(&payload, binary.LittleEndian, instruction.immediate)
		}
	}
	digest := sha256.Sum256(payload.Bytes())
	payload.Write(digest[:])
	var compressed bytes.Buffer
	stream, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	stream.Header.OS = 255
	if _, err := stream.Write(payload.Bytes()); err != nil {
		return nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

func ioReadFull(reader io.Reader, value []byte) error {
	_, err := io.ReadFull(reader, value)
	return err
}

type addressSetFlag map[uint64]bool

func (values addressSetFlag) String() string {
	addresses := make([]uint64, 0, len(values))
	for address := range values {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(left, right int) bool { return addresses[left] < addresses[right] })
	parts := make([]string, len(addresses))
	for index, address := range addresses {
		parts[index] = fmt.Sprintf("%#x", address)
	}
	return strings.Join(parts, ",")
}

func (values addressSetFlag) Set(value string) error {
	address, err := number(value)
	if err != nil || address == 0 || address%4 != 0 {
		return fmt.Errorf("invalid seed start %q", value)
	}
	values[address] = true
	return nil
}

func openMachoARM64eText(path string) ([]byte, uint64, error) {
	var file *macho.File
	fat, fatErr := macho.OpenFat(path)
	if fatErr == nil {
		defer fat.Close()
		for index := range fat.Arches {
			candidate := fat.Arches[index].File
			if candidate.Cpu == macho.CpuArm64 && uint32(candidate.SubCpu)&0x00ffffff == 2 {
				file = candidate
				if uint32(candidate.SubCpu)&0xff000000 == 0 {
					break
				}
			}
		}
	} else {
		thin, err := macho.Open(path)
		if err != nil {
			return nil, 0, err
		}
		defer thin.Close()
		file = thin
	}
	if file == nil || file.Cpu != macho.CpuArm64 || uint32(file.SubCpu)&0x00ffffff != 2 {
		return nil, 0, fmt.Errorf("Mach-O is not arm64e")
	}
	section := file.Section("__text")
	if section == nil || section.Seg != "__TEXT" {
		return nil, 0, fmt.Errorf("Mach-O has no __TEXT,__text section")
	}
	text, err := section.Data()
	return text, section.Addr, err
}

func machoPCRelativeTarget(instruction arm64asm.Inst, pc uint64) (uint64, bool) {
	for _, argument := range instruction.Args {
		relative, ok := argument.(arm64asm.PCRel)
		if !ok {
			continue
		}
		target := int64(pc) + int64(relative)
		if target < 0 {
			return 0, false
		}
		return uint64(target), true
	}
	return 0, false
}

func machoAuthenticatedBranch(word uint32) (string, bool) {
	target, modifier := (word>>5)&31, word&31
	switch word & 0xfffffc00 {
	case 0xd71f0800:
		return fmt.Sprintf("braa x%d, x%d", target, modifier), true
	case 0xd71f0c00:
		return fmt.Sprintf("brab x%d, x%d", target, modifier), true
	case 0xd73f0800:
		return fmt.Sprintf("blraa x%d, x%d", target, modifier), true
	case 0xd73f0c00:
		return fmt.Sprintf("blrab x%d, x%d", target, modifier), true
	}
	switch word & 0xfffffc1f {
	case 0xd61f081f:
		return fmt.Sprintf("braaz x%d", target), true
	case 0xd61f0c1f:
		return fmt.Sprintf("brabz x%d", target), true
	case 0xd63f081f:
		return fmt.Sprintf("blraaz x%d", target), true
	case 0xd63f0c1f:
		return fmt.Sprintf("blrabz x%d", target), true
	}
	switch word {
	case 0xd65f0bff:
		return "retaa", true
	case 0xd65f0fff:
		return "retab", true
	}
	return "", false
}

func machoInstructionText(data []byte, pc uint64) string {
	word := binary.LittleEndian.Uint32(data)
	if word&0xffe08000 == 0xce000000 { // EOR3 Vd.16B, Vn.16B, Vm.16B, Va.16B
		return fmt.Sprintf("eor3 v%d.16b, v%d.16b, v%d.16b, v%d.16b", word&31, (word>>5)&31, (word>>16)&31, (word>>10)&31)
	}
	if word&0xffffffe0 == 0xdac123e0 { // PACIZA Xd
		return fmt.Sprintf("paciza x%d", word&31)
	}
	if authenticated, ok := machoAuthenticatedBranch(word); ok {
		return authenticated
	}
	instruction, err := arm64asm.Decode(data)
	if err != nil {
		return fmt.Sprintf(".word %#x", word)
	}
	op := instruction.Op.String()
	target, hasTarget := machoPCRelativeTarget(instruction, pc)
	switch op {
	case "B":
		if !hasTarget {
			break
		}
		if condition, ok := instruction.Args[0].(arm64asm.Cond); ok {
			return fmt.Sprintf("b.%s #%#x", strings.ToLower(fmt.Sprint(condition)), target)
		}
		return fmt.Sprintf("b #%#x", target)
	case "BL":
		if hasTarget {
			return fmt.Sprintf("bl #%#x", target)
		}
	case "CBZ", "CBNZ":
		if hasTarget {
			return fmt.Sprintf("%s %s, #%#x", strings.ToLower(op), strings.ToLower(fmt.Sprint(instruction.Args[0])), target)
		}
	case "TBZ", "TBNZ":
		if hasTarget {
			return fmt.Sprintf("%s %s, %s, #%#x", strings.ToLower(op), strings.ToLower(fmt.Sprint(instruction.Args[0])), strings.ToLower(fmt.Sprint(instruction.Args[1])), target)
		}
	case "ADRP":
		if relative, ok := instruction.Args[1].(arm64asm.PCRel); ok {
			target := int64(pc&^0xfff) + int64(relative)
			if target >= 0 {
				return fmt.Sprintf("adrp %s, #%#x", strings.ToLower(fmt.Sprint(instruction.Args[0])), uint64(target))
			}
		}
	}
	result := strings.ToLower(arm64asm.GNUSyntax(instruction))
	result = strings.ReplaceAll(result, ", ", ",")
	result = strings.ReplaceAll(result, ",", ", ")
	result = gnuVectorRange.ReplaceAllStringFunc(result, func(value string) string {
		match := gnuVectorRange.FindStringSubmatch(value)
		start, startErr := strconv.Atoi(match[1])
		end, endErr := strconv.Atoi(match[2])
		if startErr != nil || endErr != nil || start < 0 || end < start || end > 31 || end-start >= 4 {
			return value
		}
		registers := make([]string, 0, end-start+1)
		for index := start; index <= end; index++ {
			registers = append(registers, fmt.Sprintf("v%d.16b", index))
		}
		return "{" + strings.Join(registers, ", ") + "}"
	})
	if match := gnuShiftedCompare.FindStringSubmatch(result); match != nil {
		immediate, immediateErr := number(match[3])
		shift, shiftErr := number(match[4])
		if immediateErr == nil && shiftErr == nil && shift <= 63 && immediate <= ^uint64(0)>>shift {
			return fmt.Sprintf("%s %s, #%#x", match[1], match[2], immediate<<shift)
		}
	}
	if match := gnuNegativeMov64.FindStringSubmatch(result); match != nil {
		value, err := strconv.ParseUint(match[2], 0, 64)
		if err == nil && value > math.MaxInt64 {
			return fmt.Sprintf("mov x%s, #-0x%x", match[1], uint64(0)-value)
		}
	}
	return result
}

func annotatedBlocksFromStarts(text []byte, textBase uint64, starts []uint64) []annotatedBlock {
	result := make([]annotatedBlock, 0, len(starts))
	textEnd := textBase + uint64(len(text))
	for index, start := range starts {
		if start < textBase || start >= textEnd || (start-textBase)%4 != 0 {
			continue
		}
		next := textEnd
		if index+1 < len(starts) {
			next = starts[index+1]
		}
		maxInstructions := uint64(512)
		// These exact-image indirect entries exceed the ordinary block bound.
		// Keep the larger bound local; truncated blocks still fail translation.
		if start == 0x100254df4 {
			maxInstructions = 4840
		}
		if start == 0x1002986d0 {
			maxInstructions = 2114
		}
		limit := min(next, start+maxInstructions*4)
		block := annotatedBlock{name: fmt.Sprintf("machoBlock%x", start), start: start}
		for pc := start; pc+4 <= limit; pc += 4 {
			offset := pc - textBase
			instruction := annotatedInstruction{pc: pc, disassembly: machoInstructionText(text[offset:offset+4], pc)}
			block.instructions = append(block.instructions, instruction)
			if _, err := compactTerminator(instruction); err == nil {
				break
			}
		}
		if len(block.instructions) != 0 {
			result = append(result, block)
		}
	}
	return result
}

func annotatedMachoBlocks(path string, seedStarts map[uint64]bool) ([]annotatedBlock, error) {
	text, textBase, err := openMachoARM64eText(path)
	if err != nil {
		return nil, err
	}
	layout, err := fairplay.InspectFairPlayRecoveryCodeLayout(path)
	if err != nil {
		return nil, err
	}
	startsSet := make(map[uint64]bool, len(layout.BasicBlocks)+len(seedStarts))
	for _, start := range layout.BasicBlocks {
		startsSet[start] = true
	}
	for start := range seedStarts {
		startsSet[start] = true
	}
	// Authenticated indirect edges reach these entries; static branch discovery
	// cannot recover its target. Restrict the additional boundary to this image.
	if layout.BinarySHA256 == fairplay.FairPlayBuild26A428Hash {
		startsSet[0x100254df4] = true
		startsSet[0x1002986d0] = true
	}
	starts := make([]uint64, 0, len(startsSet))
	for start := range startsSet {
		starts = append(starts, start)
	}
	sort.Slice(starts, func(left, right int) bool { return starts[left] < starts[right] })
	return annotatedBlocksFromStarts(text, textBase, starts), nil
}

func excludeAnnotatedBlocks(blocks []annotatedBlock, excluded map[uint64]bool) []annotatedBlock {
	if len(excluded) == 0 {
		return blocks
	}
	result := make([]annotatedBlock, 0, len(blocks))
	for _, block := range blocks {
		if !excluded[block.start] {
			result = append(result, block)
		}
	}
	return result
}

func main() {
	seedStartsFlag := make(addressSetFlag)
	machoPath := flag.String("macho", "", "extract CFG blocks directly from an arm64e Mach-O")
	seedProfilePath := flag.String("seed-profile", "", "compact profile whose verified starts split and are excluded from Mach-O output")
	flag.Var(seedStartsFlag, "seed-start", "additional verified block start to split and exclude (repeatable)")
	compactOutput := flag.Bool("compact-output", false, "write a compressed compact-profile section instead of Go source")
	sectionID := flag.Int("section-id", 1, "compact-output section identifier (1..255)")
	inputPath := flag.String("input", "", "generated Go kernel source")
	outputPath := flag.String("output", "", "generated compact profile Go file")
	name := flag.String("name", "", "Go variable name for the compact kernel")
	cfgPrefix := flag.String("cfg-prefix", "", "generated block function prefix (enables CFG mode)")
	limit := flag.Int("limit", 0, "maximum compatible CFG blocks to emit (zero means all)")
	verboseSkips := flag.Bool("verbose-skips", false, "report exact unsupported CFG instructions")
	prunedOutput := flag.String("pruned-output", "", "write CFG source without blocks replaced by a complete compact profile")
	pruneOnlyPrefix := flag.String("prune-only-prefix", "", "remove generated CFG switch and block functions with this prefix")
	flag.Parse()
	if (*inputPath == "") == (*machoPath == "") || *outputPath == "" ||
		!*compactOutput && *pruneOnlyPrefix == "" && !identifier.MatchString(*name) {
		fmt.Fprintln(os.Stderr, "exactly one of --input or --macho, plus --output and a valid --name, is required")
		os.Exit(2)
	}
	if (*seedProfilePath != "" || len(seedStartsFlag) != 0) && *machoPath == "" {
		fmt.Fprintln(os.Stderr, "--seed-profile and --seed-start require --macho")
		os.Exit(2)
	}
	if *compactOutput && (*machoPath == "" || *sectionID < 1 || *sectionID > 255) {
		fmt.Fprintln(os.Stderr, "--compact-output requires --macho and a section ID from 1 through 255")
		os.Exit(2)
	}
	if *machoPath != "" {
		seedStarts := make(map[uint64]bool, len(seedStartsFlag))
		for address := range seedStartsFlag {
			seedStarts[address] = true
		}
		var err error
		if *seedProfilePath != "" {
			profileStarts, profileErr := compactProfileStarts(*seedProfilePath)
			err = profileErr
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for address := range profileStarts {
				seedStarts[address] = true
			}
		}
		allBlocks, err := annotatedMachoBlocks(*machoPath, seedStarts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		blocks := excludeAnnotatedBlocks(allBlocks, seedStarts)
		outputName := *name
		if *compactOutput {
			outputName = ""
		}
		formatted, packed, skipped, reasons, err := generateCompactCFG(outputName, blocks, *limit, *verboseSkips)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "discovered %d Mach-O blocks; excluded %d verified starts; generated %d compact blocks; skipped %d unsafe or unsupported blocks\n",
			len(allBlocks), len(allBlocks)-len(blocks), len(packed), skipped)
		type reasonCount struct {
			reason string
			count  int
		}
		ordered := make([]reasonCount, 0, len(reasons))
		for reason, count := range reasons {
			ordered = append(ordered, reasonCount{reason, count})
		}
		sort.Slice(ordered, func(left, right int) bool {
			if ordered[left].count != ordered[right].count {
				return ordered[left].count > ordered[right].count
			}
			return ordered[left].reason < ordered[right].reason
		})
		if len(ordered) > 20 {
			ordered = ordered[:20]
		}
		for _, item := range ordered {
			fmt.Fprintf(os.Stderr, "%6d %s\n", item.count, item.reason)
		}
		if *compactOutput {
			formatted, err = marshalCompactBlocks(byte(*sectionID), packed)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			digest := sha256.Sum256(formatted)
			fmt.Fprintf(os.Stderr, "compact profile bytes=%d sha256=%x\n", len(formatted), digest)
		}
		if err := os.WriteFile(*outputPath, formatted, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	inputBytes, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *pruneOnlyPrefix != "" {
		pruned, err := pruneCompleteCFGSource(string(inputBytes), *pruneOnlyPrefix)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outputPath, pruned, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	var formatted []byte
	if *cfgPrefix != "" {
		var blocks []annotatedBlock
		blocks, err = parseAnnotatedBlocks(string(inputBytes), *cfgPrefix)
		if err == nil {
			var skipped int
			var reasons map[string]int
			formatted, skipped, reasons, err = generateCompactCFGSource(*name, blocks, *limit, *verboseSkips)
			if err == nil {
				fmt.Fprintf(os.Stderr, "generated %d compact blocks; skipped %d unsupported blocks\n", strings.Count(string(formatted), "start:"), skipped)
				type reasonCount struct {
					reason string
					count  int
				}
				ordered := make([]reasonCount, 0, len(reasons))
				for reason, count := range reasons {
					ordered = append(ordered, reasonCount{reason: reason, count: count})
				}
				sort.Slice(ordered, func(i, j int) bool {
					if ordered[i].count != ordered[j].count {
						return ordered[i].count > ordered[j].count
					}
					return ordered[i].reason < ordered[j].reason
				})
				for _, item := range ordered {
					fmt.Fprintf(os.Stderr, "%4d %s\n", item.count, item.reason)
				}
				if *prunedOutput != "" {
					if skipped != 0 {
						err = fmt.Errorf("refusing to prune CFG with %d unsupported blocks", skipped)
					} else {
						var pruned []byte
						pruned, err = pruneCompleteCFGSource(string(inputBytes), *cfgPrefix)
						if err == nil {
							err = os.WriteFile(*prunedOutput, pruned, 0o644)
						}
					}
				}
			}
		}
	} else {
		var annotated []annotatedInstruction
		scanner := bufio.NewScanner(strings.NewReader(string(inputBytes)))
		for scanner.Scan() {
			match := commentPattern.FindStringSubmatch(scanner.Text())
			if match == nil {
				continue
			}
			pc, parseErr := strconv.ParseUint(strings.TrimPrefix(match[1], "0x"), 16, 64)
			if parseErr != nil {
				err = parseErr
				break
			}
			annotated = append(annotated, annotatedInstruction{pc: pc, disassembly: match[2]})
		}
		if err == nil {
			err = scanner.Err()
		}
		if err == nil {
			formatted, err = generateCompactSource(*name, annotated)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outputPath, formatted, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func compactLogicalMaskFields(operation, destination, left string, value uint64) (string, bool, error) {
	kind, ok := map[string]int{"and": 0, "orr": 1, "eor": 2}[operation]
	if !ok {
		return "", false, fmt.Errorf("invalid logical operation")
	}
	for width := 2; width <= 64; width *= 2 {
		for ones := 1; ones < width; ones++ {
			mask := (uint64(1) << ones) - 1
			for step := width; step < 64; step *= 2 {
				mask |= mask << step
			}
			for rotation := 0; rotation < width; rotation++ {
				if bits.RotateLeft64(mask, -rotation) == value {
					return fields("compactLogicalMask64", "destination", destination, "left", left,
						"right", fmt.Sprint(rotation), "accumulator", fmt.Sprint(kind),
						"shift", fmt.Sprint(width), "immediate", fmt.Sprint(ones)), false, nil
				}
			}
		}
	}
	return "", false, fmt.Errorf("invalid ARM64 logical bitmask %#x", value)
}
