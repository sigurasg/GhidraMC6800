// Copyright 2025 Sigurdur Asgeirsson <siggi@sort.is>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package is.sort.mc6800;

import org.junit.jupiter.api.Test;

public class DisassemblyMC68HC11Test extends DisassemblyMC6801CommonTest {
	public DisassemblyMC68HC11Test() {
		super("MC68HC11:BE:16:default");
	}

	// Test the indexed,Y addressing mode for the 6800 instructions.
	@Test
	public void ADC() {
		super.ADC();
		assertDisassemblesTo("ADCA 0xa,Y", 0x18, 0xA9, 0x0A);
		assertDisassemblesTo("ADCB 0xa,Y", 0x18, 0xE9, 0x0A);
	}

	@Test
	public void ADD() {
		super.ADD();
		assertDisassemblesTo("ADDA 0xa,Y", 0x18, 0xAB, 0x0A);
		assertDisassemblesTo("ADDB 0xa,Y", 0x18, 0xEB, 0x0A);
	}

	@Test
	public void AND() {
		super.AND();
		assertDisassemblesTo("ANDA 0xa,Y", 0x18, 0xA4, 0x0A);
		assertDisassemblesTo("ANDB 0xa,Y", 0x18, 0xE4, 0x0A);
	}

	@Test
	public void ASL() {
		super.ASL();
		assertDisassemblesTo("ASL 0x12,Y", 0x18, 0x68, 0x12);
	}

	@Test
	public void ASR() {
		assertDisassemblesTo("ASR 0x12,Y", 0x18, 0x67, 0x12);
	}

	@Test
	public void BIT() {
		super.BIT();
		assertDisassemblesTo("BITA 0xab,Y", 0x18, 0xA5, 0xAB);
		assertDisassemblesTo("BITB 0xab,Y", 0x18, 0xE5, 0xAB);
	}

	@Test
	public void CLR() {
		super.CLR();
		assertDisassemblesTo("CLR 0x12,Y", 0x18, 0x6F, 0x12);
	}

	@Test
	public void CMP() {
		super.CMP();
		assertDisassemblesTo("CMPA 0xab,Y", 0x18, 0xA1, 0xAB);
		assertDisassemblesTo("CMPB 0xab,Y", 0x18, 0xE1, 0xAB);
	}

	@Test
	public void COM() {
		super.COM();
		assertDisassemblesTo("COM 0x12,Y", 0x18, 0x63, 0x12);
	}

	@Test
	public void DEC() {
		super.DEC();
		assertDisassemblesTo("DEC 0x12,Y", 0x18, 0x6A, 0x12);
	}

	@Test
	public void EOR() {
		super.EOR();
		assertDisassemblesTo("EORA 0xab,Y", 0x18, 0xA8, 0xAB);
		assertDisassemblesTo("EORB 0xab,Y", 0x18, 0xE8, 0xAB);
	}

	@Test
	public void INC() {
		super.INC();
		assertDisassemblesTo("INC 0x12,Y", 0x18, 0x6C, 0x12);
	}

	@Test
	public void JMP() {
		super.JMP();
		assertDisassemblesTo("JMP 0x12,Y", 0x18, 0x6E, 0x12);
	}

	@Test
	public void JSR() {
		super.JSR();
		assertDisassemblesTo("JSR 0x12,Y", 0x18, 0xAD, 0x12);
	}

	@Test
	public void LDA() {
		super.LDA();
		assertDisassemblesTo("LDAA 0xab,Y", 0x18, 0xA6, 0xAB);
		assertDisassemblesTo("LDAB 0xab,Y", 0x18, 0xE6, 0xAB);
	}

	@Test
	public void LDS() {
		super.LDS();
		assertDisassemblesTo("LDS 0x12,Y", 0x18, 0xAE, 0x12);
	}

	@Test
	public void LSR() {
		super.LSR();
		assertDisassemblesTo("LSR 0x12,Y", 0x18, 0x64, 0x12);
	}

	@Test
	public void NEG() {
		super.NEG();
		assertDisassemblesTo("NEG 0x12,Y", 0x18, 0x60, 0x12);
	}

	@Test
	public void ORA() {
		super.ORA();
		assertDisassemblesTo("ORAA 0xab,Y", 0x18, 0xAA, 0xAB);
		assertDisassemblesTo("ORAB 0xab,Y", 0x18, 0xEA, 0xAB);
	}

	@Test
	public void ROL() {
		super.ROL();
		assertDisassemblesTo("ROL 0x12,Y", 0x18, 0x69, 0x12);
	}

	@Test
	public void ROR() {
		super.ROR();
		assertDisassemblesTo("ROR 0x12,Y", 0x18, 0x66, 0x12);
	}

	@Test
	public void SBC() {
		super.SBC();
		assertDisassemblesTo("SBCA 0xa,Y", 0x18, 0xA2, 0x0A);
		assertDisassemblesTo("SBCB 0xa,Y", 0x18, 0xE2, 0x0A);
	}

	@Test
	public void STA() {
		super.STA();
		assertDisassemblesTo("STAA 0xa,Y", 0x18, 0xA7, 0x0A);
		assertDisassemblesTo("STAB 0xa,Y", 0x18, 0xE7, 0x0A);
	}

	@Test
	public void STS() {
		super.STS();
		assertDisassemblesTo("STS 0xa,Y", 0x18, 0xAF, 0x0A);
	}

	@Test
	public void SUB() {
		super.SUB();
		assertDisassemblesTo("SUBA 0xa,Y", 0x18, 0xA0, 0x0A);
		assertDisassemblesTo("SUBB 0xa,Y", 0x18, 0xE0, 0x0A);
	}

	@Test
	public void TST() {
		super.TST();
		assertDisassemblesTo("TST 0x12,Y", 0x18, 0x6D, 0x12);
	}

	// Test the 6801 specific imm,Y instructions.
	@Test
	public void ADDD() {
		super.ADDD();
		assertDisassemblesTo("ADDD 0xab,Y", 0x18, 0xE3, 0xAB);
	}

	@Test
	public void LDD() {
		super.LDD();
		assertDisassemblesTo("LDD 0xab,Y", 0x18, 0xEC, 0xAB);
	}

	@Test
	public void STD() {
		super.STD();
		assertDisassemblesTo("STD 0xab,Y", 0x18, 0xED, 0xAB);
	}

	@Test
	public void SUBD() {
		super.SUBD();
		assertDisassemblesTo("SUBD 0xab,Y", 0x18, 0xA3, 0xAB);
	}

	// The 6800 Y-specific instructions.
	@Test
	public void INY() {
		assertDisassemblesTo("INY", 0x18, 0x08);
	}

	@Test
	public void TSY() {
		assertDisassemblesTo("TSY", 0x18, 0x30);
	}

	@Test
	public void TYS() {
		assertDisassemblesTo("TYS", 0x18, 0x35);
	}

	@Test
	public void CPY() {
		assertDisassemblesTo("CPY #0x1234", 0x18, 0x8C, 0x12, 0x34);
		assertDisassemblesTo("CPY 0x00ab", 0x18, 0x9C, 0xAB);
		assertDisassemblesTo("CPY 0x1234", 0x18, 0xBC, 0x12, 0x34);
		assertDisassemblesTo("CPY 0x12,Y", 0x18, 0xAC, 0x12);
		assertDisassemblesTo("CPY 0x12,X", 0x1A, 0xAC, 0x12);
	}

	@Test
	public void LDY() {
		assertDisassemblesTo("LDY #0x1234", 0x18, 0xCE, 0x12, 0x34);
		assertDisassemblesTo("LDY 0x00ab", 0x18, 0xDE, 0xAB);
		assertDisassemblesTo("LDY 0x1234", 0x18, 0xFE, 0x12, 0x34);
		assertDisassemblesTo("LDY 0x12,Y", 0x18, 0xEE, 0x12);
		assertDisassemblesTo("LDY 0x12,X", 0x1A, 0xEE, 0x12);
	}

	@Test
	public void STY() {
		assertDisassemblesTo("STY 0x000a", 0x18, 0xDF, 0x0A);
		assertDisassemblesTo("STY 0x1234", 0x18, 0xFF, 0x12, 0x34);
		assertDisassemblesTo("STY 0xa,Y", 0x18, 0xEF, 0x0A);
		assertDisassemblesTo("STY 0xa,X", 0x1A, 0xEF, 0x0A);
	}

	// Test 6801 Y-specific opcodes.
	@Test
	public void ABY() {
		assertDisassemblesTo("ABY", 0x18, 0x3A);
	}

	@Test
	public void PSHY() {
		assertDisassemblesTo("PSHY", 0x18, 0x3C);
	}

	@Test
	public void PULY() {
		assertDisassemblesTo("PULY", 0x18, 0x38);
	}

	// Test 68HC11 specific instructions.
	@Test
	public void TEST() {
		assertDisassemblesTo("TEST", 0x00);
	}

	@Test
	public void IDIV() {
		assertDisassemblesTo("IDIV", 0x02);
	}

	@Test
	public void FDIV() {
		assertDisassemblesTo("FDIV", 0x03);
	}

	@Test
	public void BRSET() {
		// TODO(siggi): How to coerce MASK to be a byte?
		assertDisassemblesTo("BRSET 0x0012 0x23 0x0038", 0x12, 0x12, 0x23, 0x34);
		assertDisassemblesTo("BRSET 0x12,X 0x23 0x0038", 0x1E, 0x12, 0x23, 0x34);
		assertDisassemblesTo("BRSET 0x12,Y 0x23 0x0039", 0x18, 0x1E, 0x12, 0x23, 0x34);
	}

	@Test
	public void BRCLR() {
		assertDisassemblesTo("BRCLR 0x0012 0x23 0x0038", 0x13, 0x12, 0x23, 0x34);
		assertDisassemblesTo("BRCLR 0x12,X 0x23 0x0038", 0x1F, 0x12, 0x23, 0x34);
		assertDisassemblesTo("BRCLR 0x12,Y 0x23 0x0039", 0x18, 0x1F, 0x12, 0x23, 0x34);
	}

	@Test
	public void BSET() {
		assertDisassemblesTo("BSET 0x0012 0x23", 0x14, 0x12, 0x23);
		assertDisassemblesTo("BSET 0x12,X 0x23", 0x1C, 0x12, 0x23);
		assertDisassemblesTo("BSET 0x12,Y 0x23", 0x18, 0x1C, 0x12, 0x23);
	}

	@Test
	public void BCLR() {
		assertDisassemblesTo("BCLR 0x0012 0x23", 0x15, 0x12, 0x23);
		assertDisassemblesTo("BCLR 0x12,X 0x23", 0x1D, 0x12, 0x23);
		assertDisassemblesTo("BCLR 0x12,Y 0x23", 0x18, 0x1D, 0x12, 0x23);
	}
	
	@Test
	public void CPD() {
		assertDisassemblesTo("CPD #0x1234", 0x1A, 0x83, 0x12, 0x34);
		assertDisassemblesTo("CPD 0x00ab", 0x1A, 0x93, 0xAB);
		assertDisassemblesTo("CPD 0x1234", 0x1A, 0xB3, 0x12, 0x34);
		assertDisassemblesTo("CPD 0x12,X", 0x1A, 0xA3, 0x12);
		assertDisassemblesTo("CPD 0x12,Y", 0xCD, 0xA3, 0x12);
	}

	@Test
	public void CPX() {
		super.CPX();
		assertDisassemblesTo("CPX 0x12,Y", 0xCD, 0xAC, 0x12);
	}

	public void LDX() {
		super.LDX();
		assertDisassemblesTo("LDX 0x12,Y", 0xCD, 0xEE, 0x12);
	}

	public void STX() {
		super.STX();
		assertDisassemblesTo("STX 0x12,Y", 0xCD, 0xEF, 0x12);
	}

	@Test
	public void Page0OpCodes() {
		Integer[] invalidOpcodes = {
			0x18, 0x1A,
			0x41, 0x42, 0x45, 0x4B, 0x4E,
			0x51, 0x52, 0x55, 0x5B, 0x5E,
			0x61, 0x62, 0x65, 0x6B,
			0x71, 0x72, 0x75, 0x7B,
			0x87,
			0xC7, 0xCD
		};
		assertValidOpcodes(complementOpcodes(invalidOpcodes));
		assertInvaldOpcodes(invalidOpcodes);
	}

	@Test
	public void Page1OpCodes() {
		Integer[] validOpcodes = {
			0x08, 0x09,
			0x1C, 0x1D, 0x1E, 0x1F,
			0x30, 0x35, 0x38, 0x3A, 0x3C,
			0x60, 0x63, 0x64, 0x66, 0x67, 0x68, 0x69, 0x6A, 0X6C, 0x6D, 0x6E, 0x6F,
			0x8C, 0x8F,
			0x9C,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
			0xAE, 0xAF,
			0xBC,
			0xCE,
			0xDE, 0xDF,
			0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
			0xEE, 0xEF,
			0xFE, 0xFF
		};
		assertValidOpcodes(0x18, validOpcodes);
		assertInvaldOpcodes(0x18, complementOpcodes(validOpcodes));
	}

	@Test
	public void Page2OpCodes() {
		Integer[] validOpcodes = {
			0x83,
			0x93,
			0xA3, 0xAC,
			0xB3,
			0xEE, 0xEF,
		};
		assertValidOpcodes(0x1A, validOpcodes);
		assertInvaldOpcodes(0x1A, complementOpcodes(validOpcodes));
	}

	@Test
	public void Page3OpCodes() {
		Integer[] validOpcodes = {
			0xA3, 0xAC,
			0xEE, 0xEF,
		};
		assertValidOpcodes(0xCD, validOpcodes);
		assertInvaldOpcodes(0xCD, complementOpcodes(validOpcodes));
	}

	private void assertInvaldOpcodes(int prefix, Integer[] invalidOpcodes) {
		for (int opcode : invalidOpcodes) {
			assertInvalidOpcode(prefix, opcode);
		}
	}

	private void assertValidOpcodes(int prefix, Integer[] validOpcodes) {
		for (int opcode : validOpcodes) {
			assertValidOpcode(prefix, opcode);
		}
	}
}
