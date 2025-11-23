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
	public void LDX() {
		super.LDX();
		assertDisassemblesTo("LDX 0x12,Y", 0x18, 0xEE, 0x12);
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
	public void STX() {
		super.STX();
		assertDisassemblesTo("STX 0xa,Y", 0x18, 0xEF, 0x0A);
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

	// TODO(siggi): Test the Y-register instructions.
    @Test
	public void ABY() {
		assertDisassemblesTo("ABY", 0x18, 0x3A);
	}

	@Test
	public void InvalidOpCodes() {
		assertInvalidOpcode(0x00);
		assertInvalidOpcode(0x02);
		assertInvalidOpcode(0x03);

		assertInvalidOpcode(0x12);
		assertInvalidOpcode(0x13);
		assertInvalidOpcode(0x14);
		assertInvalidOpcode(0x15);
		assertInvalidOpcode(0x18);

		assertInvalidOpcode(0x1A);
		assertInvalidOpcode(0x1C);
		assertInvalidOpcode(0x1D);
		assertInvalidOpcode(0x1E);
		assertInvalidOpcode(0x1F);

		assertInvalidOpcode(0x41);
		assertInvalidOpcode(0x42);
		assertInvalidOpcode(0x45);
		assertInvalidOpcode(0x4B);
		assertInvalidOpcode(0x4E);

		assertInvalidOpcode(0x51);
		assertInvalidOpcode(0x52);
		assertInvalidOpcode(0x55);
		assertInvalidOpcode(0x5B);
		assertInvalidOpcode(0x5E);

		assertInvalidOpcode(0x61);
		assertInvalidOpcode(0x62);
		assertInvalidOpcode(0x65);
		assertInvalidOpcode(0x6B);

		assertInvalidOpcode(0x71);
		assertInvalidOpcode(0x72);
		assertInvalidOpcode(0x75);
		assertInvalidOpcode(0x7B);

		assertInvalidOpcode(0x87);
		assertInvalidOpcode(0x8F);

		assertInvalidOpcode(0xC7);
		assertInvalidOpcode(0xCD);
		assertInvalidOpcode(0xCF);
	}
}
