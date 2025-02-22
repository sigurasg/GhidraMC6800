// Copyright 2024 Sigurdur Asgeirsson <siggi@sort.is>
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;

public abstract class DisassemblyCommonTest extends AbstractIntegrationTest {
	protected DisassemblyCommonTest(String lang) {
		super(lang);
	}

	// The instructions are tested in the order of appearance in the
	// Motorola M6800 Programming Reference Manual.
	// http://www.bitsavers.org/components/motorola/6800/Motorola_M6800_Programming_Reference_Manual_M68PRM(D)_Nov76.pdf

	@Test
	public void ABA() {
		test(0x1B, "ABA");
	}

	@Test
	public void ADC() {
		test(0x89, "ADCA #0xa", 0x0A);
		test(0x99, "ADCA 0x000a", 0x0A);
		test(0xB9, "ADCA 0x1234", 0x12, 0x34);
		test(0xA9, "ADCA 0xa,X", 0x0A);

		test(0xC9, "ADCB #0xa", 0x0A);
		test(0xD9, "ADCB 0x000a", 0x0A);
		test(0xF9, "ADCB 0x1234", 0x12, 0x34);
		test(0xE9, "ADCB 0xa,X", 0x0A);
	}

	@Test
	public void ADD() {
		test(0x8B, "ADDA #0xa", 0x0A);
		test(0x9B, "ADDA 0x000a", 0x0A);
		test(0xBB, "ADDA 0x1234", 0x12, 0x34);
		test(0xAB, "ADDA 0xa,X", 0x0A);

		test(0xCB, "ADDB #0xa", 0x0A);
		test(0xDB, "ADDB 0x000a", 0x0A);
		test(0xFB, "ADDB 0x1234", 0x12, 0x34);
		test(0xEB, "ADDB 0xa,X", 0x0A);
	}

	@Test
	public void AND() {
		test(0x84, "ANDA #0xa", 0x0A);
		test(0x94, "ANDA 0x000a", 0x0A);
		test(0xB4, "ANDA 0x1234", 0x12, 0x34);
		test(0xA4, "ANDA 0xa,X", 0x0A);

		test(0xC4, "ANDB #0xa", 0x0A);
		test(0xD4, "ANDB 0x000a", 0x0A);
		test(0xF4, "ANDB 0x1234", 0x12, 0x34);
		test(0xE4, "ANDB 0xa,X", 0x0A);
	}

	@Test
	public void ASL() {
		test(0x48, "ASLA");
		test(0x58, "ASLB");
		test(0x78, "ASL 0x1234", 0x12, 0x34);
		test(0x68, "ASL 0x12,X", 0x12);
	}

	@Test
	public void ASR() {
		test(0x47, "ASRA");
		test(0x57, "ASRB");
		test(0x77, "ASR 0x1234", 0x12, 0x34);
		test(0x67, "ASR 0x12,X", 0x12);
	}

	@Test
	public void BCC() {
		test(0x24, "BCC 0x0022", 0x20);
	}

	@Test
	public void BCS() {
		test(0x25, "BCS 0x0022", 0x20);
	}

	@Test
	public void BEQ() {
		test(0x27, "BEQ 0x0022", 0x20);
	}

	@Test
	public void BGE() {
		test(0x2C, "BGE 0x0022", 0x20);
	}

	@Test
	public void BGT() {
		test(0x2E, "BGT 0x0022", 0x20);
	}

	@Test
	public void BHI() {
		test(0x22, "BHI 0x0022", 0x20);
	}

	@Test
	public void BIT() {
		test(0x85, "BITA #0xab", 0xAB);
		test(0x95, "BITA 0x00ab", 0xAB);
		test(0xB5, "BITA 0x1234", 0x12, 0x34);
		test(0xA5, "BITA 0xab,X", 0xAB);

		test(0xC5, "BITB #0xab", 0xAB);
		test(0xD5, "BITB 0x00ab", 0xAB);
		test(0xF5, "BITB 0x1234", 0x12, 0x34);
		test(0xE5, "BITB 0xab,X", 0xAB);
	}

	@Test
	public void BLE() {
		test(0x2F, "BLE 0x0022", 0x20);
	}

	@Test
	public void BLS() {
		test(0x23, "BLS 0x0022", 0x20);
	}

	@Test
	public void BLT() {
		test(0x2D, "BLT 0x0022", 0x20);
	}

	@Test
	public void BMI() {
		test(0x2B, "BMI 0x0022", 0x20);
	}

	@Test
	public void BNE() {
		test(0x26, "BNE 0x0022", 0x20);
	}

	@Test
	public void BPL() {
		test(0x2A, "BPL 0x0022", 0x20);
	}

	@Test
	public void BRA() {
		test(0x20, "BRA 0x0022", 0x20);
	}

	@Test
	public void BSR() {
		test(0x8D, "BSR 0x0022", 0x20);
	}

	@Test
	public void BVC() {
		test(0x28, "BVC 0x0022", 0x20);
	}

	@Test
	public void BVS() {
		test(0x29, "BVS 0x0022", 0x20);
	}

	@Test
	public void CBA() {
		test(0x11, "CBA");
	}

	@Test
	public void CLC() {
		test(0x0C, "CLC");
	}

	@Test
	public void CLI() {
		test(0x0E, "CLI");
	}

	@Test
	public void CLR() {
		test(0x4F, "CLRA");
		test(0x5F, "CLRB");
		test(0x7F, "CLR 0x1234", 0x12, 0x34);
		test(0x6F, "CLR 0x12,X", 0x12);
	}

	@Test
	public void CLV() {
		test(0x0A, "CLV");
	}

	@Test
	public void CMP() {
		test(0x81, "CMPA #0xab", 0xAB);
		test(0x91, "CMPA 0x00ab", 0xAB);
		test(0xB1, "CMPA 0x1234", 0x12, 0x34);
		test(0xA1, "CMPA 0xab,X", 0xAB);

		test(0xC1, "CMPB #0xab", 0xAB);
		test(0xD1, "CMPB 0x00ab", 0xAB);
		test(0xF1, "CMPB 0x1234", 0x12, 0x34);
		test(0xE1, "CMPB 0xab,X", 0xAB);
	}

	@Test
	public void COM() {
		test(0x43, "COMA");
		test(0x53, "COMB");
		test(0x73, "COM 0x1234", 0x12, 0x34);
		test(0x63, "COM 0x12,X", 0x12);
	}

	@Test
	public void CPX() {
		test(0x8C, "CPX #0x1234", 0x12, 0x34);
		test(0x9C, "CPX 0x00ab", 0xAB);
		test(0xBC, "CPX 0x1234", 0x12, 0x34);
		test(0xAC, "CPX 0x12,X", 0x12);
	}

	@Test
	public void DAA() {
		test(0x19, "DAA");
	}

	@Test
	public void DEC() {
		test(0x4A, "DECA");
		test(0x5A, "DECB");
		test(0x7A, "DEC 0x1234", 0x12, 0x34);
		test(0x6A, "DEC 0x12,X", 0x12);
	}

	@Test
	public void DES() {
		test(0x34, "DES");
	}

	@Test
	public void DEX() {
		test(0x09, "DEX");
	}

	@Test
	public void EOR() {
		test(0x88, "EORA #0xab", 0xAB);
		test(0x98, "EORA 0x00ab", 0xAB);
		test(0xB8, "EORA 0x1234", 0x12, 0x34);
		test(0xA8, "EORA 0xab,X", 0xAB);

		test(0xC8, "EORB #0xab", 0xAB);
		test(0xD8, "EORB 0x00ab", 0xAB);
		test(0xF8, "EORB 0x1234", 0x12, 0x34);
		test(0xE8, "EORB 0xab,X", 0xAB);
	}

	@Test
	public void INC() {
		test(0x4C, "INCA");
		test(0x5C, "INCB");
		test(0x7C, "INC 0x1234", 0x12, 0x34);
		test(0x6C, "INC 0x12,X", 0x12);
	}

	@Test
	public void INS() {
		test(0x31, "INS");
	}

	@Test
	public void INX() {
		test(0x08, "INX");
	}

	@Test
	public void JMP() {
		test(0x7E, "JMP 0x1234", 0x12, 0x34);
		test(0x6E, "JMP 0x12,X", 0x12);
	}

	@Test
	public void JSR() {
		test(0xBD, "JSR 0x1234", 0x12, 0x34);
		test(0xAD, "JSR 0x12,X", 0x12);
	}

	@Test
	public void LDA() {
		test(0x86, "LDAA #0xab", 0xAB);
		test(0x96, "LDAA 0x00ab", 0xAB);
		test(0xB6, "LDAA 0x1234", 0x12, 0x34);
		test(0xA6, "LDAA 0xab,X", 0xAB);

		test(0xC6, "LDAB #0xab", 0xAB);
		test(0xD6, "LDAB 0x00ab", 0xAB);
		test(0xF6, "LDAB 0x1234", 0x12, 0x34);
		test(0xE6, "LDAB 0xab,X", 0xAB);
	}

	@Test
	public void LDS() {
		test(0x8E, "LDS #0x1234", 0x12, 0x34);
		test(0x9E, "LDS 0x00ab", 0xAB);
		test(0xBE, "LDS 0x1234", 0x12, 0x34);
		test(0xAE, "LDS 0x12,X", 0x12);
	}

	@Test
	public void LDX() {
		test(0xCE, "LDX #0x1234", 0x12, 0x34);
		test(0xDE, "LDX 0x00ab", 0xAB);
		test(0xFE, "LDX 0x1234", 0x12, 0x34);
		test(0xEE, "LDX 0x12,X", 0x12);
	}

	@Test
	public void LSR() {
		test(0x44, "LSRA");
		test(0x54, "LSRB");
		test(0x74, "LSR 0x1234", 0x12, 0x34);
		test(0x64, "LSR 0x12,X", 0x12);
	}

	@Test
	public void NEG() {
		test(0x40, "NEGA");
		test(0x50, "NEGB");
		test(0x70, "NEG 0x1234", 0x12, 0x34);
		test(0x60, "NEG 0x12,X", 0x12);
	}

	@Test
	public void NOP() {
		test(0x01, "NOP");
	}

	@Test
	public void ORA() {
		test(0x8A, "ORAA #0xab", 0xAB);
		test(0x9A, "ORAA 0x00ab", 0xAB);
		test(0xBA, "ORAA 0x1234", 0x12, 0x34);
		test(0xAA, "ORAA 0xab,X", 0xAB);

		test(0xCA, "ORAB #0xab", 0xAB);
		test(0xDA, "ORAB 0x00ab", 0xAB);
		test(0xFA, "ORAB 0x1234", 0x12, 0x34);
		test(0xEA, "ORAB 0xab,X", 0xAB);
	}

	@Test
	public void PSH() {
		test(0x36, "PSHA");
		test(0x37, "PSHB");
	}

	@Test
	public void PUL() {
		test(0x32, "PULA");
		test(0x33, "PULB");
	}

	@Test
	public void ROL() {
		test(0x49, "ROLA");
		test(0x59, "ROLB");
		test(0x79, "ROL 0x1234", 0x12, 0x34);
		test(0x69, "ROL 0x12,X", 0x12);
	}

	@Test
	public void ROR() {
		test(0x46, "RORA");
		test(0x56, "RORB");
		test(0x76, "ROR 0x1234", 0x12, 0x34);
		test(0x66, "ROR 0x12,X", 0x12);
	}

	@Test
	public void RTI() {
		test(0x3B, "RTI");
	}

	@Test
	public void RTS() {
		test(0x39, "RTS");
	}

	@Test
	public void SBA() {
		test(0x10, "SBA");
	}

	@Test
	public void SBC() {
		test(0x82, "SBCA #0xa", 0x0A);
		test(0x92, "SBCA 0x000a", 0x0A);
		test(0xB2, "SBCA 0x1234", 0x12, 0x34);
		test(0xA2, "SBCA 0xa,X", 0x0A);

		test(0xC2, "SBCB #0xa", 0x0A);
		test(0xD2, "SBCB 0x000a", 0x0A);
		test(0xF2, "SBCB 0x1234", 0x12, 0x34);
		test(0xE2, "SBCB 0xa,X", 0x0A);
	}

	@Test
	public void SEC() {
		test(0x0D, "SEC");
	}

	@Test
	public void SEI() {
		test(0x0F, "SEI");
	}

	@Test
	public void SEV() {
		test(0x0B, "SEV");
	}

	@Test
	public void STA() {
		test(0x97, "STAA 0x000a", 0x0A);
		test(0xB7, "STAA 0x1234", 0x12, 0x34);
		test(0xA7, "STAA 0xa,X", 0x0A);

		test(0xD7, "STAB 0x000a", 0x0A);
		test(0xF7, "STAB 0x1234", 0x12, 0x34);
		test(0xE7, "STAB 0xa,X", 0x0A);
	}

	public void STS() {
		test(0x9F, "STX 0x000a", 0x0A);
		test(0xBF, "STX 0x1234", 0x12, 0x34);
		test(0xAF, "STX 0xa,X", 0x0A);
	}

	public void STX() {
		test(0xDF, "STX 0x000a", 0x0A);
		test(0xFF, "STX 0x1234", 0x12, 0x34);
		test(0xEF, "STX 0xa,X", 0x0A);
	}

	@Test
	public void SUB() {
		test(0x80, "SUBA #0xa", 0x0A);
		test(0x90, "SUBA 0x000a", 0x0A);
		test(0xB0, "SUBA 0x1234", 0x12, 0x34);
		test(0xA0, "SUBA 0xa,X", 0x0A);

		test(0xC0, "SUBB #0xa", 0x0A);
		test(0xD0, "SUBB 0x000a", 0x0A);
		test(0xF0, "SUBB 0x1234", 0x12, 0x34);
		test(0xE0, "SUBB 0xa,X", 0x0A);
	}

	@Test
	public void SWI() {
		test(0x3F, "SWI");
	}

	@Test
	public void TAB() {
		test(0x16, "TAB");
	}

	@Test
	public void TAP() {
		test(0x06, "TAP");
	}

	@Test
	public void TBA() {
		test(0x17, "TBA");
	}

	@Test
	public void TPA() {
		test(0x07, "TPA");
	}

	@Test
	public void TST() {
		test(0x4D, "TSTA");
		test(0x5D, "TSTB");
		test(0x7D, "TST 0x1234", 0x12, 0x34);
		test(0x6D, "TST 0x12,X", 0x12);
	}

	@Test
	public void TSX() {
		test(0x30, "TSX");
	}

	@Test
	public void TXS() {
		test(0x35, "TXS");
	}

	@Test
	public void WAI() {
		test(0x3E, "WAI");
	}

	protected void assertInvalidOpcode(int opCode) {
		byte[] code = new byte[] { (byte) opCode, (byte) 0x12, (byte) 0x34 };
		CodeUnit codeUnit = disassemble(code);
		assertTrue(codeUnit instanceof Data);
	}

	protected void test(int opCode, String expected, int... args) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		stream.write(opCode);
		for (int arg : args) {
			stream.write(arg);
		}

		byte[] bytes = stream.toByteArray();
		CodeUnit codeUnit = disassemble(bytes);
		assertTrue(codeUnit instanceof Instruction);
		assertNotNull(codeUnit);
		assertEquals(expected, codeUnit.toString());
		assertEquals(bytes.length, codeUnit.getLength());
	}
}
