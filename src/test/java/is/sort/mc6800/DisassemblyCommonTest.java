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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

import db.Transaction;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public abstract class DisassemblyCommonTest extends AbstractIntegrationTest {
	protected DisassemblyCommonTest(String lang) {
		super(lang);
	}

	// The instructions are tested in the order of appearance in the
	// Motorola M6800 Programming Reference Manual.
	// http://www.bitsavers.org/components/motorola/6800/Motorola_M6800_Programming_Reference_Manual_M68PRM(D)_Nov76.pdf

	@Test
	public void ABA() {
		assertDisassemblesTo("ABA", 0x1B);
	}

	@Test
	public void ADC() {
		assertDisassemblesTo("ADCA #0xa", 0x89, 0x0A);
		assertDisassemblesTo("ADCA 0x000a", 0x99, 0x0A);
		assertDisassemblesTo("ADCA 0x1234", 0xB9, 0x12, 0x34);
		assertDisassemblesTo("ADCA 0xa,X", 0xA9, 0x0A);

		assertDisassemblesTo("ADCB #0xa", 0xC9, 0x0A);
		assertDisassemblesTo("ADCB 0x000a", 0xD9, 0x0A);
		assertDisassemblesTo("ADCB 0x1234", 0xF9, 0x12, 0x34);
		assertDisassemblesTo("ADCB 0xa,X", 0xE9, 0x0A);
	}

	@Test
	public void ADD() {
		assertDisassemblesTo("ADDA #0xa", 0x8B, 0x0A);
		assertDisassemblesTo("ADDA 0x000a", 0x9B, 0x0A);
		assertDisassemblesTo("ADDA 0x1234", 0xBB, 0x12, 0x34);
		assertDisassemblesTo("ADDA 0xa,X", 0xAB, 0x0A);

		assertDisassemblesTo("ADDB #0xa", 0xCB, 0x0A);
		assertDisassemblesTo("ADDB 0x000a", 0xDB, 0x0A);
		assertDisassemblesTo("ADDB 0x1234", 0xFB, 0x12, 0x34);
		assertDisassemblesTo("ADDB 0xa,X", 0xEB, 0x0A);
	}

	@Test
	public void AND() {
		assertDisassemblesTo("ANDA #0xa", 0x84, 0x0A);
		assertDisassemblesTo("ANDA 0x000a", 0x94, 0x0A);
		assertDisassemblesTo("ANDA 0x1234", 0xB4, 0x12, 0x34);
		assertDisassemblesTo("ANDA 0xa,X", 0xA4, 0x0A);

		assertDisassemblesTo("ANDB #0xa", 0xC4, 0x0A);
		assertDisassemblesTo("ANDB 0x000a", 0xD4, 0x0A);
		assertDisassemblesTo("ANDB 0x1234", 0xF4, 0x12, 0x34);
		assertDisassemblesTo("ANDB 0xa,X", 0xE4, 0x0A);
	}

	@Test
	public void ASL() {
		assertDisassemblesTo("ASLA", 0x48);
		assertDisassemblesTo("ASLB", 0x58);
		assertDisassemblesTo("ASL 0x1234", 0x78, 0x12, 0x34);
		assertDisassemblesTo("ASL 0x12,X", 0x68, 0x12);
	}

	@Test
	public void ASR() {
		assertDisassemblesTo("ASRA", 0x47);
		assertDisassemblesTo("ASRB", 0x57);
		assertDisassemblesTo("ASR 0x1234", 0x77, 0x12, 0x34);
		assertDisassemblesTo("ASR 0x12,X", 0x67, 0x12);
	}

	@Test
	public void BCC() {
		assertDisassemblesTo("BCC 0x0022", 0x24, 0x20);
	}

	@Test
	public void BCS() {
		assertDisassemblesTo("BCS 0x0022", 0x25, 0x20);
	}

	@Test
	public void BEQ() {
		assertDisassemblesTo("BEQ 0x0022", 0x27, 0x20);
	}

	@Test
	public void BGE() {
		assertDisassemblesTo("BGE 0x0022", 0x2C, 0x20);
	}

	@Test
	public void BGT() {
		assertDisassemblesTo("BGT 0x0022", 0x2E, 0x20);
	}

	@Test
	public void BHI() {
		assertDisassemblesTo("BHI 0x0022", 0x22, 0x20);
	}

	@Test
	public void BIT() {
		assertDisassemblesTo("BITA #0xab", 0x85, 0xAB);
		assertDisassemblesTo("BITA 0x00ab", 0x95, 0xAB);
		assertDisassemblesTo("BITA 0x1234", 0xB5, 0x12, 0x34);
		assertDisassemblesTo("BITA 0xab,X", 0xA5, 0xAB);

		assertDisassemblesTo("BITB #0xab", 0xC5, 0xAB);
		assertDisassemblesTo("BITB 0x00ab", 0xD5, 0xAB);
		assertDisassemblesTo("BITB 0x1234", 0xF5, 0x12, 0x34);
		assertDisassemblesTo("BITB 0xab,X", 0xE5, 0xAB);
	}

	@Test
	public void BLE() {
		assertDisassemblesTo("BLE 0x0022", 0x2F, 0x20);
	}

	@Test
	public void BLS() {
		assertDisassemblesTo("BLS 0x0022", 0x23, 0x20);
	}

	@Test
	public void BLT() {
		assertDisassemblesTo("BLT 0x0022", 0x2D, 0x20);
	}

	@Test
	public void BMI() {
		assertDisassemblesTo("BMI 0x0022", 0x2B, 0x20);
	}

	@Test
	public void BNE() {
		assertDisassemblesTo("BNE 0x0022", 0x26, 0x20);
	}

	@Test
	public void BPL() {
		assertDisassemblesTo("BPL 0x0022", 0x2A, 0x20);
	}

	@Test
	public void BRA() {
		assertDisassemblesTo("BRA 0x0022", 0x20, 0x20);
	}

	@Test
	public void BSR() {
		assertDisassemblesTo("BSR 0x0022", 0x8D, 0x20);
	}

	@Test
	public void BVC() {
		assertDisassemblesTo("BVC 0x0022", 0x28, 0x20);
	}

	@Test
	public void BVS() {
		assertDisassemblesTo("BVS 0x0022", 0x29, 0x20);
	}

	@Test
	public void CBA() {
		assertDisassemblesTo("CBA", 0x11);
	}

	@Test
	public void CLC() {
		assertDisassemblesTo("CLC", 0x0C);
	}

	@Test
	public void CLI() {
		assertDisassemblesTo("CLI", 0x0E);
	}

	@Test
	public void CLR() {
		assertDisassemblesTo("CLRA", 0x4F);
		assertDisassemblesTo("CLRB", 0x5F);
		assertDisassemblesTo("CLR 0x1234", 0x7F, 0x12, 0x34);
		assertDisassemblesTo("CLR 0x12,X", 0x6F, 0x12);
	}

	@Test
	public void CLV() {
		assertDisassemblesTo("CLV", 0x0A);
	}

	@Test
	public void CMP() {
		assertDisassemblesTo("CMPA #0xab", 0x81, 0xAB);
		assertDisassemblesTo("CMPA 0x00ab", 0x91, 0xAB);
		assertDisassemblesTo("CMPA 0x1234", 0xB1, 0x12, 0x34);
		assertDisassemblesTo("CMPA 0xab,X", 0xA1, 0xAB);

		assertDisassemblesTo("CMPB #0xab", 0xC1, 0xAB);
		assertDisassemblesTo("CMPB 0x00ab", 0xD1, 0xAB);
		assertDisassemblesTo("CMPB 0x1234", 0xF1, 0x12, 0x34);
		assertDisassemblesTo("CMPB 0xab,X", 0xE1, 0xAB);
	}

	@Test
	public void COM() {
		assertDisassemblesTo("COMA", 0x43);
		assertDisassemblesTo("COMB", 0x53);
		assertDisassemblesTo("COM 0x1234", 0x73, 0x12, 0x34);
		assertDisassemblesTo("COM 0x12,X", 0x63, 0x12);
	}

	@Test
	public void CPX() {
		assertDisassemblesTo("CPX #0x1234", 0x8C, 0x12, 0x34);
		assertDisassemblesTo("CPX 0x00ab", 0x9C, 0xAB);
		assertDisassemblesTo("CPX 0x1234", 0xBC, 0x12, 0x34);
		assertDisassemblesTo("CPX 0x12,X", 0xAC, 0x12);
	}

	@Test
	public void DAA() {
		assertDisassemblesTo("DAA", 0x19);
	}

	@Test
	public void DEC() {
		assertDisassemblesTo("DECA", 0x4A);
		assertDisassemblesTo("DECB", 0x5A);
		assertDisassemblesTo("DEC 0x1234", 0x7A, 0x12, 0x34);
		assertDisassemblesTo("DEC 0x12,X", 0x6A, 0x12);
	}

	@Test
	public void DES() {
		assertDisassemblesTo("DES", 0x34);
	}

	@Test
	public void DEX() {
		assertDisassemblesTo("DEX", 0x09);
	}

	@Test
	public void EOR() {
		assertDisassemblesTo("EORA #0xab", 0x88, 0xAB);
		assertDisassemblesTo("EORA 0x00ab", 0x98, 0xAB);
		assertDisassemblesTo("EORA 0x1234", 0xB8, 0x12, 0x34);
		assertDisassemblesTo("EORA 0xab,X", 0xA8, 0xAB);

		assertDisassemblesTo("EORB #0xab", 0xC8, 0xAB);
		assertDisassemblesTo("EORB 0x00ab", 0xD8, 0xAB);
		assertDisassemblesTo("EORB 0x1234", 0xF8, 0x12, 0x34);
		assertDisassemblesTo("EORB 0xab,X", 0xE8, 0xAB);
	}

	@Test
	public void INC() {
		assertDisassemblesTo("INCA", 0x4C);
		assertDisassemblesTo("INCB", 0x5C);
		assertDisassemblesTo("INC 0x1234", 0x7C, 0x12, 0x34);
		assertDisassemblesTo("INC 0x12,X", 0x6C, 0x12);
	}

	@Test
	public void INS() {
		assertDisassemblesTo("INS", 0x31);
	}

	@Test
	public void INX() {
		assertDisassemblesTo("INX", 0x08);
	}

	@Test
	public void JMP() {
		assertDisassemblesTo("JMP 0x1234", 0x7E, 0x12, 0x34);
		assertDisassemblesTo("JMP 0x12,X", 0x6E, 0x12);
	}

	@Test
	public void JSR() {
		assertDisassemblesTo("JSR 0x1234", 0xBD, 0x12, 0x34);
		assertDisassemblesTo("JSR 0x12,X", 0xAD, 0x12);
	}

	@Test
	public void LDA() {
		assertDisassemblesTo("LDAA #0xab", 0x86, 0xAB);
		assertDisassemblesTo("LDAA 0x00ab", 0x96, 0xAB);
		assertDisassemblesTo("LDAA 0x1234", 0xB6, 0x12, 0x34);
		assertDisassemblesTo("LDAA 0xab,X", 0xA6, 0xAB);

		assertDisassemblesTo("LDAB #0xab", 0xC6, 0xAB);
		assertDisassemblesTo("LDAB 0x00ab", 0xD6, 0xAB);
		assertDisassemblesTo("LDAB 0x1234", 0xF6, 0x12, 0x34);
		assertDisassemblesTo("LDAB 0xab,X", 0xE6, 0xAB);
	}

	@Test
	public void LDS() {
		assertDisassemblesTo("LDS #0x1234", 0x8E, 0x12, 0x34);
		assertDisassemblesTo("LDS 0x00ab", 0x9E, 0xAB);
		assertDisassemblesTo("LDS 0x1234", 0xBE, 0x12, 0x34);
		assertDisassemblesTo("LDS 0x12,X", 0xAE, 0x12);
	}

	@Test
	public void LDX() {
		assertDisassemblesTo("LDX #0x1234", 0xCE, 0x12, 0x34);
		assertDisassemblesTo("LDX 0x00ab", 0xDE, 0xAB);
		assertDisassemblesTo("LDX 0x1234", 0xFE, 0x12, 0x34);
		assertDisassemblesTo("LDX 0x12,X", 0xEE, 0x12);
	}

	@Test
	public void LSR() {
		assertDisassemblesTo("LSRA", 0x44);
		assertDisassemblesTo("LSRB", 0x54);
		assertDisassemblesTo("LSR 0x1234", 0x74, 0x12, 0x34);
		assertDisassemblesTo("LSR 0x12,X", 0x64, 0x12);
	}

	@Test
	public void NEG() {
		assertDisassemblesTo("NEGA", 0x40);
		assertDisassemblesTo("NEGB", 0x50);
		assertDisassemblesTo("NEG 0x1234", 0x70, 0x12, 0x34);
		assertDisassemblesTo("NEG 0x12,X", 0x60, 0x12);
	}

	@Test
	public void NOP() {
		assertDisassemblesTo("NOP", 0x01);
	}

	@Test
	public void ORA() {
		assertDisassemblesTo("ORAA #0xab", 0x8A, 0xAB);
		assertDisassemblesTo("ORAA 0x00ab", 0x9A, 0xAB);
		assertDisassemblesTo("ORAA 0x1234", 0xBA, 0x12, 0x34);
		assertDisassemblesTo("ORAA 0xab,X", 0xAA, 0xAB);

		assertDisassemblesTo("ORAB #0xab", 0xCA, 0xAB);
		assertDisassemblesTo("ORAB 0x00ab", 0xDA, 0xAB);
		assertDisassemblesTo("ORAB 0x1234", 0xFA, 0x12, 0x34);
		assertDisassemblesTo("ORAB 0xab,X", 0xEA, 0xAB);
	}

	@Test
	public void PSH() {
		assertDisassemblesTo("PSHA", 0x36);
		assertDisassemblesTo("PSHB", 0x37);
	}

	@Test
	public void PUL() {
		assertDisassemblesTo("PULA", 0x32);
		assertDisassemblesTo("PULB", 0x33);
	}

	@Test
	public void ROL() {
		assertDisassemblesTo("ROLA", 0x49);
		assertDisassemblesTo("ROLB", 0x59);
		assertDisassemblesTo("ROL 0x1234", 0x79, 0x12, 0x34);
		assertDisassemblesTo("ROL 0x12,X", 0x69, 0x12);
	}

	@Test
	public void ROR() {
		assertDisassemblesTo("RORA", 0x46);
		assertDisassemblesTo("RORB", 0x56);
		assertDisassemblesTo("ROR 0x1234", 0x76, 0x12, 0x34);
		assertDisassemblesTo("ROR 0x12,X", 0x66, 0x12);
	}

	@Test
	public void RTI() {
		assertDisassemblesTo("RTI", 0x3B);
	}

	@Test
	public void RTS() {
		assertDisassemblesTo("RTS", 0x39);
	}

	@Test
	public void SBA() {
		assertDisassemblesTo("SBA", 0x10);
	}

	@Test
	public void SBC() {
		assertDisassemblesTo("SBCA #0xa", 0x82, 0x0A);
		assertDisassemblesTo("SBCA 0x000a", 0x92, 0x0A);
		assertDisassemblesTo("SBCA 0x1234", 0xB2, 0x12, 0x34);
		assertDisassemblesTo("SBCA 0xa,X", 0xA2, 0x0A);

		assertDisassemblesTo("SBCB #0xa", 0xC2, 0x0A);
		assertDisassemblesTo("SBCB 0x000a", 0xD2, 0x0A);
		assertDisassemblesTo("SBCB 0x1234", 0xF2, 0x12, 0x34);
		assertDisassemblesTo("SBCB 0xa,X", 0xE2, 0x0A);
	}

	@Test
	public void SEC() {
		assertDisassemblesTo("SEC", 0x0D);
	}

	@Test
	public void SEI() {
		assertDisassemblesTo("SEI", 0x0F);
	}

	@Test
	public void SEV() {
		assertDisassemblesTo("SEV", 0x0B);
	}

	@Test
	public void STA() {
		assertDisassemblesTo("STAA 0x000a", 0x97, 0x0A);
		assertDisassemblesTo("STAA 0x1234", 0xB7, 0x12, 0x34);
		assertDisassemblesTo("STAA 0xa,X", 0xA7, 0x0A);

		assertDisassemblesTo("STAB 0x000a", 0xD7, 0x0A);
		assertDisassemblesTo("STAB 0x1234", 0xF7, 0x12, 0x34);
		assertDisassemblesTo("STAB 0xa,X", 0xE7, 0x0A);
	}

	@Test
	public void STS() {
		assertDisassemblesTo("STS 0x000a", 0x9F, 0x0A);
		assertDisassemblesTo("STS 0x1234", 0xBF, 0x12, 0x34);
		assertDisassemblesTo("STS 0xa,X", 0xAF, 0x0A);
	}

	@Test
	public void STX() {
		assertDisassemblesTo("STX 0x000a", 0xDF, 0x0A);
		assertDisassemblesTo("STX 0x1234", 0xFF, 0x12, 0x34);
		assertDisassemblesTo("STX 0xa,X", 0xEF, 0x0A);
	}

	@Test
	public void SUB() {
		assertDisassemblesTo("SUBA #0xa", 0x80, 0x0A);
		assertDisassemblesTo("SUBA 0x000a", 0x90, 0x0A);
		assertDisassemblesTo("SUBA 0x1234", 0xB0, 0x12, 0x34);
		assertDisassemblesTo("SUBA 0xa,X", 0xA0, 0x0A);

		assertDisassemblesTo("SUBB #0xa", 0xC0, 0x0A);
		assertDisassemblesTo("SUBB 0x000a", 0xD0, 0x0A);
		assertDisassemblesTo("SUBB 0x1234", 0xF0, 0x12, 0x34);
		assertDisassemblesTo("SUBB 0xa,X", 0xE0, 0x0A);
	}

	@Test
	public void SWI() {
		assertDisassemblesTo("SWI", 0x3F);
	}

	@Test
	public void TAB() {
		assertDisassemblesTo("TAB", 0x16);
	}

	@Test
	public void TAP() {
		assertDisassemblesTo("TAP", 0x06);
	}

	@Test
	public void TBA() {
		assertDisassemblesTo("TBA", 0x17);
	}

	@Test
	public void TPA() {
		assertDisassemblesTo("TPA", 0x07);
	}

	@Test
	public void TST() {
		assertDisassemblesTo("TSTA", 0x4D);
		assertDisassemblesTo("TSTB", 0x5D);
		assertDisassemblesTo("TST 0x1234", 0x7D, 0x12, 0x34);
		assertDisassemblesTo("TST 0x12,X", 0x6D, 0x12);
	}

	@Test
	public void TSX() {
		assertDisassemblesTo("TSX", 0x30);
	}

	@Test
	public void TXS() {
		assertDisassemblesTo("TXS", 0x35);
	}

	@Test
	public void WAI() {
		assertDisassemblesTo("WAI", 0x3E);
	}

	protected void assertInvalidOpcode(int opCode) {
		byte[] code = new byte[] { (byte) opCode, (byte) 0x12, (byte) 0x34 };
		CodeUnit codeUnit = disassemble(code);
		assertTrue(codeUnit instanceof Data);
	}

	protected void assertDisassemblesAt(String expected, int addr, int... code) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		for (int arg : code) {
			stream.write(arg);
		}

		byte[] bytes = stream.toByteArray();
		CodeUnit codeUnit = disassembleAt(addr, bytes);

		assertNotNull(codeUnit);
		assertTrue(codeUnit instanceof Instruction);

		assertEquals(bytes.length, codeUnit.getLength());
		assertEquals(expected, codeUnit.toString());
	}

	protected void assertDisassemblesTo(String expected, int... code) {
		assertDisassemblesAt(expected, 0, code);
	}

	protected CodeUnit disassembleAt(int addr, byte[] bytes) {
		try (Transaction transaction = program.openTransaction("disassemble")) {
			ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
			// Create an overlay block.
			MemoryBlock block = program.getMemory()
					.createInitializedBlock("test", address(addr), stream, bytes.length,
						TaskMonitor.DUMMY,
						true);

			Disassembler disassembler =
				Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
			disassembler.disassemble(block.getStart(),
				program.getMemory().getLoadedAndInitializedAddressSet());
			CodeUnit ret = program.getCodeManager().getCodeUnitAt(block.getStart());
			transaction.commit();
			return ret;
		}
		catch (Exception e) {
			return null;
		}
	}

	protected CodeUnit disassemble(byte[] bytes) {
		return disassembleAt(0, bytes);
	}
}

