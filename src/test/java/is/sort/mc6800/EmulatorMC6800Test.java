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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import org.junit.jupiter.api.Test;

public class EmulatorMC6800Test extends AbstractEmulatorTest {
	public EmulatorMC6800Test() {
		super("MC6800:BE:16:default");
	}

	@Test
	public void NOP() {
		setA(0x00);
		setB(0x00);
		setCC(0x00);
		setX(0x0000);
		setS(0x0800);

		assemble(0x0000, "NOP");
		stepFrom(0x000);

		assertEquals(getA(), 0x00);
		assertEquals(getB(), 0x00);
		assertEquals(getCC(), 0x00);
		assertEquals(getX(), 0x0000);
		assertEquals(getS(), 0x0800);
		assertEquals(0x0001, getPC());
	}

	@Test
	public void CPX() {
		assemble(0x0000, "CPX #0x1234");

		// Test the equals case.
		setX(0x1234);
		setCC(0x00);
		stepFrom(0x0000);
		assertEquals(0x1234, getX());
		assertEquals(CC.Z, getCC());

		// Test the negative overflow case, as per the
		// programming manual the carry flag is
		// unaffected.
		setX(0x1233);
		setCC(0x00);
		stepFrom(0x0000);
		assertEquals(CC.N, getCC());
	}

	@Test
	public void BLT() {
		assemble(0x0100,
			"CMPA 	#0x10",		// Equals case.
			"BLT 	0x130");
		assemble(0x0110,
			"CMPA	#0x20",		// Less-than case.
			"BLT 	0x130");
		assemble(0x0120,
			"CMPA	#0x0A",		// Greater-than case.
			"BLT 	0x130");

		setA(0x10);
		stepFrom(0x0100, 2);
		assertNotEquals(getPC(), 0x0130);

		stepFrom(0x0110, 2);
		assertEquals(getPC(), 0x0130);

		stepFrom(0x0120, 2);
		assertNotEquals(getPC(), 0x0130);
	}

	@Test
	public void BGT() {
		assemble(0x0100,
			"CMPA 	#0x10",		// Equals case.
			"BGT 	0x130");
		assemble(0x0110,
			"CMPA	#0x20",		// Less-than case.
			"BGT 	0x130");
		assemble(0x0120,
			"CMPA	#0x0A",		// Greater-than case.
			"BGT 	0x130");

		setA(0x10);
		stepFrom(0x0100, 2);
		assertNotEquals(getPC(), 0x0130);

		stepFrom(0x0110, 2);
		assertNotEquals(getPC(), 0x0130);

		stepFrom(0x0120, 2);
		assertEquals(getPC(), 0x0130);
	}

	@Test
	public void BLE() {
		assemble(0x0100,
			"CMPA 	#0x10",		// Equals case.
			"BLE 	0x130");
		assemble(0x0110,
			"CMPA	#0x20",		// Less-than case.
			"BLE 	0x130");
		assemble(0x0120,
			"CMPA	#0x0A",		// Greater-than case.
			"BLE 	0x130");

		setA(0x10);
		stepFrom(0x0100, 2);
		assertEquals(getPC(), 0x0130);

		stepFrom(0x0110, 2);
		assertEquals(getPC(), 0x0130);

		stepFrom(0x0120, 2);
		assertNotEquals(getPC(), 0x0130);
	}

	@Test
	public void JSR() {
		// This is an indirect test of the Push2 macro in the language spec.
		assemble(0x0200,
			"JSR 0x0300");

		setS(0x07FF);
		stepFrom(0x0200, 1);
		assertEquals(0x0300, getPC());
		assertEquals(0x07FD, getS());

		final int retAddr = 0x0203; // Address after JSR instruction.

		// Per big-endian stack storage, the high order byte should be
		// at the ToS.
		byte[] retaddr = read(0x07FE, 2);
		assertEquals(retAddr & 0xFF, retaddr[1]);
		assertEquals(retAddr >> 8, retaddr[0]);
	}

	@Test
	public void BRA() {
		assemble(0x0100, "BRA 0x0130");

		stepFrom(0x0100);
		assertEquals(0x0130, getPC());
	}

	@Test
	public void BHI() {
		// BHI branches if C==0 && Z==0 (unsigned higher).
		assemble(0x0100, "BHI 0x0130");

		setCC(0x00);              // C=0, Z=0: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.C);              // C=1: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());

		setCC(CC.Z);              // Z=1: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BLS() {
		// BLS branches if C==1 || Z==1 (unsigned lower or same).
		assemble(0x0100, "BLS 0x0130");

		setCC(CC.C);              // C=1: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.Z);              // Z=1: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(0x00);              // C=0, Z=0: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BCC() {
		// BCC branches if C==0 (carry clear).
		assemble(0x0100, "BCC 0x0130");

		setCC(0x00);              // C=0: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.C);              // C=1: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BCS() {
		// BCS branches if C==1 (carry set).
		assemble(0x0100, "BCS 0x0130");

		setCC(CC.C);              // C=1: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(0x00);              // C=0: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BNE() {
		// BNE branches if Z==0 (not equal).
		assemble(0x0100, "BNE 0x0130");

		setCC(0x00);              // Z=0: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.Z);              // Z=1: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BEQ() {
		// BEQ branches if Z==1 (equal).
		assemble(0x0100, "BEQ 0x0130");

		setCC(CC.Z);              // Z=1: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(0x00);              // Z=0: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BVC() {
		// BVC branches if V==0 (overflow clear).
		assemble(0x0100, "BVC 0x0130");

		setCC(0x00);              // V=0: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.V);              // V=1: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BVS() {
		// BVS branches if V==1 (overflow set).
		assemble(0x0100, "BVS 0x0130");

		setCC(CC.V);              // V=1: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(0x00);              // V=0: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BPL() {
		// BPL branches if N==0 (plus / positive).
		assemble(0x0100, "BPL 0x0130");

		setCC(0x00);              // N=0: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.N);              // N=1: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BMI() {
		// BMI branches if N==1 (minus / negative).
		assemble(0x0100, "BMI 0x0130");

		setCC(CC.N);              // N=1: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(0x00);              // N=0: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BGE() {
		// BGE branches if N==V (signed greater or equal).
		assemble(0x0100, "BGE 0x0130");

		setCC(0x00);              // N=0, V=0: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.N | CC.V);       // N=1, V=1: taken.
		stepFrom(0x0100);
		assertEquals(0x0130, getPC());

		setCC(CC.N);              // N=1, V=0: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());

		setCC(CC.V);              // N=0, V=1: not taken.
		stepFrom(0x0100);
		assertNotEquals(0x0130, getPC());
	}

	@Test
	public void BSR() {
		// BSR pushes the return address and branches to the target.
		assemble(0x0200, "BSR 0x0230");

		setS(0x07FF);
		stepFrom(0x0200, 1);
		assertEquals(0x0230, getPC());
		assertEquals(0x07FD, getS());

		final int retAddr = 0x0202; // BSR is 2 bytes, so return address is PC+2.

		// Per big-endian stack storage, the high order byte should be at the ToS.
		byte[] retaddr = read(0x07FE, 2);
		assertEquals(retAddr & 0xFF, retaddr[1]);
		assertEquals(retAddr >> 8, retaddr[0]);
	}

	@Test
	public void LDAA() {
		assemble(0x0000, "LDAA #0x42");    // Immediate: positive value.
		assemble(0x0002, "LDAA #0x00");    // Immediate: zero.
		assemble(0x0004, "LDAA #0x80");    // Immediate: negative (MSB set).
		assemble(0x0006, "LDAA 0x50");     // Direct: reads from zero-page address.
		assemble(0x0008, "LDAA 0x10,X");   // Indexed: reads from X + offset.
		assemble(0x000A, "LDAA 0x0300");   // Extended: reads from 16-bit address.

		// Immediate: positive value — A gets value, N=0, Z=0, V=0.
		setCC(CC.V | CC.C);
		stepFrom(0x0000);
		assertEquals(0x42, getA());
		assertEquals(CC.C, getCC());      // V cleared, C unaffected.

		// Immediate: zero — Z set, N=0, V=0.
		setCC(CC.V | CC.C);
		stepFrom(0x0002);
		assertEquals(0x00, getA());
		assertEquals(CC.Z | CC.C, getCC());

		// Immediate: negative — N set, Z=0, V=0.
		setCC(CC.V | CC.C);
		stepFrom(0x0004);
		assertEquals(0x80, getA());
		assertEquals(CC.N | CC.C, getCC());

		// Direct: loads from zero-page address 0x50.
		write(0x0050, 0x77);
		stepFrom(0x0006);
		assertEquals(0x77, getA());

		// Indexed: loads from X + 0x10.
		write(0x0110, 0x55);
		setX(0x0100);
		stepFrom(0x0008);
		assertEquals(0x55, getA());

		// Extended: loads from 16-bit address 0x0300.
		write(0x0300, 0x33);
		stepFrom(0x000A);
		assertEquals(0x33, getA());
	}

	@Test
	public void LDAB() {
		assemble(0x0000, "LDAB #0x42");    // Immediate: positive value.
		assemble(0x0002, "LDAB #0x00");    // Immediate: zero.
		assemble(0x0004, "LDAB #0x80");    // Immediate: negative (MSB set).
		assemble(0x0006, "LDAB 0x50");     // Direct: reads from zero-page address.
		assemble(0x0008, "LDAB 0x10,X");   // Indexed: reads from X + offset.
		assemble(0x000A, "LDAB 0x0300");   // Extended: reads from 16-bit address.

		// Immediate: positive value — B gets value, N=0, Z=0, V=0.
		setCC(CC.V | CC.C);
		stepFrom(0x0000);
		assertEquals(0x42, getB());
		assertEquals(CC.C, getCC());      // V cleared, C unaffected.

		// Immediate: zero — Z set, N=0, V=0.
		setCC(CC.V | CC.C);
		stepFrom(0x0002);
		assertEquals(0x00, getB());
		assertEquals(CC.Z | CC.C, getCC());

		// Immediate: negative — N set, Z=0, V=0.
		setCC(CC.V | CC.C);
		stepFrom(0x0004);
		assertEquals(0x80, getB());
		assertEquals(CC.N | CC.C, getCC());

		// Direct: loads from zero-page address 0x50.
		write(0x0050, 0x77);
		stepFrom(0x0006);
		assertEquals(0x77, getB());

		// Indexed: loads from X + 0x10.
		write(0x0110, 0x55);
		setX(0x0100);
		stepFrom(0x0008);
		assertEquals(0x55, getB());

		// Extended: loads from 16-bit address 0x0300.
		write(0x0300, 0x33);
		stepFrom(0x000A);
		assertEquals(0x33, getB());
	}
}
