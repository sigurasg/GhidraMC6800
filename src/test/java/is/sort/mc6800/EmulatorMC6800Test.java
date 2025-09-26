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
	public void BLT() throws Exception {
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
	public void BGT() throws Exception {
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
	public void BLE() throws Exception {
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
}
