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

import org.junit.jupiter.api.Test;

public class EmulatorMC6801Test extends AbstractEmulatorTest {
	public EmulatorMC6801Test() {
		super("MC6801:BE:16:default");
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
		// programming manual the carry flag is set,
		// which is opposite to the 6800 behavior.
		setX(0x1233);
		setCC(0x00);
		stepFrom(0x0000);
		assertEquals(CC.N + CC.C, getCC());
	}
}
