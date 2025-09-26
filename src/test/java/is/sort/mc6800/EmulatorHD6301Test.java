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

public class EmulatorHD6301Test extends AbstractEmulatorTest {
	public EmulatorHD6301Test() {
		super("HD6301:BE:16:default");
	}

	@Test
	public void AIM() {
		assemble(0x0000,
			"AIM #0xAA,0x0020",
			"AIM #0x55,0x10,X");
		// Set 0x20 to 0x0F.
		write(0x0020, 0x0F);

		setCC(0x00);
		stepFrom(0x0000);
		assertEquals(0, getCC());
		assertEquals(0x0A, readByte(0x20));

		setX(0x0010);
		// Test the indexed variant.
		stepFrom(0x0003);
		assertEquals(CC.Z, getCC());
		assertEquals(0x00, readByte(0x20));
	}

	@Test
	public void TIM() {
		assemble(0x0000,
			"TIM #0xAA,0x0020",
			"TIM #0xF0,0x10,X");
		// Set 0x20 to 0x0F.
		write(0x0020, 0x0F);

		setCC(0x00);
		stepFrom(0x0000);
		assertEquals(0, getCC());
		assertEquals(0x0F, readByte(0x20));

		setX(0x0010);
		// Test the indexed variant.
		stepFrom(0x0003);
		assertEquals(CC.Z, getCC());
		assertEquals(0x0F, readByte(0x20));
	}

	@Test
	public void XGDX() {
		assemble(0x0000, "XGDX");

		setCC(0x00);
		setX(0xCAFE);
		setD(0xBABE);
		stepFrom(0x0000);

		assertEquals(0xBABE, getX());
		assertEquals(0xCAFE, getD());
		assertEquals(0x00, getCC());
	}
}
