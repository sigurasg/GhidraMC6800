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

import org.junit.jupiter.api.Test;

public class DisassemblyMC6800Test extends DisassemblyCommonTest {
	public DisassemblyMC6800Test() {
		super("MC6800:BE:16:default");
	}

	@Test
	public void InvalidOpCodes() {
		assertInvalidOpcode(0x00);
		assertInvalidOpcode(0x02);
		assertInvalidOpcode(0x03);
		assertInvalidOpcode(0x04);
		assertInvalidOpcode(0x05);

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

		assertInvalidOpcode(0x21);

		assertInvalidOpcode(0x38);
		assertInvalidOpcode(0x3A);
		assertInvalidOpcode(0x3C);
		assertInvalidOpcode(0x3D);

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

		assertInvalidOpcode(0x83);
		assertInvalidOpcode(0x87);
		assertInvalidOpcode(0x8F);

		assertInvalidOpcode(0x93);
		assertInvalidOpcode(0x9D);

		assertInvalidOpcode(0xA3);

		assertInvalidOpcode(0xB3);

		assertInvalidOpcode(0xC3);
		assertInvalidOpcode(0xC7);
		assertInvalidOpcode(0xCC);
		assertInvalidOpcode(0xCD);
		assertInvalidOpcode(0xCF);

		assertInvalidOpcode(0xD3);
		assertInvalidOpcode(0xDC);
		assertInvalidOpcode(0xDD);

		assertInvalidOpcode(0xE3);
		assertInvalidOpcode(0xEC);
		assertInvalidOpcode(0xED);

		assertInvalidOpcode(0xF3);
		assertInvalidOpcode(0xFC);
		assertInvalidOpcode(0xFD);
	}
}
