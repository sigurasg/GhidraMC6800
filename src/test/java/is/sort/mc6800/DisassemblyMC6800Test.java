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
	public void ValidInvalidOpCodes() {
		Integer[] invalidOpcodes = {
			0x00, 0x02, 0x03, 0x04, 0x05,
			0x12, 0x13, 0x14, 0x15, 0x18,
			0x1A, 0x1C, 0x1D, 0x1E, 0x1F,
			0x21,
			0x38, 0x3A, 0x3C, 0x3D,
			0x41, 0x42, 0x45, 0x4B, 0x4E,
			0x51, 0x52, 0x55, 0x5B, 0x5E,
			0x61, 0x62, 0x65, 0x6B,
			0x71, 0x72, 0x75, 0x7B,
			0x83, 0x87, 0x8F,
			0x93, 0x9D,
			0xA3,
			0xB3,
			0xC3, 0xC7, 0xCC, 0xCD, 0xCF,
			0xD3, 0xDC, 0xDD,
			0xE3, 0xEC, 0xED,
			0xF3, 0xFC, 0xFD
		};

		assertInvaldOpcodes(invalidOpcodes);
		assertValidOpcodes(complementOpcodes(invalidOpcodes));
	}
}
