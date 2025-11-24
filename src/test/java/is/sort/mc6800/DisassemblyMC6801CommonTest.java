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

public abstract class DisassemblyMC6801CommonTest extends DisassemblyCommonTest {
	public DisassemblyMC6801CommonTest(String lang) {
		super(lang);
	}

	@Test
	public void ABX() {
		assertDisassemblesTo("ABX", 0x3A);
	}

	@Test
	public void ADDD() {
		assertDisassemblesTo("ADDD #0x1234", 0xC3, 0x12, 0x34);
		assertDisassemblesTo("ADDD 0x00ab", 0xD3, 0xab);
		assertDisassemblesTo("ADDD 0x1234", 0xF3, 0x12, 0x34);
		assertDisassemblesTo("ADDD 0xab,X", 0xE3, 0xAB);
	}

	@Test
	public void ASLD() {
		assertDisassemblesTo("ASLD", 0x05);
	}

	@Override
	@Test
	public void JSR() {
		// Test the MC6800 variants.
		super.JSR();

		// The direct JSR is first present in the MC6801.
		assertDisassemblesTo("JSR 0x00ab", 0x9D, 0xAB);
	}

	@Test
	public void LDD() {
		assertDisassemblesTo("LDD #0x1234", 0xCC, 0x12, 0x34);
		assertDisassemblesTo("LDD 0x00ab", 0xDC, 0xab);
		assertDisassemblesTo("LDD 0x1234", 0xFC, 0x12, 0x34);
		assertDisassemblesTo("LDD 0xab,X", 0xEC, 0xAB);
	}

	@Test
	public void LSRD() {
		assertDisassemblesTo("LSRD", 0x04);
	}

	@Test
	public void MUL() {
		assertDisassemblesTo("MUL", 0x3D);
	}

	@Test
	public void PSHX() {
		assertDisassemblesTo("PSHX", 0x3C);
	}

	@Test
	public void PULX() {
		assertDisassemblesTo("PULX", 0x38);
	}

	@Test
	public void STD() {
		assertDisassemblesTo("STD 0x00ab", 0xDD, 0xAB);
		assertDisassemblesTo("STD 0x1234", 0xFD, 0x12, 0x34);
		assertDisassemblesTo("STD 0xab,X", 0xED, 0xAB);
	}

	@Test
	public void SUBD() {
		assertDisassemblesTo("SUBD #0x1234", 0x83, 0x12, 0x34);
		assertDisassemblesTo("SUBD 0x00ab", 0x93, 0xab);
		assertDisassemblesTo("SUBD 0x1234", 0xB3, 0x12, 0x34);
		assertDisassemblesTo("SUBD 0xab,X", 0xA3, 0xAB);
	}
<<<<<<< HEAD
}
=======
}
>>>>>>> origin/main
