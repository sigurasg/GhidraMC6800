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
// limitations under the License.package is.sort.ghidramc6800;

package is.sort.ghidramc6800;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;

public class MC6800LoaderTest {
	public MC6800LoaderTest() {
	}

	@Test
	public void getName() {
		assertTrue("MC6800".equals(loader.getName()));
	}

	@Test
	public void findSupportedLoadSpecs() throws IOException {
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(null);

        assertEquals(specs.size(), 3);
    }

	@BeforeEach
	public void beforeEach() {
		loader = new MC6800Loader();
	}
	
	private Loader loader;
}
