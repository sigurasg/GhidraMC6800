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

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import generic.jar.ResourceFile;
import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.framework.GModule;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import utility.application.ApplicationLayout;

public abstract class AbstractIntegrationTest extends AbstractGenericTest {

	protected Address address(int addr) {
		return language.getDefaultSpace().getAddress(addr);
	}

	public AbstractIntegrationTest(String lang) {
		SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
		this.language = provider.getLanguage(new LanguageID(lang));
		ProgramDB program = null;
		try {
			program = new ProgramDB("test", language, language.getDefaultCompilerSpec(), this);
		}
		catch (IOException e) {
		}
		this.program = program;
	}

	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new TestApplicationLayout(new File(AbstractGTest.getTestDirectoryPath()));
	}

	// This is necessary to inject the build directory into the application layout.
	private class TestApplicationLayout extends GhidraTestApplicationLayout {
		public TestApplicationLayout(File path) throws IOException {
			super(path);
		}

		@Override
		public Map<String, GModule> findGhidraModules() throws IOException {
			var ret = new HashMap<String, GModule>(super.findGhidraModules());

			ret.put("6800", new GModule(applicationRootDirs, new ResourceFile("./build")));
			return ret;
		}
	}

	protected final Language language;
	protected final ProgramDB program;
}
