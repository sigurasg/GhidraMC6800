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
// limitations under the License.

package is.sort.ghidramc6800;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MC6800Loader extends AbstractProgramLoader {
	private static final String OPTION_ADD_MEMORY_BLOCKS = "Add Memory Blocks";
	private static final String OPTION_ADD_TYPES = "Add Types";
	private static final String OPTION_MPU_KIND = "MPU";


	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider arg0) throws IOException {
    	List<LoadSpec> loadSpecs = new ArrayList<>();
        String[] mpus = {"MC6800", "MC6801", "HD6301"};
		for (String mpu : mpus) {
			LoadSpec spec = new LoadSpec(this, 0x8000,
				new LanguageCompilerSpecPair(mpu + ":BE:16:default", "default"), true);

				loadSpecs.add(spec);
		}

        return loadSpecs;
    }

	@Override
	public String getName() {
		return "MC6800";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 1;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

//		options.add(new Option());

		return options;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ByteProvider arg0, String arg1, Project arg2,
			String arg3, LoadSpec arg4, List<Option> arg5, MessageLog arg6, Object arg7,
			TaskMonitor arg8) throws IOException, LoadException, CancelledException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'loadProgram'");
	}

	@Override
	protected void loadProgramInto(ByteProvider arg0, LoadSpec arg1, List<Option> arg2,
			MessageLog arg3, Program arg4, TaskMonitor arg5)
			throws IOException, LoadException, CancelledException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'loadProgramInto'");
	}

}
