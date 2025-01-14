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
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MC6800Loader extends AbstractProgramLoader {

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider arg0) throws IOException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'findSupportedLoadSpecs'");
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
