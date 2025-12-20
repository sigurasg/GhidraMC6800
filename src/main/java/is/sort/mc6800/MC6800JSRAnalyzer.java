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

package is.sort.mc6800;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MC6800JSRAnalyzer extends AbstractAnalyzer {

    public MC6800JSRAnalyzer() {
        super("MC6800 JSR Analyzer",
            "Makes sure JSR instructions reference the called function as a primary reference",
            AnalyzerType.INSTRUCTION_ANALYZER);

        // Allow one time analysis.
        setSupportsOneTimeAnalysis(true);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return true;
    }

    @Override
    public boolean canAnalyze(Program program) {
        // TODO(siggi): Maybe this needs to filter for specific processor versions?
        return true;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        var instructions = program.getListing().getInstructions(set, true);
        for (var instruction : instructions) {
            monitor.checkCancelled();

            var references = instruction.getReferencesFrom();
            for (var reference : references) {
                if (reference.getReferenceType().isCall()) {
                    // Found an isCall reference.
                    if (!reference.isPrimary()) {
                        program.getReferenceManager().setPrimary(reference, true);
                    }
                }
            }
        }

        return true;
    }
}