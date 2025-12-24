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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An analyzer that makes sure computed JSR instructions reference the called
 * function as a primary reference, when Ghidra is able to infer the called
 * function.
 *
 * When Ghidra can infer the value of the stack pointer and the X/Y register,
 * a computed JSR instruction will have two references.
 *  1. A write reference to the location in stack where the return address is stored.
 *  2. A call reference to the called function.
 *
 * This would happen for example for the following code:
 *   LDS #$07FF
 *   LDX fn
 *   JSR 0,X
 *
 * fn:
 *   RTS
 *
 * By default Ghidra marks the write reference as primary, this analyzer
 * changes that to make the call reference primary.
 *
 * Because this should be a fairly rare case for MC6800 programs, and because this
 * might have unforseen side effects on non-MC6800 programs, this analyzer is not
 * enabled by default.
 */
public class MC6800JSRAnalyzer extends AbstractAnalyzer {
    public MC6800JSRAnalyzer() {
        super("MC6800 JSR Analyzer",
            "Makes sure computed JSR instructions reference the called function" +
                " as a primary reference",
            AnalyzerType.INSTRUCTION_ANALYZER);

        // Allow one time analysis.
        setSupportsOneTimeAnalysis(true);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    @Override
    public boolean canAnalyze(Program program) {
        // Only analyze for 16 bit address spaces.
        AddressSpace ram = program.getAddressFactory().getAddressSpace("ram");
        if (ram == null || ram.getSize() != 16) {
            return false;
        }

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
