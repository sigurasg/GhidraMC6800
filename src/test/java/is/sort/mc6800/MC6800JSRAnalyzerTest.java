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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class MC6800JSRAnalyzerTest extends AbstractEmulatorTest {
    public MC6800JSRAnalyzerTest() {
        super("MC6800:BE:16:default");
    }

    @Test
    public void DefaultEnablement() {
        MC6800JSRAnalyzer analyzer = new MC6800JSRAnalyzer();
        assertFalse(analyzer.getDefaultEnablement(program));
    }

    @Test
    public void canAnalyzeMC6800() {
        MC6800JSRAnalyzer analyzer = new MC6800JSRAnalyzer();
        assertTrue(analyzer.canAnalyze(program));
    }

    // TODO(siggi): Test the actual analysis.
    //   This requires setting up a program with computed JSR instructions,
    //   then performing whatever analysis is needed to create the references.
    //   Finally running the analyzer and checking that the primary reference
    //   is set correctly.
}