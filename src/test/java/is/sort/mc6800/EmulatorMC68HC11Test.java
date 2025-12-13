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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class EmulatorMC68HC11Test extends AbstractEmulatorTest {
    public EmulatorMC68HC11Test() {
        super("MC68HC11:BE:16:default");
    }

    @Test
    public void IDIV() {
        assemble(0x0000, "IDIV");

        // Divide by zero.
        setD(0xFFFF);
        setX(0x0000);
        setCC(CC.V);
        stepFrom(0x0000);
        assertEquals(getX(), 0xFFFF);
        assertEquals(getCC(), CC.C);

        // Normal divide.
        setD(0x1234);
        setX(0x0011);
        stepFrom(0x0000);
        assertEquals(getX(), 0x1234 / 0x0011);
        assertEquals(getD(), 0x1234 % 0x0011);
        assertEquals(getCC(), 0x00);

        // Zero result.
        // Normal divide.
        setD(0x0000);
        setX(0x0011);
        stepFrom(0x0000);
        assertEquals(getX(), 0);
        assertEquals(getD(), 0);
        assertEquals(getCC(), CC.Z);
    }

    @Test
    public void FDIV() {
        assemble(0x0000, "FDIV");

        // Divide by zero.
        setD(0xFFFF);
        setX(0x0000);
        setCC(CC.V);
        stepFrom(0x0000);
        assertEquals(getX(), 0xFFFF);
        assertEquals(getCC(), CC.C);

        /* TODO(siggi): Writeme!
        // Normal divide.
        setD(0x1234);
        setX(0x0011);
        stepFrom(0x0000);
        assertEquals(getX(), 0x1234 / 0x0011);
        assertEquals(getD(), 0x1234 % 0x0011);
        assertEquals(getCC(), 0x00);

        // Zero result.
        // Normal divide.
        setD(0x0000);
        setX(0x0011);
        stepFrom(0x0000);
        assertEquals(getX(), 0);
        assertEquals(getD(), 0);
        assertEquals(getCC(), CC.Z);
        */
    }
}
