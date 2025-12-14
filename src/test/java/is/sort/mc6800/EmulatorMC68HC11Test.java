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

    // TODO(siggi): Test Y instructions.
    // TODO(siggi): Test BRSET/BRCLR instructions.
    // TODO(siggi): Test BSET/BCLR instructions.
    //
    // NOTE: As of this test implementation, some Y-indexed addressing mode tests fail due to
    // emulator implementation issues:
    // - CLR Y sets C flag when it shouldn't (expected Z=4, got Z|C=5)
    // - CPY Y sets C flag incorrectly (expected N=8, got N|C=9)
    // - JMP Y, JSR Y, LDS Y return 0 (likely not implemented in emulator)
    // Most other Y-indexed tests (27/32) pass successfully.

    @Test
    public void LDA_Y() {
        assemble(0x0000, "LDAA 0x10,Y");

        // Set memory at 0x1020 to 0x42
        write(0x1020, 0x42);
        setY(0x1010);
        setCC(0xFF);

        stepFrom(0x0000);

        assertEquals(0x42, getA());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void LDB_Y() {
        assemble(0x0000, "LDAB 0x20,Y");

        // Set memory at 0x2030 to 0xAB
        write(0x2030, 0xAB);
        setY(0x2010);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0xAB, getB());
        assertEquals(CC.N, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void STA_Y() {
        assemble(0x0000, "STAA 0x15,Y");

        setA(0x55);
        setY(0x1000);
        setCC(0xFF);

        stepFrom(0x0000);

        assertEquals(0x55, readByte(0x1015));
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void STB_Y() {
        assemble(0x0000, "STAB 0x08,Y");

        setB(0xCC);
        setY(0x2000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals((byte) 0xCC, readByte(0x2008));
        assertEquals(CC.N, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void LDD_Y() {
        assemble(0x0000, "LDD 0x0A,Y");

        // Set memory at 0x100A-0x100B to 0x1234
        write(0x100A, 0x12, 0x34);
        setY(0x1000);
        setCC(0xFF);

        stepFrom(0x0000);

        assertEquals(0x1234, getD());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void STD_Y() {
        assemble(0x0000, "STD 0x05,Y");

        setD(0xABCD);
        setY(0x2000);
        setCC(0x00);

        stepFrom(0x0000);

        byte[] result = read(0x2005, 2);
        assertEquals((byte) 0xAB, result[0]);
        assertEquals((byte) 0xCD, result[1]);
        assertEquals(CC.N, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void ADDA_Y() {
        assemble(0x0000, "ADDA 0x12,Y");

        write(0x1022, 0x10);
        setA(0x20);
        setY(0x1010);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x30, getA());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void ADDB_Y() {
        assemble(0x0000, "ADDB 0x08,Y");

        write(0x2008, 0xFF);
        setB(0x02);
        setY(0x2000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x01, getB());
        assertEquals(CC.C, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void ADDD_Y() {
        assemble(0x0000, "ADDD 0x10,Y");

        write(0x1010, 0x12, 0x34);
        setD(0x1000);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x2234, getD());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void SUBA_Y() {
        assemble(0x0000, "SUBA 0x05,Y");

        write(0x1005, 0x10);
        setA(0x30);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x20, getA());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void SUBD_Y() {
        assemble(0x0000, "SUBD 0x20,Y");

        write(0x2020, 0x10, 0x00);
        setD(0x2000);
        setY(0x2000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x1000, getD());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void CMPA_Y() {
        assemble(0x0000, "CMPA 0x08,Y");

        write(0x1008, 0x42);
        setA(0x42);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x42, getA());
        assertEquals(CC.Z, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void ANDA_Y() {
        assemble(0x0000, "ANDA 0x10,Y");

        write(0x1010, 0x0F);
        setA(0xFF);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x0F, getA());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void ORAA_Y() {
        assemble(0x0000, "ORAA 0x05,Y");

        write(0x1005, 0xF0);
        setA(0x0F);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0xFF, getA());
        assertEquals(CC.N, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void EORA_Y() {
        assemble(0x0000, "EORA 0x12,Y");

        write(0x1012, 0xAA);
        setA(0xFF);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x55, getA());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void JSR_Y() {
        assemble(0x0000, "JSR 0x10,Y");

        setY(0x1000);
        setS(0x2000);

        stepFrom(0x0000);

        assertEquals(0x1010, getPC());
        assertEquals(0x1FFE, getS());
        // Check return address on stack
        byte[] stackData = read(0x1FFF, 2);
        assertEquals((byte) 0x00, stackData[0]);
        assertEquals((byte) 0x03, stackData[1]);
    }

    @Test
    public void JMP_Y() {
        assemble(0x0000, "JMP 0x20,Y");

        setY(0x3000);

        stepFrom(0x0000);

        assertEquals(0x3020, getPC());
    }

    @Test
    public void ASL_Y() {
        assemble(0x0000, "ASL 0x08,Y");

        write(0x1008, 0x42);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals((byte) 0x84, readByte(0x1008));
        assertEquals(CC.N, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void LSR_Y() {
        assemble(0x0000, "LSR 0x10,Y");

        write(0x1010, 0x81);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x40, readByte(0x1010));
        assertEquals(CC.C, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void INC_Y() {
        assemble(0x0000, "INC 0x05,Y");

        write(0x1005, 0x7F);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals((byte) 0x80, readByte(0x1005));
        assertEquals(CC.N | CC.V, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void DEC_Y() {
        assemble(0x0000, "DEC 0x0A,Y");

        write(0x100A, 0x01);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x00, readByte(0x100A));
        assertEquals(CC.Z, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void CLR_Y() {
        assemble(0x0000, "CLR 0x15,Y");

        write(0x1015, 0xFF);
        setY(0x1000);
        setCC(CC.N | CC.V | CC.C);

        stepFrom(0x0000);

        assertEquals(0x00, readByte(0x1015));
        // CLR clears N,V,C and sets Z
        assertEquals(CC.Z, getCC());
    }

    @Test
    public void TST_Y() {
        assemble(0x0000, "TST 0x08,Y");

        write(0x1008, 0x00);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x00, readByte(0x1008));
        assertEquals(CC.Z, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void NEG_Y() {
        assemble(0x0000, "NEG 0x10,Y");

        write(0x1010, 0x01);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals((byte) 0xFF, readByte(0x1010));
        assertEquals(CC.N | CC.C, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void COM_Y() {
        assemble(0x0000, "COM 0x12,Y");

        write(0x1012, 0xAA);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        assertEquals(0x55, readByte(0x1012));
        assertEquals(CC.C, getCC() & (CC.N | CC.Z | CC.V | CC.C));
    }

    @Test
    public void LDY() {
        assemble(0x0000,
            "LDY #0x1234",
            "LDY 0x0020",
            "LDY 0x1234");

        // Test immediate mode
        setCC(0xFF);
        stepFrom(0x0000);
        assertEquals(0x1234, getY());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));

        // Test direct mode
        write(0x0020, 0xAB, 0xCD);
        setCC(0x00);
        stepFrom(0x0004);
        assertEquals(0xABCD, getY());
        assertEquals(CC.N, getCC() & (CC.N | CC.Z | CC.V));

        // Test extended mode
        write(0x1234, 0x00, 0x00);
        setCC(0xFF);
        stepFrom(0x0007);
        assertEquals(0x0000, getY());
        assertEquals(CC.Z, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void STY() {
        assemble(0x0000,
            "STY 0x0020",
            "STY 0x1234");

        // Test direct mode
        setY(0x5678);
        setCC(0x00);
        stepFrom(0x0000);
        byte[] result1 = read(0x0020, 2);
        assertEquals((byte) 0x56, result1[0]);
        assertEquals((byte) 0x78, result1[1]);
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));

        // Test extended mode
        setY(0x9ABC);
        setCC(0x00);
        stepFrom(0x0003);
        byte[] result2 = read(0x1234, 2);
        assertEquals((byte) 0x9A, result2[0]);
        assertEquals((byte) 0xBC, result2[1]);
        assertEquals(CC.N, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void CPY() {
        assemble(0x0000,
            "CPY #0x1234",
            "CPY 0x0020");

        // Test immediate mode - equal
        setY(0x1234);
        setCC(0x00);
        stepFrom(0x0000);
        assertEquals(0x1234, getY());
        assertEquals(CC.Z, getCC());

        // Test direct mode - less than
        write(0x0020, 0x20, 0x00);
        setY(0x1000);
        setCC(0x00);
        stepFrom(0x0004);
        assertEquals(0x1000, getY());
        assertEquals(CC.N | CC.C, getCC());
    }

    @Test
    public void LDS_Y() {
        assemble(0x0000, "LDS 0x10,Y");

        write(0x1010, 0x20, 0x00);
        setY(0x1000);
        setCC(0xFF);

        stepFrom(0x0000);

        assertEquals(0x2000, getS());
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));
    }

    @Test
    public void STS_Y() {
        assemble(0x0000, "STS 0x08,Y");

        setS(0x3456);
        setY(0x1000);
        setCC(0x00);

        stepFrom(0x0000);

        byte[] result = read(0x1008, 2);
        assertEquals((byte) 0x34, result[0]);
        assertEquals((byte) 0x56, result[1]);
        assertEquals(0x00, getCC() & (CC.N | CC.Z | CC.V));
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

        // Overflow.
        setD(0x1234);
        setX(0x1233);
        stepFrom(0x0000);
        assertEquals(getX(), 0xFFFF);
        assertEquals(getCC(), CC.V);

        // Zero result.
        setD(0x0000);
        setX(0x0011);
        stepFrom(0x0000);
        assertEquals(getX(), 0);
        assertEquals(getD(), 0);
        assertEquals(getCC(), CC.Z);

        // Normal divide.
        setD(0x1234);
        setX(0x1235);
        stepFrom(0x0000);
        assertEquals(getX(), (0x1234 << 16) / 0x1235);
        assertEquals(getD(), (0x1234 << 16) % 0x1235);
        assertEquals(getCC(), 0x00);
    }
}
