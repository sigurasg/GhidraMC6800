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

import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;

public abstract class AbstractEmulatorTest extends AbstractIntegrationTest {

	public AbstractEmulatorTest(String lang) {
		super(lang);

		emulator = new PcodeEmulator(language);
		thread = emulator.newThread();

		regA = language.getRegister("A");
		regB = language.getRegister("B");
		regD = language.getRegister("D");
		regCC = language.getRegister("CC");
		regX = language.getRegister("X");
		regY = language.getRegister("Y");
		regS = language.getRegister("S");
		regPC = language.getRegister("PC");
	}

	protected int assemble(int addr, String... code) {
		AddressSpace dyn = language.getDefaultSpace();
		Address entry = dyn.getAddress(addr);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buffer = new AssemblyBuffer(asm, entry);
		for (String line : code) {
			try {
				buffer.assemble(line);
			}
			catch (Exception e) {
				fail("Failed to assemble line: " + line, e);
				return 0;
			}
		}

		byte[] bytes = buffer.getBytes();
		emulator.getSharedState().setVar(dyn, entry.getOffset(), bytes.length, true, bytes);

		return bytes.length;
	}

	protected void setA(int value) {
		writeRegister(regA, value);
	}

	protected void setB(int value) {
		writeRegister(regB, value);
	}

	protected void setD(int value) {
		writeRegister(regD, value);
	}

	protected void setCC(int value) {
		writeRegister(regCC, value);
	}

	protected void setX(int value) {
		writeRegister(regX, value);
	}

	protected void setY(int value) {
		writeRegister(regY, value);
	}

	protected void setS(int value) {
		writeRegister(regS, value);
	}

	protected void setPC(int value) {
		writeRegister(regPC, value);
		thread.setCounter(address(value));
	}

	protected int getA() {
		return readRegister(regA);
	}

	protected int getB() {
		return readRegister(regB);
	}

	protected int getD() {
		return readRegister(regD);
	}

	protected int getCC() {
		return readRegister(regCC);
	}

	protected int getX() {
		return readRegister(regX);
	}

	protected int getY() {
		return readRegister(regY);
	}

	protected int getS() {
		return readRegister(regS);
	}

	protected int getPC() {
		return readRegister(regPC);
	}

	protected void write(int addr, int... bytes) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		for (int v : bytes) {
			stream.write(v);
		}
		writeMemory(addr, stream.toByteArray());
	}

	protected byte[] read(int addr, int length) {
		return readMemory(addr, length);
	}

	protected byte readByte(int addr) {
		return read(addr, 1)[0];
	}

	protected void step(int numInstructions) {
		for (int i = 0; i < numInstructions; ++i) {
			thread.stepInstruction();
		}
	}

	protected void step() {
		step(1);
	}

	protected void stepFrom(int addr, int numInstructions) {
		setPC(addr);
		step(numInstructions);
	}

	protected void stepFrom(int addr) {
		stepFrom(addr, 1);
	}

	private void writeMemory(int addr, byte[] data) {
		AddressSpace dyn = language.getDefaultSpace();
		Address entry = dyn.getAddress(addr);

		emulator.getSharedState().setVar(dyn, entry.getOffset(), data.length, true, data);
	}

	private byte[] readMemory(int addr, int length) {
		AddressSpace dyn = language.getDefaultSpace();

		return emulator.getSharedState().getVar(dyn, addr, length, true, Reason.INSPECT);
	}

	private void writeRegister(Register reg , int value) {
		thread.getState()
				.setVar(reg, Utils.longToBytes(value,
					reg.getNumBytes(), language.isBigEndian()));
	}

	private int readRegister(Register reg ) {
		return (int) Utils.bytesToLong(thread.getState().getVar(reg, Reason.INSPECT),
			reg.getNumBytes(), language.isBigEndian());

	}

	private PcodeEmulator emulator = null;
	private PcodeThread<byte[]> thread = null;

	private Register regA = null;
	private Register regB = null;
	private Register regD = null;
	private Register regCC = null;
	private Register regX = null;
	private Register regY = null;
	private Register regS = null;
	private Register regPC = null;
};
