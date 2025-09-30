# GhidraMC6800

A Ghidra extension for the Motorola MC6800 and related MCUs.

![Disassembly](screenshot.png)

## Features

* Contains language specs for Motorola MC6800 and related MPUs.

  The supported instruction sets include:

  - Motorola MC6800, which also covers Motorola MC6802 and MC6808.
  - Motorola MC6801, which also covers Motorola MC6803 as well as Hitachi HD6803.
  - Hitachi HD6301, which also covers Hitachi HD6303.

## How to install
1. Download a [prebuilt GhidraMC6800 release](https://github.com/sigurasg/GhidraMC6800/releases), or build it yourself.
1. Start Ghidra
1. File -> Install Extensions
1. Press the plus icon ("Add extension")
1. Choose the built or downloaded GhidraMC6800 zip file
1. Restart Ghidra when prompted to load the extension properly

## How to build

### With VS Code and Docker

Open the directory in a VS Code instance and then reopen it in a devcontainer.

In a new terminal window type
```
./gradlew
```

### Otherwise

As a prerequisite, you need to have a Ghidra installation somewhere (an actual
installation, not a copy of Ghidra source code!).

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

or

```
./gradlew -Pghidra.dir=/path/to/ghidra
```

You can then find a built extension .zip in the `dist` directory.



## License

Licensed under the Apache License, Version 2.0.
