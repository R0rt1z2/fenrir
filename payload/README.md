Folder containing the source code of the payloads used in this PoC.

The payload is divided into 3 different stages that get executed at different times:

- `stage1`: Gets executed BEFORE LK calls `platform_init()`, which executes platform-specific hardware initialization.
- `stage2`: Gets executed BEFORE LK emits an enter fastboot event.
- `stage3`: Gets executed BEFORE LK emits a load linux kernel event.

The definitions of each stage can be found in the Makefile. The common folder contains common code that is used across all payloads.

The payload supports multiple devices. Targets are selected at build time via preprocessor defines and device-specific header files.

Each device has its own header file under `devices/` (e.g. `pacman.h` for the Nothing Phone 2a) that defines stage entry points and other function addresses specific to that bootloader and device.

If you want to enable debugging, use `export DEBUG=1` before building the payload or running the build script.