# Cross-Compiling VeeX For `aarch64-unknown-linux-musl`

## When To Use This

Use this when building `veex-cli` for `aarch64-unknown-linux-musl` with the OpenWrt musl toolchain already available on disk.

## Required

- Find `TOOLCHAIN` first.
  - It must point to the OpenWrt `toolchain-*` directory.
  - Example: `/path/to/staging_dir/toolchain-aarch64_*_musl`
- Confirm `$TOOLCHAIN/bin` contains:
  - `aarch64-openwrt-linux-musl-gcc`
  - `aarch64-openwrt-linux-musl-g++`
  - `aarch64-openwrt-linux-musl-ar`
  - `aarch64-openwrt-linux-musl-ranlib`
- `PATH="$TOOLCHAIN/bin:$PATH"`
  - Makes the OpenWrt toolchain visible to Cargo and build scripts.
- `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-gcc"`
  - Sets the target linker.
- `CC_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-gcc"`
  - Sets the target C compiler.
- `CXX_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-g++"`
  - Sets the target C++ compiler.
- `AR_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-ar"`
  - Sets the target archiver.
- `RANLIB_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-ranlib"`
  - Sets the target ranlib.

## Command

```bash
TOOLCHAIN=/path/to/staging_dir/toolchain-aarch64_*_musl
PATH="$TOOLCHAIN/bin:$PATH" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-gcc" \
CC_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-gcc" \
CXX_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-g++" \
AR_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-ar" \
RANLIB_aarch64_unknown_linux_musl="$TOOLCHAIN/bin/aarch64-openwrt-linux-musl-ranlib" \
cargo build --release -p veex-cli --target aarch64-unknown-linux-musl
```
