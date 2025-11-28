# SPDX-FileCopyrightText: Copyright (c) 2025 Alexander Holler <holler@ahsoftware.de>
# SPDX-License-Identifier: MIT OR Apache-2.0

all: target/release/se-modbus-metrics-exporter

target/release/se-modbus-metrics-exporter: src/main.rs Cargo.toml
	cargo build --release && strip $@
	@# cargo build --release --ignore-rust-version && strip $@

clean:
	@rm -rf target

.PHONY: FORCE
