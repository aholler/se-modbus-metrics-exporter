<!-- SPDX-FileCopyrightText: Copyright (c) 2025 Alexander Holler <holler@ahsoftware.de> -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

seproxy
---------

According to the SolarEdge documentation, the MODBUS TCP implementation
of SolarEdge inverters are supporting only a single connection and
session.
In order to circumvent this limitation I've written seproxy using Rust.
When started, if fetches a set of registers from the SolarEdge device
and updates the values every 10 seconds. Currently the set of registers
are hardcoded to those needed to use an openWB wallbox (the register which
are queried by openWB). The number of clients and sessions which can query
seproxy isn't restricted.

Just call make to build it.

Alexander Holler


    user@host:~/Source/seproxy.git$ target/release/seproxy

    seproxy v1.0.0

    Usage:
            target/release/seproxy ip:port server_ip:port [update_seconds]
    Examples:
            target/release/seproxy 127.0.0.1:1502 127.0.0.1:5502
            target/release/seproxy 127.0.0.1:1502 127.0.0.1:5502 20
    The default for update_seconds is 10.

    user@host:~/Source/seproxy.git$ target/release/seproxy 127.0.0.1:1502 0.0.0.0:5502

    seproxy v1.0.0

    Fetching from 127.0.0.1:1502 ...
    Disconnecting
    Updating values every 10s.
    Starting up server on 0.0.0.0:5502
