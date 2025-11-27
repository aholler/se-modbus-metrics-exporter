<!-- SPDX-FileCopyrightText: Copyright (c) 2025 Alexander Holler <holler@ahsoftware.de> -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

se-modbus-metrics-exporter
--------------------------

According to the SolarEdge documentation, the MODBUS TCP implementation
of SolarEdge inverters supports only a single connection and session. This
makes it almost impossible to use the values by multiple means.
In order to circumvent this limitation I've written this tool using Rust.
When started, if fetches a configured set of registers from the SolarEdge
device, updates values (by default) every 10 seconds and offers them via
a modbus-TCP-server. Furthermore it shows some values via http (at /) and
offers some metrics (at /metrics) for scraping by prometheus. This makes it
possible to display timelines e.g. by using Grafana.

Just call make to build it.

Scraping the metrics with prometheus can be done e.g. with the
following in the config of prometheus:

    scrape_configs:
      - job_name: 'solaredge'
        static_configs:
          - targets: ['127.0.0.1:5503']
        metrics_path: /metrics
        scheme: http
        scrape_interval: 4m
        scrape_timeout: 10s

Alexander Holler


    user@host:~/Source/se-modbus-metrics-exporter.git$ target/release/se-modbus-metrics-exporter please help

    se-modbus-metrics-exporter v1.3.0

    Usage:
        target/release/se-modbus-metrics-exporter [config.yaml]
    If config.yaml is not given 'target/release/se-modbus-metrics-exporter.yaml' will be used.

    user@host:~/Source/se-modbus-metrics-exporter.git$ target/release/se-modbus-metrics-exporter config.yaml

    se-modbus-metrics-exporter v1.3.0

    Fetching from 127.0.0.1:1502 ...
    Disconnecting
    Starting up modbus-tcp-server on 127.0.0.1:5502
    Updating values every 10s.
    Starting up http-server on 0.0.0.0:5503
