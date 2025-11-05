//
// Written 2025 by Alexander Holler
//
// SPDX-FileCopyrightText: Copyright (c) 2025 Alexander Holler <holler@ahsoftware.de>
// SPDX-License-Identifier: MIT OR Apache-2.0

use tokio;

use std::{
    env,
    future,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use tokio::net::TcpListener;

use tokio_modbus::{
    prelude::*,
    server::tcp::{accept_tcp_connection, Server},
};

struct RegisterBlock {
    start_address: u16,
    update: bool,
    registers: Vec<u16>,
}

struct ExampleService {
    register_blocks: Vec<Arc<RwLock<RegisterBlock>>>,
}

impl tokio_modbus::server::Service for ExampleService {
    type Request = Request<'static>;
    type Response = Response;
    type Exception = ExceptionCode;
    type Future = future::Ready<Result<Self::Response, Self::Exception>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        let res = match req {
            Request::ReadHoldingRegisters(addr, cnt) => {
                //println!("addr {} cnt {}", addr, cnt);
                register_read(self.register_blocks.clone(), addr, cnt)
                    .map(Response::ReadHoldingRegisters)
            }
            _ => {
                println!("SERVER: Exception::IllegalFunction - Unimplemented function code in request: {req:?}");
                Err(ExceptionCode::IllegalFunction)
            }
        };
        future::ready(res)
    }
}

impl ExampleService {
    fn new(register_blocks: Vec<Arc<RwLock<RegisterBlock>>>) -> Self {
        Self {
            register_blocks: register_blocks.clone(),
        }
    }
}

fn register_read(
    register_blocks: Vec<Arc<RwLock<RegisterBlock>>>,
    addr: u16,
    cnt: u16,
) -> Result<Vec<u16>, ExceptionCode> {
    for block in register_blocks {
        let start_addr = block.read().unwrap().start_address;
        if addr >= start_addr && usize::from(addr + cnt) <= usize::from(start_addr) + block.read().unwrap().registers.len() {
            let data = &block.read().unwrap().registers;
            return Ok(data[usize::from(addr-start_addr)..usize::from(addr-start_addr+cnt)].to_vec());
        }
    }
    println!("SERVER: Exception::IllegalDataAddress {} {}", addr, cnt);
    return Err(ExceptionCode::IllegalDataAddress);
}

async fn server_context(socket_addr: SocketAddr, register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>) -> anyhow::Result<()> {
    println!("Starting up server on {socket_addr}");
    let listener = TcpListener::bind(socket_addr).await?;
    let server = Server::new(listener);
    let new_service = |_socket_addr| Ok(Some(ExampleService::new(register_blocks.clone())));
    let on_connected = |stream, socket_addr| async move {
        accept_tcp_connection(stream, socket_addr, new_service)
    };
    let on_process_error = |err| {
        eprintln!("{err}");
    };
    server.serve(&on_connected, on_process_error).await?;
    Ok(())
}

fn print_help(my_name: &str) {
        eprintln!("Usage:");
        eprintln!("\t{} ip:port server_ip:port [update_seconds]", my_name);
        eprintln!("Examples:");
        eprintln!("\t{} 127.0.0.1:1502 127.0.0.1:5502", my_name);
        eprintln!("\t{} 127.0.0.1:1502 127.0.0.1:5502 20", my_name);
        eprintln!("The default for update_seconds is 10.");
}

async fn update_thread(register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>, socket_addr: SocketAddr, update_seconds: u64) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(update_seconds)).await;
        let slave = Slave(0x01);
        if let Ok(mut ctx) = tcp::connect_slave(socket_addr, slave).await {
            for block in register_blocks {
                if block.read().unwrap().update {
                    let start = block.read().unwrap().start_address;
                    let len : u16 = block.read().unwrap().registers.len().try_into().unwrap();
                    if let Ok(Ok(data)) = ctx.read_holding_registers(start, len).await {
                        block.write().unwrap().registers = data;
                    } else {
                        eprintln!("error reading values");
                    }
                }
            }
            if let Err(e) = ctx.disconnect().await {
                eprintln!("Error disconnecting ({e})");
            }
        } else {
            eprintln!("Error connecting");
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("\nseproxy v{}\n", env!("CARGO_PKG_VERSION"));

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 && args.len() != 4 {
        print_help(&args[0]);
        std::process::exit(1)
    }

    let sock_addr = args[1].parse().unwrap();
    let socket_addr = args[2].parse().unwrap();
    let update_seconds = if args.len() == 4 {
        args[3].parse().unwrap()
    } else {
        10
    };

    let mut register_blocks: Vec<Arc<RwLock<RegisterBlock>>> = Vec::new();

    let slave = Slave(0x01);
    let mut ctx = tcp::connect_slave(sock_addr, slave).await?;

    println!("Fetching from {sock_addr} ...");

    let data_battery = ctx.read_holding_registers(62836, 18).await??;
    register_blocks.push(Arc::new(RwLock::new(RegisterBlock{start_address: 62836, update: true, registers: data_battery})));

    let data_inverter = ctx.read_holding_registers(40072, 30).await??;
    register_blocks.push(Arc::new(RwLock::new(RegisterBlock{start_address: 40072, update: true, registers: data_inverter})));

    let data_meter_option = ctx.read_holding_registers(40155, 8).await??;
    register_blocks.push(Arc::new(RwLock::new(RegisterBlock{start_address: 40155, update: false, registers: data_meter_option})));

    let data_meter = ctx.read_holding_registers(40191, 52).await??;
    register_blocks.push(Arc::new(RwLock::new(RegisterBlock{start_address: 40191, update: true, registers: data_meter})));

    println!("Disconnecting");

    ctx.disconnect().await?;

    println!("Updating values every {}s.", update_seconds);

    tokio::select! {
        _ = server_context(socket_addr, &register_blocks) => unreachable!(),
        _ = update_thread(&register_blocks, sock_addr, update_seconds) => println!("Exiting"),
    }

    Ok(())
}
