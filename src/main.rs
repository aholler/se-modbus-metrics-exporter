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
    server::tcp::accept_tcp_connection,
};

use axum::{
    routing::get,
    extract::State,
    Router,
    response::Html,
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
        let len = block.read().unwrap().registers.len();
        if addr >= start_addr && usize::from(addr + cnt) <= usize::from(start_addr) + len {
            let data = &block.read().unwrap().registers;
            return Ok(data[usize::from(addr-start_addr)..usize::from(addr-start_addr+cnt)].to_vec());
        }
    }
    println!("SERVER: Exception::IllegalDataAddress {} {}", addr, cnt);
    return Err(ExceptionCode::IllegalDataAddress);
}

async fn server_context(socket_addr: SocketAddr, register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>) -> anyhow::Result<()> {
    println!("Starting up modbus-tcp-server on {socket_addr}");
    loop {
        let listener = TcpListener::bind(socket_addr).await?;
        let server = tokio_modbus::server::tcp::Server::new(listener);
        let new_service = |_socket_addr| Ok(Some(ExampleService::new(register_blocks.clone())));
        let on_connected = |stream, socket_addr| async move {
            accept_tcp_connection(stream, socket_addr, new_service)
        };
        let on_process_error = |err| {
            eprintln!("process error: {err}");
        };
        if let Err(e) = server.serve(&on_connected, on_process_error).await {
            eprintln!("Errors starting modbus-server: {e}");
        }
    }
}

fn print_help(my_name: &str) {
        eprintln!("Usage:");
        eprintln!("\t{} ip_inverter:port listen_ip_modbus:port listen_ip_http:port [update_seconds]", my_name);
        eprintln!("Examples:");
        eprintln!("\t{} 127.0.0.1:1502 127.0.0.1:5502 127.0.0.1:5503 ", my_name);
        eprintln!("\t{} 127.0.0.1:1502 127.0.0.1:5502 0.0.0.0:5503 20", my_name);
        eprintln!("The default for update_seconds is 10.");
}

async fn update_thread(register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>, socket_addr: SocketAddr, update_seconds: u64) -> anyhow::Result<()> {
    println!("Updating values every {}s.", update_seconds);
    let slave = Slave(0x01);
    loop {
        tokio::time::sleep(Duration::from_secs(update_seconds)).await;
        if let Ok(mut ctx) = tcp::connect_slave(socket_addr, slave).await {
            for block in register_blocks {
                let update = block.read().unwrap().update;
                if update {
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

fn v_u16_to_f32(data: &Vec<u16>) -> f32 {
    let bytes: Vec<u8> = data.iter().fold(vec![], |mut x, elem| {
        x.push((elem & 0xff) as u8);
        x.push((elem >> 8) as u8);
        x
    });
    let b: [u8; 4] = bytes.try_into().unwrap();
    return f32::from_ne_bytes(b);
}

fn get_f32_from_regs(register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>, addr: u16) -> f32 {
    for block in register_blocks {
        let start_addr = block.read().unwrap().start_address;
        let len = block.read().unwrap().registers.len();
        if addr >= start_addr && usize::from(addr + 2) <= usize::from(start_addr) + len {
            let data = &block.read().unwrap().registers;
            return v_u16_to_f32(&data[usize::from(addr-start_addr)..usize::from(addr-start_addr+2)].to_vec());
        }
    }
    0.0
}

fn scale(val: u16, scale: u16) -> f32 {
    return val as i16 as f32 * 10_f32.powi((scale as i16).into());
}

fn get_scaled_f32_from_regs(register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>, addr: u16, scale_addr: u16) -> f32 {
    for block in register_blocks {
        let start_addr = block.read().unwrap().start_address;
        let len = block.read().unwrap().registers.len();
        if addr >= start_addr && usize::from(addr + 1) <= usize::from(start_addr) + len
            && scale_addr >= start_addr && usize::from(scale_addr + 1) <= usize::from(start_addr) + len {
            let data = &block.read().unwrap().registers;
            return scale(data[usize::from(addr-start_addr)], data[usize::from(scale_addr-start_addr)]);
        }
    }
    0.0
}

async fn handler(State(state): State<Arc<RwLock<Vec<Arc<RwLock<RegisterBlock>>>>>>) -> Html<String> {
    let regs = state.read().unwrap();

    let battery_soc = get_f32_from_regs(&regs, 0xf584);
    let battery_power = get_f32_from_regs(&regs, 0xf574);
    let battery_health = get_f32_from_regs(&regs, 0xf582);

     let head = "<head><meta http-equiv='refresh' content='30'><title>PV-Status</title></head>";
     let power = if battery_power < 0.0 {
             format!("<font color='red'>{battery_power:.0}W</font>")
         } else {
             format!("<font color='green'>{battery_power:.0}W</font>")
        };
     let battery = format!("Batterie&colon; Ladezustand {battery_soc:.0}% Leistung {power} health {battery_health:.0}%");

     let ac_power = get_scaled_f32_from_regs(&regs, 40071+12, 40071+13);
     let ac = format!("AC {ac_power:.0}W");

     let dc_power = get_scaled_f32_from_regs(&regs, 40071+29, 40071+30);
     let dc = format!("DC {dc_power:.0}W");

     let real_power = get_scaled_f32_from_regs(&regs, 40190+16, 40190+20);
     let r_power = if real_power < 0.0 {
             format!("<font color='red'>{real_power:.0}W</font>") // vom Netz
         } else {
             format!("<font color='green'>{real_power:.0}W</font>") // Einspeisung
        };

     let frequency = get_scaled_f32_from_regs(&regs, 40190+14, 40190+15);
     let body = format!("<body><h1>{battery}</h1><h1>Wechselrichter&colon; {ac} {dc}</h1><h1>Z&auml;hler&colon; {r_power} Frequenz {frequency:.2}Hz</h1></body>");
     ("<!doctype html><html lang='de'>".to_owned() + head + &body + "</html>").into()
}

async fn http_server_context(socket_addr: SocketAddr, register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>) -> anyhow::Result<()> {
    let shared_state = Arc::new(RwLock::new(register_blocks.clone()));
    let app = Router::new()
        .route("/", get(handler))
        .with_state(shared_state);
    println!("Starting up http-server on {socket_addr}");
    let listener = TcpListener::bind(socket_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("\nseproxy v{}\n", env!("CARGO_PKG_VERSION"));

    let args: Vec<String> = env::args().collect();

    if args.len() != 4 && args.len() != 5 {
        print_help(&args[0]);
        std::process::exit(1)
    }

    let sock_addr = args[1].parse().unwrap();
    let socket_addr = args[2].parse().unwrap();
    let socket_addr_http = args[3].parse().unwrap();
    let update_seconds = if args.len() == 5 {
        args[4].parse().unwrap()
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

    let regs = register_blocks.clone();
    let modbus_future = server_context(socket_addr, &regs);
    let update_future = update_thread(&register_blocks, sock_addr, update_seconds);
    let regs2 = register_blocks.clone();
    let http_future = http_server_context(socket_addr_http, &regs2);

    let _ = tokio::join!(
        modbus_future,
        update_future,
        http_future,
    );

    Ok(())
}
