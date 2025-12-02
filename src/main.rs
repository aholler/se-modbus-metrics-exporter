//
// Written 2025 by Alexander Holler
//
// SPDX-FileCopyrightText: Copyright (c) 2025 Alexander Holler <holler@ahsoftware.de>
// SPDX-License-Identifier: MIT OR Apache-2.0

use tokio;

use std::{
    env,
    fs::File,
    future,
    io::BufReader,
    io::Read,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, RwLock},
    time::Duration,
};

use yaml_rust::YamlLoader;

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

struct RegisterBlockDefinition {
    start_address: u16,
    size: u16,
    update: bool,
}

struct Config {
    ip_inverter_modbus: String,
    listen_ip_modbus: String,
    listen_ip_http: String,
    slave_id_modbus: u8,
    update_interval_seconds: u64,
    register_blocks: Vec<RegisterBlockDefinition>,
}

impl Config {
    fn new() -> Self {
        Self {
            ip_inverter_modbus: "".to_string(),
            listen_ip_modbus: "".to_string(),
            listen_ip_http: "".to_string(),
            slave_id_modbus: 1,
            update_interval_seconds: 10,
            register_blocks: Vec::new(),
        }
    }
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

async fn update_thread(register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>, socket_addr: SocketAddr, update_seconds: u64, slave_id: u8) -> anyhow::Result<()> {
    println!("Updating values every {}s.", update_seconds);
    let slave = Slave(slave_id);
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

fn v_u16_to_u32(data: &Vec<u16>) -> u32 {
    let mut rc0: u32 = data[0].into();
    rc0 <<= 16;
    let rc1: u32 = data[1].into();
    return rc0 + rc1;
}

fn scale_u32(val: u32, scale: u16) -> f32 {
    return val as f32 * 10_f32.powi((scale as i16).into());
}

fn get_scaled_u32_from_regs(register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>, addr: u16, scale_addr: u16) -> f32 {
    for block in register_blocks {
        let start_addr = block.read().unwrap().start_address;
        let len = block.read().unwrap().registers.len();
        if addr >= start_addr && usize::from(addr + 1) <= usize::from(start_addr) + len
            && scale_addr >= start_addr && usize::from(scale_addr + 1) <= usize::from(start_addr) + len {
            let data = &block.read().unwrap().registers;
            return scale_u32(v_u16_to_u32(&data[usize::from(addr-start_addr)..usize::from(addr-start_addr+2)].to_vec()), data[usize::from(scale_addr-start_addr)]);
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
    let total_exported_kwh = get_scaled_u32_from_regs(&regs, 40226, 40242)/1000.;
    let total_imported_kwh = get_scaled_u32_from_regs(&regs, 40234, 40242)/1000.;

    let ac_lifetime_energy_production_kwh = get_scaled_u32_from_regs(&regs, 40093, 40095) / 1000.;

    let pv_power = ac_power + battery_power;
    let home_power = ac_power - real_power;

    let mut body = "<body>".to_string();
    body = body + format!("<h1>{battery}</h1>").as_str();
    body = body + format!("<h1>Wechselrichter&colon; {ac} {dc}</h1>").as_str();
    body = body + format!("<h1>AC produziert (gesamt)&colon; {ac_lifetime_energy_production_kwh:.2}kWh</h1>").as_str();
    body = body + format!("<h1>Z&auml;hler&colon; {r_power} Frequenz {frequency:.2}Hz</h1>").as_str();
    body = body + format!("<h1>exportiert (gesamt)&colon; {total_exported_kwh:.2}kWh importiert (gesamt) {total_imported_kwh:.2}kWh</h1>").as_str();
    body = body + format!("<h1>Produktion&colon; {pv_power:.0}W (AC + Batterie)</h1>").as_str();
    body = body + format!("<h1>Hausverbrauch&colon; {home_power:.0}W (AC - Z&auml;hler)</h1>").as_str();
    body = body + "</body>";
    ("<!doctype html><html lang='de'>".to_owned() + head + &body + "</html>").into()
}

async fn metrics(State(state): State<Arc<RwLock<Vec<Arc<RwLock<RegisterBlock>>>>>>) -> String {
    let regs = state.read().unwrap();

    let mut response = "".to_string();

    let real_power = get_scaled_f32_from_regs(&regs, 40190+16, 40190+20);
    response = response + "# HELP sunspec_ac_meter_abcn_W_W Model 203, ac_meter_abcn (wye-connect three phase (abcn) meter)\\nW (Watts): Total Real Power\n";
    response = response + "# TYPE sunspec_ac_meter_abcn_W_W gauge\n";
    response = response + format!("sunspec_ac_meter_abcn_W_W {real_power:.0}\n").as_str();

    let ac_power = get_scaled_f32_from_regs(&regs, 40071+12, 40071+13);
    response = response + "# HELP sunspec_inverter_three_phase_W_W Model 103, inverter_three_phase (Inverter (Three Phase))\\nW (Watts): AC Power\n";
    response = response + "# TYPE sunspec_inverter_three_phase_W_W gauge\n";
    response = response + format!("sunspec_inverter_three_phase_W_W {ac_power:.0}\n").as_str();

    let battery_soc = get_f32_from_regs(&regs, 0xf584);
    response = response + "# HELP solaredge_Battery_1_State_of_Energy_Pct\\nPct (Percent)\n";
    response = response + "# TYPE solaredge_Battery_1_State_of_Energy_Pct gauge\n";
    response = response + format!("solaredge_Battery_1_State_of_Energy_Pct {battery_soc:.0}\n").as_str();

    let battery_power = get_f32_from_regs(&regs, 0xf574);
    response = response + "# HELP solaredge_Battery_1_Instantaneous_Power_W_W\\nW (Watts)\n";
    response = response + "# TYPE solaredge_Battery_1_Instantaneous_Power_W_W gauge\n";
    response = response + format!("solaredge_Battery_1_Instantaneous_Power_W_W {battery_power:.0}\n").as_str();

    let total_exported_wh = get_scaled_u32_from_regs(&regs, 40226, 40242);
    response = response + "# HELP sunspec_ac_meter_abcn_TotWhExp_Wh Model 203, ac_meter_abcn (wye-connect three phase (abcn) meter)\\nTotWhExp (Total Watt-hours Exported): Total Real Energy Exported\n";
    response = response + "# TYPE sunspec_ac_meter_abcn_TotWhExp_Wh counter\n";
    response = response + format!("sunspec_ac_meter_abcn_TotWhExp_Wh {total_exported_wh:.0}\n").as_str();

    let total_imported_wh = get_scaled_u32_from_regs(&regs, 40234, 40242);
    response = response + "# HELP sunspec_ac_meter_abcn_TotWhImp_Wh Model 203, ac_meter_abcn (wye-connect three phase (abcn) meter)\\nTotWhImp (Total Watt-hours Imported): Total Real Energy Imported\n";
    response = response + "# TYPE sunspec_ac_meter_abcn_TotWhImp_Wh counter\n";
    response = response + format!("sunspec_ac_meter_abcn_TotWhImp_Wh {total_imported_wh:.0}\n").as_str();

    response
}

async fn http_server_context(socket_addr: SocketAddr, register_blocks: &Vec<Arc<RwLock<RegisterBlock>>>) -> anyhow::Result<()> {
    let shared_state = Arc::new(RwLock::new(register_blocks.clone()));
    let app = Router::new()
        .route("/metrics", get(metrics))
        .route("/", get(handler))
        .with_state(shared_state);
    println!("Starting up http-server on {socket_addr}");
    let listener = TcpListener::bind(socket_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

fn read_config(filename: &str) -> Result<Config, std::io::Error> {
    let mut config_reader = BufReader::new(File::open(filename)?);
    let mut config_str = String::new();
    config_reader.read_to_string(&mut config_str)?;
    let config = YamlLoader::load_from_str(&config_str).unwrap();
    let mut config_s = Config::new();
    config_s.ip_inverter_modbus = config[0]["ipPortInverter"].as_str().unwrap().to_string();
    config_s.listen_ip_modbus = config[0]["ipPortModbus"].as_str().unwrap().to_string();
    config_s.listen_ip_http = config[0]["ipPortHttp"].as_str().unwrap().to_string();
    config_s.update_interval_seconds = u64::try_from(config[0]["updateIntervalSeconds"].as_i64().unwrap()).unwrap();
    config_s.slave_id_modbus = u8::try_from(config[0]["slaveIdModbus"].as_i64().unwrap()).unwrap();
    if let Some(vec) = config[0]["registerBlocks"].as_vec() {
        for v in vec {
            config_s.register_blocks.push(RegisterBlockDefinition{
                start_address: u16::try_from(v["startAddress"].as_i64().unwrap()).unwrap(),
                size: u16::try_from(v["size"].as_i64().unwrap()).unwrap(),
                update: v["update"].as_bool().unwrap(),
            });
        }
    }
    Ok(config_s)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("\n{} v{}\n", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    let args: Vec<String> = env::args().collect();

    let my_name = &args[0];
    let mut config_name = my_name.to_owned() + ".yaml";

    if args.len() != 1 && args.len() != 2 {
        eprintln!("Usage:");
        eprintln!("\t{} [config.yaml]", my_name);
        eprintln!("If config.yaml is not given '{}' will be used.", config_name);
        std::process::exit(1)
    }

    if args.len() == 2 {
        config_name = args[1].clone();
    }

    let config = match read_config(&config_name) {
        Err(e) => { eprintln!("Error reading config '{}': {}", config_name, e); std::process::exit(1) }
        Ok(c) => c
    };

    let sock_addr = config.ip_inverter_modbus.to_socket_addrs().unwrap().next().unwrap();
    let socket_addr = config.listen_ip_modbus.to_socket_addrs().unwrap().next().unwrap();
    let socket_addr_http = config.listen_ip_http.to_socket_addrs().unwrap().next().unwrap();

    let mut register_blocks: Vec<Arc<RwLock<RegisterBlock>>> = Vec::new();

    let slave = Slave(config.slave_id_modbus);
    let mut ctx = tcp::connect_slave(sock_addr, slave).await?;

    println!("Fetching from {sock_addr} ...");

    for block in config.register_blocks {
        let data = ctx.read_holding_registers(block.start_address, block.size).await??;
        register_blocks.push(Arc::new(RwLock::new(RegisterBlock{start_address: block.start_address, update: block.update, registers: data})));
    }

    println!("Disconnecting");

    ctx.disconnect().await?;

    let regs = register_blocks.clone();
    let modbus_future = server_context(socket_addr, &regs);
    let update_future = update_thread(&register_blocks, sock_addr, config.update_interval_seconds, config.slave_id_modbus);
    let regs2 = register_blocks.clone();
    let http_future = http_server_context(socket_addr_http, &regs2);

    let _ = tokio::join!(
        modbus_future,
        update_future,
        http_future,
    );

    Ok(())
}
