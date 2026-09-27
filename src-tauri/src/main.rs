#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_shell::ShellExt;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::fileapi::{CreateFileW, ReadFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, HANDLE};

// ---------- helpers ----------

fn run_ps(script: &str) -> Result<String, String> {
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn parse_ps_array<T>(json: &str) -> Vec<T>
where T: for<'de> Deserialize<'de> + Default {
    let t = json.trim();
    if t.is_empty() { return vec![]; }
    if t.starts_with('[') {
        serde_json::from_str(t).unwrap_or_default()
    } else {
        match serde_json::from_str::<T>(t) { Ok(s) => vec![s], Err(_) => vec![] }
    }
}

fn open_drive(index: u32) -> Result<HANDLE, String> {
    let path: Vec<u16> = OsStr::new(&format!("\\\\.\\PhysicalDrive{}", index))
        .encode_wide().chain(Some(0)).collect();
    let h = unsafe {
        CreateFileW(path.as_ptr(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(), OPEN_EXISTING, 0, null_mut())
    };
    if h == INVALID_HANDLE_VALUE {
        return Err("No se pudo abrir el disco. Ejecuta DiskTest Pro como Administrador.".into());
    }
    Ok(h)
}

// ---------- drives ----------

#[derive(Debug, Deserialize, Default)]
struct PsDrive {
    #[serde(rename = "DeviceId", default)] device_id: u32,
    #[serde(rename = "FriendlyName", default)] friendly_name: Option<String>,
    #[serde(rename = "SerialNumber", default)] serial_number: Option<String>,
    #[serde(rename = "MediaType", default)] media_type: Option<String>,
    #[serde(rename = "Size", default)] size: Option<u64>,
    #[serde(rename = "HealthStatus", default)] health_status: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct Drive { index: u32, name: String, serial: String, media_type: String, size_gb: f64, health: String }

#[tauri::command]
fn list_drives() -> Result<Vec<Drive>, String> {
    let json = run_ps("Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,SerialNumber,MediaType,Size,HealthStatus | ConvertTo-Json -Compress")?;
    Ok(parse_ps_array::<PsDrive>(&json).into_iter().map(|d| Drive {
        index: d.device_id,
        name: d.friendly_name.unwrap_or_else(|| "Disco desconocido".into()),
        serial: d.serial_number.unwrap_or_default(),
        media_type: d.media_type.unwrap_or_else(|| "Unspecified".into()),
        size_gb: d.size.unwrap_or(0) as f64 / 1_000_000_000.0,
        health: d.health_status.unwrap_or_default(),
    }).collect())
}

#[tauri::command]
fn get_hwid() -> Result<String, String> {
    Ok(run_ps("(Get-CimInstance Win32_ComputerSystemProduct).UUID")?.trim().to_string())
}

// ---------- disk space ----------

#[derive(Debug, Deserialize, Default, Serialize, Clone)]
struct DiskSpace {
    #[serde(rename = "DeviceID", default)] device_id: String,
    #[serde(rename = "VolumeName", default)] volume_name: Option<String>,
    #[serde(rename = "SizeGB", default)] size_gb: f64,
    #[serde(rename = "FreeGB", default)] free_gb: f64,
}

#[tauri::command]
fn disk_space() -> Result<Vec<DiskSpace>, String> {
    let json = run_ps("Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,VolumeName,@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}} | ConvertTo-Json -Compress")?;
    Ok(parse_ps_array::<DiskSpace>(&json))
}

// ---------- security (Defender + startup) ----------

#[tauri::command]
fn security_status() -> Result<serde_json::Value, String> {
    let mp = run_ps("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress").unwrap_or_default();
    let threats = run_ps("Get-MpThreatDetection | Select-Object -First 20 ThreatName,SeverityID,Resources,InitialDetectionTime | ConvertTo-Json -Compress").unwrap_or_default();
    let startup = run_ps("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json -Compress").unwrap_or_default();
    let parse = |s: &str| -> serde_json::Value {
        let t = s.trim();
        if t.is_empty() { return serde_json::Value::Array(vec![]); }
        serde_json::from_str(t).unwrap_or(serde_json::Value::Array(vec![]))
    };
    let mut mpv: serde_json::Value = parse(&mp);
    if mpv.is_array() { mpv = mpv.as_array().unwrap().first().cloned().unwrap_or(serde_json::Value::Null); }
    Ok(serde_json::json!({
        "defender": mpv,
        "threats": parse(&threats),
        "startup": parse(&startup),
    }))
}

// ---------- SMART via smartctl sidecar ----------

#[tauri::command]
async fn smart_info(app: AppHandle, index: u32) -> Result<serde_json::Value, String> {
    let mut last = String::new();
    for dev in [format!("/dev/pd{}", index), format!("/dev/nvme{}", index)] {
        let output = app.shell().sidecar("smartctl").map_err(|e| e.to_string())?
            .args(["--all", "--json", dev.as_str()]).output().await.map_err(|e| e.to_string())?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        match serde_json::from_str::<serde_json::Value>(&stdout) {
            Ok(v) => {
                let has_data = v.get("model_name").is_some()
                    || v.pointer("/smart_status/passed").is_some()
                    || v.pointer("/nvme_smart_health_information_log/percentage_used").is_some();
                if has_data { return Ok(v); }
                last = stdout.chars().take(200).collect();
            }
            Err(_) => last = stdout.chars().take(200).collect(),
        }
    }
    Err(format!("smartctl no pudo leer este disco (RAID o controlador sin soporte). {}", last))
}

// ---------- surface scan ----------

#[derive(Serialize, Clone)]
struct ScanResult { ok: bool, bytes_read: u64, bad_chunks: u64, message: String }

#[tauri::command]
fn surface_scan(app: AppHandle, index: u32, total_bytes: u64) -> Result<(), String> {
    std::thread::spawn(move || {
        let res = scan_inner(index, total_bytes, &app);
        let _ = app.emit("scan-done", res);
    });
    Ok(())
}

fn scan_inner(index: u32, total: u64, app: &AppHandle) -> ScanResult {
    let h = match open_drive(index) {
        Ok(h) => h,
        Err(e) => return ScanResult { ok: false, bytes_read: 0, bad_chunks: 0, message: e },
    };
    let chunk: usize = 4 * 1024 * 1024;
    let mut buf = vec![0u8; chunk];
    let mut done: u64 = 0; let mut bad: u64 = 0;
    let mut last_emit = std::time::Instant::now();
    while done < total {
        let want = std::cmp::min(chunk as u64, total - done) as DWORD;
        let mut read: DWORD = 0;
        let ok = unsafe { ReadFile(h, buf.as_mut_ptr() as *mut _, want, &mut read, null_mut()) };
        if ok == FALSE || read != want { bad += 1; }
        done += want as u64;
        if last_emit.elapsed().as_millis() > 500 {
            let _ = app.emit("scan-progress", serde_json::json!({"done": done, "total": total, "bad": bad}));
            last_emit = std::time::Instant::now();
        }
    }
    unsafe { CloseHandle(h); }
    ScanResult { ok: true, bytes_read: done, bad_chunks: bad,
        message: if bad == 0 { "Lectura completa sin errores".into() }
                 else { format!("{} bloques de 4MB con error de lectura", bad) } }
}

// ---------- benchmark ----------

#[derive(Serialize, Clone)]
struct BenchResult { ok: bool, mb_per_s: f64, message: String }

#[tauri::command]
fn benchmark(app: AppHandle, index: u32) -> Result<(), String> {
    std::thread::spawn(move || {
        let res = bench_inner(index);
        let _ = app.emit("bench-done", res);
    });
    Ok(())
}

fn bench_inner(index: u32) -> BenchResult {
    let h = match open_drive(index) {
        Ok(h) => h,
        Err(e) => return BenchResult { ok: false, mb_per_s: 0.0, message: e },
    };
    let chunk: usize = 4 * 1024 * 1024;
    let mut buf = vec![0u8; chunk];
    let target: u64 = 2 * 1024 * 1024 * 1024;
    let mut done: u64 = 0;
    let start = std::time::Instant::now();
    while done < target {
        let mut read: DWORD = 0;
        let ok = unsafe { ReadFile(h, buf.as_mut_ptr() as *mut _, chunk as DWORD, &mut read, null_mut()) };
        if ok == FALSE || read == 0 { break; }
        done += read as u64;
    }
    unsafe { CloseHandle(h); }
    let secs = start.elapsed().as_secs_f64().max(0.01);
    let mbs = (done as f64 / 1_000_000.0) / secs;
    BenchResult { ok: true, mb_per_s: mbs, message: format!("{:.1} MB/s lectura secuencial", mbs) }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            list_drives, get_hwid, disk_space, security_status, smart_info, surface_scan, benchmark
        ])
        .run(tauri::generate_context!())
        .expect("error while running DiskTest Pro");
      }
  
