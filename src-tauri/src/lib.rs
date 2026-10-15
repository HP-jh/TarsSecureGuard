//! TarsSecureGuard v4.11.0 桌面客户端壳（Tauri 2）

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, RunEvent};
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

const GATEWAY_PORT: u16 = 18889;
const HEALTH_PATH: &str = "/health";

struct SidecarHandle(Arc<Mutex<Option<CommandChild>>>);
struct TrayState {
    alert_until: Mutex<Option<std::time::Instant>>,
}

fn gateway_health_with_first_run() -> (bool, bool) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", GATEWAY_PORT)) else {
        return (false, false);
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!(
        "GET {HEALTH_PATH} HTTP/1.1\r\nHost: 127.0.0.1:{GATEWAY_PORT}\r\nConnection: close\r\n\r\n"
    );
    if s.write_all(req.as_bytes()).is_err() {
        return (false, false);
    }
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]);
    let ok = text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200");
    let first_run = ok && text.contains("\"first_run\":true");
    (ok, first_run)
}

fn show_window(app: &tauri::AppHandle, label: &str) {
    if let Some(win) = app.get_webview_window(label) {
        let _ = win.show();
        let _ = win.set_focus();
    }
}
fn hide_window(app: &tauri::AppHandle, label: &str) {
    if let Some(win) = app.get_webview_window(label) {
        let _ = win.hide();
    }
}
fn close_window(app: &tauri::AppHandle, label: &str) {
    if let Some(win) = app.get_webview_window(label) {
        let _ = win.close();
    }
}

fn focus_main_window(app: &tauri::AppHandle) {
    show_window(app, "main");
}

fn refresh_tray_icon(app: &tauri::AppHandle) {
    let Some(tray) = app.tray_by_id("main") else { return };
    let state = app.state::<TrayState>();
    let alert_active = state.alert_until.lock().unwrap().map_or(false, |t| t > std::time::Instant::now());

    let bytes: &[u8] = if alert_active {
        include_bytes!("../icons/tray-yellow.png")
    } else {
        include_bytes!("../icons/tray-green.png")
    };

    if let Ok(icon) = Image::from_bytes(bytes) {
        let _ = tray.set_icon(Some(icon));
    }
}

fn start_tray_alert_timer(app: tauri::AppHandle) {
    let state = app.state::<TrayState>();
    *state.alert_until.lock().unwrap() = Some(std::time::Instant::now() + Duration::from_secs(3));
    refresh_tray_icon(&app);

    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        refresh_tray_icon(&handle);
    });
}

#[tauri::command]
fn set_tray_alert(app: tauri::AppHandle) {
    start_tray_alert_timer(app);
}

#[tauri::command]
fn set_tray_error(app: tauri::AppHandle, error: bool) {
    let Some(tray) = app.tray_by_id("main") else { return };
    let bytes: &[u8] = if error {
        include_bytes!("../icons/tray-red.png")
    } else {
        include_bytes!("../icons/tray-green.png")
    };
    if let Ok(icon) = Image::from_bytes(bytes) {
        let _ = tray.set_icon(Some(icon));
    }
}

#[tauri::command]
async fn check_update(_app: tauri::AppHandle) -> Result<Option<serde_json::Value>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let resp = ureq::get("https://api.github.com/repos/HP-jh/TarsSecureGuard/releases/latest")
            .set("Accept", "application/vnd.github+json")
            .set("User-Agent", "TarsSecureGuard-Desktop/4.11.0")
            .call()
            .map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
        let latest_tag = json["tag_name"].as_str().unwrap_or("").trim_start_matches('v');
        let current = env!("CARGO_PKG_VERSION");

        if latest_tag.is_empty() {
            return Ok(None);
        }

        let parse = |s: &str| -> Vec<u32> {
            s.split('.').filter_map(|p| p.parse().ok()).collect()
        };
        let latest_v = parse(latest_tag);
        let current_v = parse(current);

        if latest_v > current_v {
            let mut download_url = None;
            if let Some(assets) = json["assets"].as_array() {
                for asset in assets {
                    let name = asset["name"].as_str().unwrap_or("");
                    if (name.ends_with("-setup.exe") || name.ends_with(".exe")) && name.contains("windows") {
                        download_url = asset["browser_download_url"].as_str().map(String::from);
                        break;
                    }
                }
            }
            Ok(Some(serde_json::json!({
                "version": latest_tag,
                "current": current,
                "url": download_url,
                "body": json["body"].as_str().unwrap_or("")
            })))
        } else {
            Ok(None)
        }
    }).await.map_err(|e| e.to_string())?;

    result
}

pub fn run() {
    let sidecar_arc: Arc<Mutex<Option<CommandChild>>> = Arc::new(Mutex::new(None));

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarHandle(sidecar_arc.clone()))
        .manage(TrayState { alert_until: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![
            set_tray_alert,
            set_tray_error,
            check_update
        ])
        .setup(|app| {
            #[cfg(desktop)]
            {
                let app_h = app.handle().clone();
                let show_i = MenuItem::with_id(&app_h, "show", "打开面板", true, None::<&str>)
                    .unwrap_or_else(|_| panic!("menu item show"));
                let pause_i = MenuItem::with_id(&app_h, "pause", "暂停防护", true, None::<&str>)
                    .unwrap_or_else(|_| panic!("menu item pause"));
                let resume_i = MenuItem::with_id(&app_h, "resume", "恢复防护", true, None::<&str>)
                    .unwrap_or_else(|_| panic!("menu item resume"));
                let quit_i = MenuItem::with_id(&app_h, "quit", "退出", true, None::<&str>)
                    .unwrap_or_else(|_| panic!("menu item quit"));

                let menu = Menu::with_items(&app_h, &[&show_i, &pause_i, &resume_i, &quit_i])
                    .unwrap_or_else(|_| panic!("menu build"));

                let tray = TrayIconBuilder::with_id("main")
                    .tooltip("TarsSecureGuard 桌面客户端")
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event({
                        let app_h2 = app_h.clone();
                        move |app, event| match event.id.as_ref() {
                            "show" => focus_main_window(app),
                            "pause" => {
                                std::thread::spawn(move || {
                                    let _ = ureq::post("http://127.0.0.1:18889/api/admin/config")
                                        .set("Content-Type", "application/json")
                                        .send_string(r#"{"security.mode":"strict"}"#);
                                });
                                let _ = app_h2.tray_by_id("main")
                                    .and_then(|t| t.set_tooltip(Some("TarsSecureGuard — 已暂停")).ok());
                            }
                            "resume" => {
                                std::thread::spawn(move || {
                                    let _ = ureq::post("http://127.0.0.1:18889/api/admin/config")
                                        .set("Content-Type", "application/json")
                                        .send_string(r#"{"security.mode":"normal"}"#);
                                });
                                let _ = app_h2.tray_by_id("main")
                                    .and_then(|t| t.set_tooltip(Some("TarsSecureGuard 桌面客户端")).ok());
                            }
                            "quit" => app.exit(0),
                            _ => {}
                        }
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            focus_main_window(tray.app_handle());
                        }
                    })
                    .build(app)
                    .expect("tray icon build failed");

                if let Ok(icon) = Image::from_bytes(include_bytes!("../icons/tray-green.png")) {
                    let _ = tray.set_icon(Some(icon));
                }
            }

            let handle = app.handle().clone();
            let sidecar_arc_thread = sidecar_arc.clone();
            std::thread::spawn(move || {
                let (healthy, first_run) = gateway_health_with_first_run();
                if healthy {
                    close_window(&handle, "loading");
                    show_window(&handle, "main");
                    if first_run {
                        let _ = handle.emit("first-run", true);
                    }
                    return;
                }

                let data_dir = handle
                    .path()
                    .app_data_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."));
                let _ = std::fs::create_dir_all(&data_dir);
                let _ = std::env::set_current_dir(&data_dir);

                match handle.shell().sidecar("tsg") {
                    Ok(cmd) => match cmd.env("TSG_APP_DIR", &data_dir).args(["--no-browser"]).spawn() {
                        Ok((mut rx, child)) => {
                            *sidecar_arc_thread.lock().unwrap() = Some(child);
                            std::thread::spawn(move || {
                                while let Some(_ev) = rx.blocking_recv() {}
                            });
                        }
                        Err(e) => {
                            eprintln!("[tsg-desktop] sidecar 启动失败: {e}");
                            set_tray_error(handle.clone(), true);
                        }
                    },
                    Err(e) => {
                        eprintln!("[tsg-desktop] 未找到 sidecar 二进制: {e}");
                        set_tray_error(handle.clone(), true);
                    }
                }

                let mut first_run_detected = false;
                for _ in 0..100 {
                    let (ok, fr) = gateway_health_with_first_run();
                    if ok {
                        first_run_detected = fr;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }

                close_window(&handle, "loading");
                show_window(&handle, "main");
                if first_run_detected {
                    let _ = handle.emit("first-run", true);
                }
            });

            #[cfg(desktop)]
            {
                let h = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    match check_update(h.clone()).await {
                        Ok(Some(info)) => { let _ = h.emit("update-available", info); }
                        _ => {}
                    }
                });
            }

            Ok(())
        });

    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            focus_main_window(app);
        }));
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }

    let app = builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app, event| {
        match event {
            RunEvent::Exit => {
                let state = app.state::<SidecarHandle>();
                if let Some(mut child) = state.0.lock().unwrap().take() {
                    let _ = child.kill();
                }
            }
            RunEvent::WindowEvent { label, event: win_ev, .. } => {
                if label == "main" {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = win_ev {
                        api.prevent_close();
                        hide_window(app, "main");
                    }
                }
            }
            _ => {}
        }
    });
}
