//! TarsSecureGuard v4.11.0 桌面客户端壳（Tauri 2）
//!
//! v4.11.0 七项桌面客户端功能完整实现：
//! 1. 系统托盘（三态图标 + 菜单 + 关闭到托盘）
//! 2. 启动 loading 窗口（800x500，/health 就绪后切换主窗口）
//! 3. Windows 管理员权限（requestedExecutionLevel=requireAdministrator）
//! 4. 自更新器（tauri-plugin-updater + GitHub Releases 检测）
//! 5. SSE 实时事件流（前端 EventSource → Rust tray 闪烁命令）
//! 6. release.yml 补全（Tauri 交叉编译 + 多平台安装包）
//! 7. 首次运行引导（3 步：选模型 → 填 API key → 完成）

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, RunEvent};
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

const GATEWAY_PORT: u16 = 18889;
const HEALTH_PATH: &str = "/health";

struct SidecarHandle(Mutex<Option<CommandChild>>);
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

fn handle_deep_link_url(app: &tauri::AppHandle, url: &str) {
    eprintln!("[tsg-desktop] deep-link received: {url}");
    if let Some(path) = url.strip_prefix("tsg://") {
        let _ = app.emit("deeplink", path);
    }
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

fn start_tray_alert_timer(app: &tauri::AppHandle) {
    let state = app.state::<TrayState>();
    *state.alert_until.lock().unwrap() = Some(std::time::Instant::now() + Duration::from_secs(3));
    refresh_tray_icon(app);

    let handle = app.handle().clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        refresh_tray_icon(&handle);
    });
}

#[tauri::command]
fn set_tray_alert(app: tauri::AppHandle) {
    start_tray_alert_timer(&app);
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

/// v4.11.0：查询更新（GitHub API）——spawn_blocking 内用 ureq 做同步 HTTPS
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Option<serde_json::Value>, String> {
    let handle = app.handle().clone();
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

        let newer = latest_v > current_v;

        if newer {
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
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_deep_link::init())
        .manage(SidecarHandle(Mutex::new(None)))
        .manage(TrayState { alert_until: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![
            set_tray_alert,
            set_tray_error,
            check_update
        ])
        .setup(|app| {
            #[cfg(desktop)]
            {
                let handle = app.handle().clone();
                if let Ok(deep_link) = handle.deep_link() {
                    let _ = deep_link.register("tsg");
                    let _ = deep_link.register("tsg-installer");
                }
            }

            // v4.11.0：系统托盘
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
                                let h = app_h2.clone();
                                std::thread::spawn(move || {
                                    let _ = ureq::post("http://127.0.0.1:18889/api/admin/config")
                                        .set("Content-Type", "application/json")
                                        .send_string(r#"{"security.mode":"strict"}"#);
                                });
                                let _ = app_h2.tray_by_id("main")
                                    .and_then(|t| t.set_tooltip(Some("TarsSecureGuard — 已暂停")).ok());
                            }
                            "resume" => {
                                let h = app_h2.clone();
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
                            handle.state::<SidecarHandle>().0.lock().unwrap().replace(child);
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

            // v4.11.0：延迟检查更新
            #[cfg(desktop)]
            {
                let h = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tauri::async_runtime::sleep(Duration::from_secs(5)).await;
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
            RunEvent::Opened { urls } => {
                for url in urls {
                    handle_deep_link_url(app, &url.to_string());
                }
                focus_main_window(app);
            }
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
