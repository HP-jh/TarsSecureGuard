//! TarsSecureGuard v4.6.0 桌面客户端壳（Tauri 2）
//!
//! 职责（最小壳原则——UI 与业务逻辑全部复用 Go 网关 embed 的管理台）：
//! 1. 启动时探活 `127.0.0.1:18889/health`：已有网关实例（CLI / systemd 起的）
//!    进入"连接模式"复用，不重复拉起；
//! 2. 无实例则以 sidecar 拉起网关二进制（`--no-browser` 抑制打开浏览器），
//!    数据目录经 `TSG_APP_DIR` 指向系统用户数据目录——桌面安装位置
//!    （Program Files、/usr/bin、AppImage 只读 squashfs）不可写；
//! 3. 轮询 /health 就绪后显示窗口；前端资产由 Tauri 服务（tauri://localhost），
//!    api() 跨源请求由网关 isTrustedOrigin 信任 + CORS 放行（Go 侧已收口）；
//! 4. 退出时终止本壳拉起的 sidecar（连接模式不触碰外部实例的生命周期）。
//! 5. v4.6.0 新增：deep-link 协议注册（tsg:// + tsg-installer://）+
//!    single-instance 单实例锁 +
//!    Opened 事件处理（deep link 打开时聚焦窗口）。
//!
//! v4.6.0 明确不做（留 v4.7.0+）：自更新器、系统托盘、WS 事件流。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use tauri::Manager;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

/// 网关默认端口（Go 侧 main.go 同值；CLI -port 自定义端口的实例不做连接探测）
const GATEWAY_PORT: u16 = 18889;
const HEALTH_PATH: &str = "/health";

/// sidecar 句柄；None = 连接模式（网关由外部拉起，不拥有其生命周期）
struct SidecarHandle(Mutex<Option<CommandChild>>);

/// 探活网关 /health（免鉴权公共路由）。零依赖：手写最小 HTTP GET。
fn gateway_healthy() -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", GATEWAY_PORT)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!(
        "GET {HEALTH_PATH} HTTP/1.1\r\nHost: 127.0.0.1:{GATEWAY_PORT}\r\nConnection: close\r\n\r\n"
    );
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// v4.6.0：聚焦主窗口（供 single-instance 回调与 deep-link 复用）
fn focus_main_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
        // 尝试将窗口提到最前（各平台行为略有差异）
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let _ = win.set_always_on_top(true);
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        std::thread::sleep(std::time::Duration::from_millis(50));
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let _ = win.set_always_on_top(false);
    }
}

/// v4.6.0：处理 deep-link URL，通知前端导航到对应页面
fn handle_deep_link_url(app: &tauri::AppHandle, url: &str) {
    eprintln!("[tsg-desktop] deep-link received: {url}");
    // 提取路径部分通知前端（如 tsg://settings → 导航到设置页）
    if let Some(path) = url.strip_prefix("tsg://") {
        let _ = app.emit("deeplink", path);
    }
}

pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_deep_link::init())
        .manage(SidecarHandle(Mutex::new(None)))
        .setup(|app| {
            // v4.6.0：注册 deep-link schemes（桌面端）
            #[cfg(desktop)]
            {
                let handle = app.handle().clone();
                if let Ok(deep_link) = handle.deep_link() {
                    let _ = deep_link.register("tsg");
                    let _ = deep_link.register("tsg-installer");
                }
            }

            let handle = app.handle().clone();
            std::thread::spawn(move || {
                // ① 探活：已有网关实例 → 连接模式，仅承载窗口
                if gateway_healthy() {
                    show_main_window(&handle);
                    return;
                }

                // ② 数据目录：系统用户数据目录（安装目录不可写）
                let data_dir = handle
                    .path()
                    .app_data_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."));
                if let Err(e) = std::fs::create_dir_all(&data_dir) {
                    eprintln!(
                        "[tsg-desktop] 无法创建数据目录 {}: {e}",
                        data_dir.display()
                    );
                }
                let _ = std::env::set_current_dir(&data_dir);

                // ③ 以 sidecar 拉起网关
                match handle.shell().sidecar("tsg") {
                    Ok(cmd) => match cmd.env("TSG_APP_DIR", &data_dir).args(["--no-browser"]).spawn() {
                        Ok((mut rx, child)) => {
                            handle
                                .state::<SidecarHandle>()
                                .0
                                .lock()
                                .unwrap()
                                .replace(child);
                            std::thread::spawn(move || {
                                while let Some(_ev) = rx.blocking_recv() {}
                            });
                        }
                        Err(e) => {
                            eprintln!("[tsg-desktop] sidecar 启动失败: {e}");
                        }
                    },
                    Err(e) => eprintln!("[tsg-desktop] 未找到 sidecar 二进制: {e}"),
                }

                // ④ 轮询就绪（300ms × 100 = 上限 30s），就绪或超时均显示窗口
                for _ in 0..100 {
                    if gateway_healthy() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }
                show_main_window(&handle);
            });
            Ok(())
        });

    // v4.6.0：single-instance 插件——已有实例时聚焦窗口而非启动新实例
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        focus_main_window(app);
    }));

    builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            match event {
                // v4.6.0：处理 deep-link 打开（协议调起或文件关联）
                tauri::RunEvent::Opened { urls } => {
                    for url in urls {
                        handle_deep_link_url(app, &url.to_string());
                    }
                    focus_main_window(app);
                }
                tauri::RunEvent::Exit => {
                    // ⑤ 退出清理：仅终止本壳拉起的 sidecar
                    let state = app.state::<SidecarHandle>();
                    if let Some(mut child) = state.0.lock().unwrap().take() {
                        let _ = child.kill();
                    }
                }
                _ => {}
            }
        });
}
