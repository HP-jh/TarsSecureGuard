//! TarsSecureGuard v3.2.1 桌面客户端壳（Tauri 2）
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
//!
//! v3.2.1 明确不做（留 v3.2.2+）：Job Object 兜底、updater、系统托盘、
//! 单实例锁、WS 事件流。壳被强杀时 sidecar 可能残留为已知限制（正常关窗不残留）。

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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarHandle(Mutex::new(None)))
        .setup(|app| {
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
                // 网关内少量 cwd 相对路径（state/）也随主进程 cwd 落到数据目录
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
                            // 回收 stdout/stderr 事件流，防止子进程管道写满阻塞
                            std::thread::spawn(move || {
                                while let Some(_ev) = rx.blocking_recv() {}
                            });
                        }
                        Err(e) => {
                            // 前端启动遮罩超时会给出提示；仍显示窗口便于排查
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
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // ⑤ 退出清理：仅终止本壳拉起的 sidecar
                let state = app.state::<SidecarHandle>();
                if let Some(mut child) = state.0.lock().unwrap().take() {
                    let _ = child.kill();
                }
            }
        });
}
