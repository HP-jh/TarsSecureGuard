# TSG Android MVP (v4.2.0)

TarsSecureGuard 安卓客户端最小可跑版本。

## 功能

- 控制：启动/停止 TSG 网关服务
- 状态：查看服务运行状态、运行时长、代理/设备/隔离节点统计
- 配置：编辑监听地址、最大日志大小、网关启用、开机自启动
- 日志：查看日志文件列表、刷新、分享选中日志

## 架构

- **Kotlin Shell**：Material 3 UI，4 个 Fragment 对应 4 个功能
- **Go Backend**：`cmd/tsg-android/` 编译为 `android-arm64` 二进制，打包进 `assets/`
- **通信**：Kotlin 通过 HTTP 调用 Go 服务（127.0.0.1:18080）
- **持久化**：配置存 SharedPreferences，开机自启通过 `BootReceiver`
- **日志导出**：通过 `FileProvider` 分享日志文件

## 构建

### 前置条件

- JDK 17
- Android SDK（API 24 ~ 34）
- Gradle 8.x

### 步骤

1. 初始化 Gradle 包装器（在项目根目录已有 `gradle/wrapper/` 配置）：
   ```bash
   cd android
   gradle wrapper --gradle-version 8.4
   ```

2. 构建 Debug APK：
   ```bash
   ./gradlew assembleDebug
   ```

3. 安装到设备：
   ```bash
   adb install app/build/outputs/apk/debug/app-debug.apk
   ```

### 沙箱环境

沙箱无 Android SDK，无法直接构建 APK。Go 二进制已交叉编译并放置在 `app/src/main/assets/tsg-android-arm64`，用户需在本地构建 APK。

## 文件结构

```
android/
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
└── app/
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        ├── assets/
        │   └── tsg-android-arm64     # Go 后端二进制
        ├── java/com/tarssecureguard/android/
        │   ├── MainActivity.kt
        │   ├── service/
        │   │   ├── ServiceManager.kt # 启动/停止 Go 服务
        │   │   └── BootReceiver.kt   # 开机自启
        │   └── ui/
        │       ├── ControlFragment.kt
        │       ├── StatusFragment.kt
        │       ├── ConfigFragment.kt
        │       └── LogsFragment.kt
        └── res/
            ├── drawable/
            ├── layout/
            ├── menu/
            ├── mipmap-anydpi-v26/
            ├── navigation/
            ├── values/
            └── xml/
```

## Go 后端 API

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api/status` | GET | 服务状态 + 网关统计 |
| `/api/start` | POST | 启动网关 |
| `/api/stop` | POST | 停止网关 |
| `/api/config` | GET/POST | 获取/保存配置 |
| `/api/logs` | GET | 日志文件列表 |
| `/api/logs/download?name=X` | GET | 下载日志文件 |
| `/api/assistant/health` | GET | 助手服务健康检查 |

## 测试

端到端测试在真机/模拟器进行：
1. 安装 APK
2. 启动应用，授权通知/自启权限
3. 切换到「控制」页 → 点击「启动服务」
4. 切换到「状态」页 → 点击「刷新」，应看到运行数据
5. 切换到「配置」页 → 修改配置 → 保存
6. 切换到「日志」页 → 刷新 → 选中日志 → 分享

## 版本

- v4.2.0
- Go 后端: 5.4 MB (arm64, stripped)
- Min SDK: 24 (Android 7.0)
- Target SDK: 34 (Android 14)
