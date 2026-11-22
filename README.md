<h1 align="center">📦 ZipCrackerN</h1>

<p align="center">
  <b>轻巧、原生的压缩包密码恢复工具</b><br>
  Windows 10 / 11 · Win32 原生界面 · 多线程 · 低内存
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-2.0-blue?style=flat-square">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=flat-square&logo=windows&logoColor=white">
  <img alt="UI" src="https://img.shields.io/badge/UI-Win32%20Native-6f42c1?style=flat-square">
  <img alt="Multithreading" src="https://img.shields.io/badge/multithreading-enabled-2ea44f?style=flat-square">
</p>

---

## 🚀 简介

**ZipCrackerN** 是一款用于找回压缩包密码的 Windows 桌面工具。  
支持 ZIP / RAR / 7z 压缩包，兼容 ZipCrypto、WinZip AES-128/192/256、Zip64 以及 RAR / 7z 加密；使用系统原生 Win32 控件打造界面，支持多线程并行搜索，并在保持低内存占用的同时快速尝试密码。

无需安装，下载后直接运行即可。

---

## ✨ 功能亮点

| | 功能 | 说明 |
|---|---|---|
| ⚡ | **多线程搜索** | 自动使用 CPU 逻辑核心，任务动态分配，速度更快 |
| 🧠 | **低内存设计** | 复用密钥与校验缓冲区，长时间运行也不易占用大量内存 |
| 🔐 | **多种压缩格式** | 支持 ZIP、RAR、7z 压缩包 |
| 🗜️ | **Zip64 支持** | 支持使用 Zip64 扩展的大文件压缩包 |
| 🔤 | **密码类型组合** | 大写字母、小写字母、数字可自由勾选 |
| 📏 | **长度范围** | 支持 1~12 位，输入框带上下箭头，调整更方便 |
| 🖱️ | **拖放选择** | 把压缩包文件从资源管理器直接拖进窗口即可 |
| 📋 | **一键复制** | 找到密码后直接复制到剪贴板 |
| ⏹️ | **随时停止** | 搜索过程中可立即停止，状态与结果实时显示 |
| 🪟 | **原生界面** | Windows 10 原生控件与视觉样式，简洁清晰 |
| 🖥️ | **高 DPI 适配** | Per-Monitor V2，最高适配 500% 缩放 |
| 🎯 | **窗口舒适** | 居中显示，限制最大尺寸，不占满全屏 |

---

## 🎛 界面与操作

- 选择压缩包：点击“浏览…”，或直接把文件拖进路径框
- 勾选需要的密码类型
- 使用上下按钮或键盘设置密码长度范围
- 点击“开始破解”
- 找到密码后，结果显示在“密码：”后方，可一键复制

界面会实时显示：

- 🔎 当前状态
- 🔢 已尝试次数
- ⚡ 每秒尝试速度
- 📏 当前长度 / 多线程状态

---

## 🔐 密码类型

| 类型 | 范围 |
|---|---|
| 🔠 大写字母 | `A-Z` |
| 🔡 小写字母 | `a-z` |
| 🔢 数字 | `0-9` |

三种类型可以任意组合，例如只勾选“小写字母 + 数字”即可搜索类似 `mi12` 的密码。

---

## 📦 兼容性

| 压缩包 / 加密 | 支持情况 |
|---|---|
| **ZIP**：ZipCrypto、WinZip AES-128/192/256 | ✅ 支持 |
| **ZIP**：Zip64 大文件 | ✅ 支持 |
| **RAR**：RAR 加密 | ✅ 支持 |
| **7z**：7z AES 加密 | ✅ 支持 |

RAR / 7z 的密码校验使用程序内置的 **7z\7z.exe** 完成，无需额外安装 7-Zip。

WinZip AES 使用 PBKDF2-HMAC-SHA1（1000 次迭代）校验密码，相同密码空间下速度会明显慢于 ZipCrypto；RAR / 7z 需要启动内置 7z.exe 校验，速度也会慢一些。

---

## 🚀 快速开始

1. 运行 `ZipCrackerN.exe`
2. 选择或拖入压缩包文件
3. 勾选密码类型并设置长度
4. 点击“开始破解”
5. 找到后复制密码

---

## 📌 版本

**ZipCrackerN 2.0**

- 文件说明：ZipCrackerN - 压缩包密码恢复工具
- 产品名称：ZipCrackerN
- 版权：Copyright © 2026 ZipCrackerN

---

<p align="center">
  <sub>📦 ZipCrackerN · 原生、轻巧、专注压缩包密码恢复</sub>
</p>
