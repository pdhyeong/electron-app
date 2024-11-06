const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const { exec } = require("child_process");
const path = require("path");
const fs = require("fs");
const { readdiretory, exec_extract_siege, openDialog, save_userData } = require("./handler");
let mainWindow;

const createWindow = () => {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            contextIsolation: true,
            enableRemoteModule: false,
            nodeIntegration: false,
            webSecurity: true,
        },
    });
    mainWindow.loadURL("http://localhost:3000"); // React 앱이 실행 중인 URL,
    mainWindow.webContents.openDevTools();
};

app.whenReady().then(() => {
    createWindow();

    ipcMain.handle("select-file", () => openDialog("file"));
    ipcMain.handle("select-directory", () => openDialog("directory"));
    ipcMain.handle("get-directory-contents", readdiretory);
    ipcMain.on("message", exec_extract_siege);
    ipcMain.on("save-user-data", save_userData);

    app.on("ready", () => {
        session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
            callback({
                responseHeaders: {
                    ...details.responseHeaders,
                    "Content-Security-Policy": ["default-src 'self'"],
                },
            });
        });
    });
});

app.on("window-all-closed", () => {
    if (process.platform !== "darwin") app.quit();
});
