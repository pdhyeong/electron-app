const { app, BrowserWindow, ipcMain, protocol, session } = require("electron");
const path = require("path");
const fs = require("fs");
const {
    readdiretory,
    exec_extract_siege,
    openDialog,
    readTreeStructure,
    open_explorer,
    start_siege
} = require("./handler");

let mainWindow;

const createWindow = () => {
    mainWindow = new BrowserWindow({
        width: 1100,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            contextIsolation: true,
            enableRemoteModule: false,
            nodeIntegration: false,
            webSecurity: true,
        },
    });

    //const url = `file://${join(__dirname,'./siege/build/index.html')}` | `http://localhost:3000`;
    mainWindow.loadURL("http://localhost:3000"); 
    // React 앱이 실행 중인 URL,
    //mainWindow.webContents.openDevTools();
};

app.whenReady().then(() => {
    createWindow();

    ipcMain.handle("select-file", () => openDialog("file"));
    ipcMain.handle("select-directory", () => openDialog("directory"));
    ipcMain.handle("get-directory-contents", readdiretory);
    ipcMain.handle("get-tree-contents", readTreeStructure);
    ipcMain.on("exec-siege", exec_extract_siege);
    ipcMain.on("open-exploer",open_explorer);
    ipcMain.on("generate-siege",start_siege);

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
