const { app, BrowserWindow, ipcMain, protocol, session } = require("electron");
const path = require("path");
const fs = require("fs");
const {
    read_Diretory,
    exec_Extract_Siege,
    openDialog,
    readTreeStructure,
    openExplorer,
    start_Siege
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
        autoHideMenuBar: true
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
    ipcMain.handle("get-directory-contents", read_Diretory);
    ipcMain.handle("get-tree-contents", readTreeStructure);
    ipcMain.on("exec-siege", exec_Extract_Siege);
    ipcMain.on("open-exploer",openExplorer);
    ipcMain.on("generate-siege",start_Siege);

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
