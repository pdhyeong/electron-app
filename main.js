const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { exec } = require("child_process");
const path = require('path');
const fs = require("fs");
const {setfile, readdiretory , setdirectory, exec_extract_siege} = require('./handler');
let mainWindow;

const createWindow = () => {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, 
      enableRemoteModule: false,
      nodeIntegration: false,
      webSecurity: true,
    },
  });
  mainWindow.loadURL('http://localhost:3000'); // React 앱이 실행 중인 URL,
  mainWindow.webContents.openDevTools();
};

app.whenReady().then(() => {
    
    createWindow();

    ipcMain.handle('select-file', setfile);
    ipcMain.handle('get-directory-contents', readdiretory);
    ipcMain.handle("select-directory", setdirectory);
    ipcMain.on('message', exec_extract_siege);

    app.on('ready', () => {
        session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
            callback({
                responseHeaders: {
                    ...details.responseHeaders,
                    'Content-Security-Policy': ["default-src 'self'"]
                }
            });
        });
    });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
