const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { exec } = require("child_process");
const path = require('path');
const fs = require("fs");

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
  // 메시지 수신 처리
    ipcMain.handle('select-file', async () => {
        const result = await dialog.showOpenDialog({
        properties: ['openFile'],
        });
        if (result.canceled) return null;
        return result.filePaths[0]; // 선택된 파일 경로 반환
    });
    ipcMain.handle("select-directory", async () => {
        const result = await dialog.showOpenDialog({
        properties: ["openDirectory"], // 폴더 선택 모드
        });
        if (result.canceled) return null; // 선택 취소 시
        return result.filePaths[0]; // 선택된 폴더 경로 반환
    });
    
    ipcMain.on('message', (event, arg) => {
        // 메시지 응답
        const siege_extract_cmd = 'siege -e';
        const extract_file_path = arg.extract_file;
        const result_direct = arg.direct;
        exec(`${siege_extract_cmd} ${extract_file_path} ${result_direct}`, (error, stdout, stderr) => {
            if (error) {
            console.error(`exec error: ${error}`);
            event.reply('result',error);
            reject(error.message);
            }
            if (stderr) {
            console.error(`stderr: ${stderr}`);
            event.reply('result',error);
            reject(stderr);
            }
            console.log(stdout);
            event.reply('result',"extract Success");
        });
    });
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
