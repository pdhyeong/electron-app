// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
  sendMessage: (channel, data) => ipcRenderer.send(channel, data),
  onMessage: (channel, callback) => ipcRenderer.on(channel, (event, ...args) => callback(...args)),
  selectFile: () => ipcRenderer.invoke("select-file"),
  selectDirectory: () => ipcRenderer.invoke("select-directory")
});