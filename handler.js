const { dialog } = require('electron');
const fs = require('path');
const {exec} = require('child_process');

const setfile = async () => {
    const result = await dialog.showOpenDialog({
    properties: ['openFile'],
    });
    if (result.canceled) return null;
    return result.filePaths[0]; // 선택된 파일 경로 반환
};

const readdiretory = async (event, dirPath) => {
  return fs.promises.readdir(dirPath, { withFileTypes: true })
      .then(contents => contents.map(item => ({
          name: item.name,
          isDirectory: item.isDirectory(),
      })))
      .catch(err => { throw err; });
  };

const setdirectory = async () => {
    const result = await dialog.showOpenDialog({
    properties: ["openDirectory"],
    });
    if (result.canceled) return null;
    return result.filePaths[0];
};

const exec_extract_siege = (event, arg) => {
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
};

module.exports = {setfile, readdiretory , setdirectory, exec_extract_siege};