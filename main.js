const { app, BrowserWindow } = require('electron')
var debug = /--debug/.test(process.argv[2])

var mainWindow = null;

app.on('window-all-closed', function() {
  //if (process.platform != 'darwin') {
    app.quit();
  //}
});

app.on('ready', function() {
  var env = Object.create( process.env );
  env.LC_ALL = 'en_US.UTF-8';
  env.LANG = 'en_US.UTF-8';
  var subpy = require('child_process').spawn('./venv/bin/python', ['./app.py'], {env: env});
  var rq = require('request-promise');
  var mainAddr = 'http://localhost:5000';

  var openWindow = function(){
    mainWindow = new BrowserWindow({width: 800, height: 600});
    mainWindow.loadURL(mainAddr);
    mainWindow.on('closed', function() {
      mainWindow = null;
      subpy.kill('SIGINT');
    });

    /* Launch debug tools, usage: npm run debug */
    if (debug) {
      mainWindow.webContents.openDevTools();
    }
  };

  var startUp = function(){
    rq(mainAddr)
      .then(function(htmlString){
        console.log('server started!');
        openWindow();
      })
      .catch(function(err){
        // console.log('waiting for the server start...');
        startUp();
      });
  };

  // fire!
  startUp();
});

