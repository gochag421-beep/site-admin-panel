const {BrowserWindow}=require('electron');const {reportHtml}=require('../src/report-html');
async function createPDF(report,project,brand){
  const win=new BrowserWindow({show:false,webPreferences:{sandbox:true,nodeIntegration:false,contextIsolation:true,javascript:false}});
  win.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  try{await win.loadURL('data:text/html;charset=utf-8,'+encodeURIComponent(reportHtml(report,project,brand)));
    return await win.webContents.printToPDF({printBackground:true,preferCSSPageSize:true,displayHeaderFooter:true,headerTemplate:'<span></span>',footerTemplate:'<div style="width:100%;text-align:center;font-size:9px;color:#738196"><span class="pageNumber"></span> / <span class="totalPages"></span></div>'});
  }finally{win.destroy();}
}
module.exports={createPDF};
