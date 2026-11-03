"use strict";
const $ = (id) => document.getElementById(id);
let csrf = "", setupRequired = false, current = {}, torrents = [], filter = "all";
let selectedFolder = null, browsingFolder = ".", addMode = "file", timer, refreshing = false;
const labels = {connected:"Connected",connecting:"Connecting",disconnected:"Disconnected",not_configured:"Not configured",error:"Connection failed",unavailable:"Service starting"};

function vpnReady() { return current.vpn?.state === "connected" && current.vpn?.protected === true && current.vpn?.torrents_allowed === true; }
function showError(id, error) { const node=$(id); node.textContent=error?.message || String(error); node.hidden=false; }
function clearError(id) { $(id).hidden=true; $(id).textContent=""; }
function toast(message, error=false) { $("toast").textContent=message; $("toast").classList.toggle("error",error); $("toast").hidden=false; clearTimeout(toast.timer); toast.timer=setTimeout(()=>$("toast").hidden=true,5500); }
async function busy(button, action, label="Please wait…") { const text=button.textContent; button.disabled=true; button.textContent=label; try{return await action();} finally {button.disabled=false;button.textContent=text;} }
async function api(path, data) {
  const options={headers:{},credentials:"same-origin",signal:AbortSignal.timeout(35000)};
  if(data!==undefined){options.method="POST";options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data);}
  const response=await fetch(path,options); const value=await response.json();
  if(!response.ok){if(response.status===401&&!path.match(/login|setup/)){await initialize();}throw new Error(value.error||"Please try again.");}
  return value;
}
function view(name) {
  $("downloads-view").hidden=name!=="downloads"; $("settings-view").hidden=name!=="settings";
  $("nav-downloads").classList.toggle("selected",name==="downloads"); $("nav-settings").classList.toggle("selected",name==="settings");
  $("page-title").textContent=name==="downloads"?"Downloads":"Connection & storage";
  $("page-subtitle").textContent=name==="downloads"?"Your files, saved directly to your NAS.":"A private connection, managed in one place.";
  $("add-download").hidden=name!=="downloads";
}
function setFolder(path) { selectedFolder=path; const parts=path.split("/").filter(p=>p&&p!==".");$("selected-folder-name").textContent=parts.at(-1)||"Available storage";$("selected-folder-path").textContent="Available storage"+(parts.length?" / "+parts.join(" / "):""); }
function protocolChanged() {
  const xray=document.querySelector('input[name="protocol"]:checked').value==="xray";
  $("openvpn-fields").hidden=xray; $("xray-note").hidden=!xray;
  $("vpn-profile").accept=xray?".json":".ovpn";
  if(!$("vpn-profile").files.length)$("profile-label").textContent=xray?"Choose an Xray client JSON":"Choose an OpenVPN profile";
  $("profile-hint").textContent=xray?"Click to browse or drop your .json file here":"Click to browse or drop your .ovpn file here";
}
async function initialize() {
  clearInterval(timer);const session=await api("/api/session");csrf=session.csrf||"";setupRequired=session.setup_required;
  $("auth-screen").hidden=session.authenticated;$("app").hidden=!session.authenticated;
  if(!session.authenticated){$("auth-title").textContent=setupRequired?"Make yourself at home.":"Welcome back.";$("auth-description").textContent=setupRequired?"Create a password for your downloads app. Use at least 12 characters.":"Sign in to manage your private downloads.";$("setup-code-field").hidden=!setupRequired;$("confirm-field").hidden=!setupRequired;$("auth-submit").textContent=setupRequired?"Create account":"Sign in";$("login-password").autocomplete=setupRequired?"new-password":"current-password";return;}
  current=await api("/api/status");
  selectedFolder=current.download_dir??null;if(selectedFolder!==null)setFolder(selectedFolder);
  if(current.vpn?.protocol){document.querySelector(`input[name="protocol"][value="${current.vpn.protocol}"]`).checked=true;protocolChanged();}
  view(current.configured?"downloads":"settings");await refresh();timer=setInterval(refresh,5000);
}
async function refresh() {
  if(refreshing||$("app").hidden)return;refreshing=true;
  try {
    const [status,downloads]=await Promise.allSettled([api("/api/status"),api("/api/torrents")]);
    if(status.status==="fulfilled")current=status.value;
    if(downloads.status==="fulfilled")torrents=downloads.value.torrents||[];
    renderStatus();renderTorrents();
  } catch(error){toast(error.message,true);}finally{refreshing=false;}
}
function renderStatus() {
  const vpn=current.vpn||{},state=vpn.state||"unavailable",connected=vpnReady();
  for(const id of ["connection-badge","settings-status"]){$(id).textContent=labels[state]||"Unavailable";$(id).className="badge "+(connected?"connected":state==="connecting"?"connecting":state==="error"?"error":"neutral");}
  $("connection-title").textContent=labels[state]||"Unavailable";
  $("connection-detail").textContent=connected?`${vpn.protocol==="xray"?"Xray":"OpenVPN"} · ${vpn.external_ip||"Private connection"}`:state==="connecting"?"Connecting to your VPN service…":"Downloads wait for a VPN connection";
  $("settings-status-description").textContent=connected?`Your downloads use ${vpn.external_ip||"your VPN"}.`:state==="error"?"Could not connect. Check your profile and credentials. The app will keep trying.":state==="connecting"?"Connecting and checking Internet access. This can take a minute.":state==="disconnected"?"VPN off. Transmission is stopped. Connect to resume downloads.":"Upload a profile to get connected.";
  $("toggle-vpn").disabled=!vpn.protocol;$("toggle-vpn").textContent=connected||state==="connecting"?"Disconnect":"Connect";
  $("add-download").disabled=!connected||!current.configured;
  $("empty-add").textContent=current.configured?"Add your first download ＋":"Set up your connection →";
  $("setup-banner").hidden=!!current.configured;
  $("destination-summary").textContent=current.download_dir===null||current.download_dir===undefined?"Choose where your files will be saved.":"Saving to Available storage"+(current.download_dir!=="."?" / "+current.download_dir:"");
  if(vpn.profile_name){$("saved-profile").hidden=false;$("saved-profile").textContent=`Saved profile: ${vpn.profile_name}. Choose a new file only to replace it.`;}
}
function formatBytes(number, speed=false) {const units=speed?["B/s","KB/s","MB/s","GB/s"]:["B","KB","MB","GB","TB"];let size=Number(number)||0,index=0;while(size>=1024&&index<units.length-1){size/=1024;index++;}return `${size<10&&index?size.toFixed(1):Math.round(size)} ${units[index]}`;}
function speedStat(id,number){const [amount,unit]=formatBytes(number,true).split(" ");$(id).replaceChildren(document.createTextNode(amount+" "));const small=document.createElement("small");small.textContent=unit;$(id).append(small);}
function node(tag,className,text){const element=document.createElement(tag);if(className)element.className=className;if(text!==undefined)element.textContent=text;return element;}
function renderTorrents(){
  if(!vpnReady())torrents=torrents.map(t=>({...t,status:0,rateDownload:0,rateUpload:0,vpnBlocked:true}));
  $("nav-count").textContent=$("torrent-count").textContent=String(torrents.length);
  speedStat("download-speed",torrents.reduce((sum,t)=>sum+t.rateDownload,0));speedStat("upload-speed",torrents.reduce((sum,t)=>sum+t.rateUpload,0));
  const visible=torrents.filter(t=>filter==="all"||(filter==="active"?t.status!==0&&t.percentDone<1:t.percentDone>=1));
  $("torrent-empty").hidden=visible.length>0;$("torrent-list").replaceChildren();
  for(const torrent of visible){const row=node("article","torrent-row"),body=node("div"),actions=node("div","torrent-actions");body.append(node("div","torrent-name",torrent.name));const status=torrent.vpnBlocked?"Waiting for VPN":["Paused","Waiting to check","Checking","Queued","Downloading","Queued to seed","Seeding"][torrent.status]||"Waiting";body.append(node("p","torrent-description",`${status} · ${Math.round(torrent.percentDone*100)}% of ${formatBytes(torrent.totalSize)} · ↓ ${formatBytes(torrent.rateDownload,true)} · ↑ ${formatBytes(torrent.rateUpload,true)}`));const progress=node("progress","torrent-progress");progress.max=1;progress.value=torrent.percentDone;progress.setAttribute("aria-label",torrent.name+" progress");body.append(progress);if(torrent.errorString)body.append(node("p","torrent-error",torrent.errorString));
    for(const [action,symbol,label]of [[torrent.status===0?"start":"stop",torrent.status===0?"▷":"Ⅱ",torrent.status===0?"Resume":"Pause"],["remove","×","Remove"]]){const button=node("button","icon-button",symbol);button.setAttribute("aria-label",label+" "+torrent.name);button.title=torrent.vpnBlocked?"Connect VPN first":label;button.disabled=Boolean(torrent.vpnBlocked);button.onclick=async()=>{if(action==="remove"&&!confirm("Remove this download from the list? Downloaded files will stay in their folder."))return;try{button.disabled=true;await api("/api/torrents/action",{id:torrent.id,action});await refresh();}catch(error){toast(error.message,true);button.disabled=false;}};actions.append(button);}row.append(body,actions);$("torrent-list").append(row);}
}
async function browse(path="."){
  clearError("folder-error");try{const result=await api("/api/folders?path="+encodeURIComponent(path));browsingFolder=result.path;$("folder-breadcrumbs").replaceChildren();const parts=result.path.split("/").filter(p=>p&&p!==".");const root=node("button",null,"Available storage");root.onclick=()=>browse(".");$("folder-breadcrumbs").append(root);parts.forEach((part,i)=>{const button=node("button",null,part);button.onclick=()=>browse(parts.slice(0,i+1).join("/"));$("folder-breadcrumbs").append(document.createTextNode(" / "),button);});$("folder-entries").replaceChildren();for(const name of result.folders){const button=node("button","folder-entry");button.append(node("span",null,"▱  "+name),node("span",null,"→"));button.onclick=()=>browse((result.path==="."?"":result.path+"/")+name);$("folder-entries").append(button);}if(!result.folders.length)$("folder-entries").append(node("p","folder-empty","No subfolders here. You can use this folder or create a new one."));}catch(error){showError("folder-error",error);}
}
async function upload(file){if(file.size>2*1024*1024)throw new Error("Choose files smaller than 2 MB.");return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve({name:file.name,data:String(reader.result).split(",")[1]});reader.onerror=()=>reject(new Error("That file could not be read."));reader.readAsDataURL(file);});}
function openAdd(){if(!current.configured){view("settings");return;}if(!vpnReady()){toast("Connect your VPN before adding a download.",true);view("settings");return;}clearError("add-error");$("add-destination").textContent="Saving to Available storage"+(current.download_dir!=="."?" / "+current.download_dir:"");$("add-dialog").showModal();}

$("auth-form").onsubmit=async(event)=>{event.preventDefault();clearError("auth-error");try{if(setupRequired&&$("login-password").value!==$("confirm-password").value)throw new Error("The two passwords do not match.");await busy($("auth-submit"),async()=>{const result=await api(setupRequired?"/api/setup":"/api/login",{password:$("login-password").value,code:$("setup-code").value.trim()});csrf=result.csrf;$("auth-form").reset();await initialize();},setupRequired?"Creating account…":"Signing in…");}catch(error){showError("auth-error",error);}};
$("logout").onclick=async()=>{try{await api("/api/logout",{});await initialize();}catch(error){toast(error.message,true);}};
$("nav-downloads").onclick=()=>view("downloads");$("nav-settings").onclick=$("go-setup").onclick=()=>view("settings");
$("add-download").onclick=$("empty-add").onclick=openAdd;
document.querySelectorAll('[name="protocol"]').forEach(input=>input.onchange=()=>{$("vpn-profile").value="";protocolChanged();});
$("vpn-profile").onchange=()=>{if($("vpn-profile").files[0])$("profile-label").textContent=$("vpn-profile").files[0].name;};
$("torrent-files").onchange=()=>{$("torrent-file-label").textContent=$("torrent-files").files.length?`${$("torrent-files").files.length} file(s) selected`:"Choose torrent files";};
$("browse-folders").onclick=async()=>{$("folder-dialog").showModal();await browse(selectedFolder||".");};
$("choose-folder").onclick=()=>{setFolder(browsingFolder);$("folder-dialog").close();};
$("new-folder-form").onsubmit=async(event)=>{event.preventDefault();clearError("folder-error");try{const result=await api("/api/folders",{path:browsingFolder,name:$("new-folder-name").value.trim()});$("new-folder-name").value="";await browse(result.path);}catch(error){showError("folder-error",error);}};
$("settings-form").onsubmit=async(event)=>{event.preventDefault();clearError("settings-error");try{if(selectedFolder===null)throw new Error("Choose a download folder first.");const file=$("vpn-profile").files[0],protocol=document.querySelector('input[name="protocol"]:checked').value;if(!file&&(!current.vpn?.protocol||protocol!==current.vpn.protocol))throw new Error("Choose a profile for the selected connection.");await busy($("save-settings"),async()=>{if(file){const assets=await Promise.all(Array.from($("vpn-assets").files).map(upload));await api("/api/configure",{protocol,profile:await upload(file),assets,username:$("vpn-user").value,password:$("vpn-password").value,download_dir:selectedFolder});}else{await api("/api/folder",{path:selectedFolder});await api("/api/vpn/connect",{});}$("vpn-password").value="";$("vpn-user").value="";$("vpn-profile").value="";$("vpn-assets").value="";protocolChanged();await refresh();toast("Saved. Your connection is getting ready.");view("downloads");},"Saving & connecting…");}catch(error){showError("settings-error",error);}};
$("toggle-vpn").onclick=async()=>{try{await busy($("toggle-vpn"),async()=>{const action=["connected","connecting"].includes(current.vpn?.state)?"disconnect":"connect";await api("/api/vpn/"+action,{});});await refresh();}catch(error){toast(error.message,true);}};
document.querySelectorAll("[data-close]").forEach(button=>button.onclick=()=>$(button.dataset.close).close());
document.querySelectorAll("[data-filter]").forEach(button=>button.onclick=()=>{filter=button.dataset.filter;document.querySelectorAll("[data-filter]").forEach(b=>b.classList.toggle("selected",b===button));renderTorrents();});
document.querySelectorAll("[data-add-mode]").forEach(button=>button.onclick=()=>{addMode=button.dataset.addMode;$("torrent-file-field").hidden=addMode!=="file";$("magnet-field").hidden=addMode!=="magnet";document.querySelectorAll("[data-add-mode]").forEach(b=>b.classList.toggle("selected",b===button));});
$("add-form").onsubmit=async(event)=>{event.preventDefault();clearError("add-error");try{await busy($("submit-download"),async()=>{if(addMode==="magnet"){await api("/api/torrents",{magnet:$("magnet-link").value.trim()});}else{const files=Array.from($("torrent-files").files);if(!files.length)throw new Error("Choose at least one torrent file.");for(const file of files){if(!file.name.toLowerCase().endsWith(".torrent"))throw new Error("Choose a .torrent file.");await api("/api/torrents",{torrent:(await upload(file)).data});}}$("add-form").reset();$("torrent-file-label").textContent="Choose torrent files";$("add-dialog").close();await refresh();toast("Download added.");},"Adding…");}catch(error){showError("add-error",error);}};
for(const [zoneId,inputId]of [["profile-zone","vpn-profile"]]){const zone=$(zoneId);for(const name of ["dragover","dragleave","drop"])zone.addEventListener(name,event=>{event.preventDefault();zone.classList.toggle("dragover",name==="dragover");if(name==="drop"&&event.dataTransfer.files.length){$(inputId).files=event.dataTransfer.files;$(inputId).dispatchEvent(new Event("change"));}});}
initialize().catch(error=>{toast("The app is starting. Refresh this page in a moment.",true);$("auth-screen").hidden=false;});
