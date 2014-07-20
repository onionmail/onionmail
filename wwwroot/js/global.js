
var server="";

function getHTTPObject() {
	  var xmlhttp;
	  /*@cc_on
	  @if (@_jscript_version >= 5)
	    try {
	      xmlhttp = new ActiveXObject("Msxml2.XMLHTTP");
	    } catch (e) {
	      try {
	        xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
	      } catch (E) {
	        xmlhttp = false;
	      }
	    }
	  @else
	  xmlhttp = false;
	  @end @*/
	  if (!xmlhttp && typeof XMLHttpRequest != 'undefined') {
	    try {
	      xmlhttp = new XMLHttpRequest();
	    } catch (e) {
	      xmlhttp = false;
	    }
	  }
	  return xmlhttp;
}

function AJAXService(file,object,callback) {
	var post = JSON.stringify(object);
	var HTTP1 = new getHTTPObject();
	if (!HTTP1 || typeof HTTP1 == 'undefined') {
		APP.Perro("AJAX not supported!");
		return false;
		}	
		
	if (file.charAt(0)!='/') file=server+file;
	
	HTTP1.open('POST',file,true);
	HTTP1.setRequestHeader("Content-Type", "application/json");

	HTTP1.onreadystatechange= function () {
		if (HTTP1.readyState == 4) {
			if (HTTP1.status!=200) {
				if (HTTP1.statusText) if (HTTP1.statusText.length>0) alert('Server status error:\n'+HTTP1.statusText);
				
				} else {
				try {
					post=JSON.parse(HTTP1.responseText );
					} catch(err) { 
					alert('Data Error\n'+HTTP1.responseText);
					return false;
					}
				return callback(post);		   
				} 
			}
		
		}
	HTTP1.send(post);
}


function toHTML(st) {
	if (st==null) st="";
	st=""+st;
	st=st.replace("&","&amp;");
	st=st.replace("<","&lt;");
	st=st.replace(">","&gt;");
	st=st.replace('"',"&quot;");
	st=st.replace("'","&#39;");
	return st;
	}

function stripTags(st) {
	var q="";
	var cx=st.length;
	var c=0;
	for(var ax=0;ax<cx;ax++) {
	        var ch=st.charAt(ax);
	        if (ch=='<') {
			c++;
			q+=" ";
			}
		if (c==0) q+=ch;
	        if (ch=='>') { 
			c--;
			if (c<0) c=0;
			}
	
		}
	
	q=q.replace("<","&lt;");
	q=q.replace(">","&gt;");
	q=q.replace("&nbsp;"," ");
	return q;
	}

function SysCall(api,par) {
	if (HOOK.OnSysCall) HOOK.OnSysCall(api,par);
	var o = {
		"api"	:	api	,
		"par"	:	par	}
	AJAXService("/api.php",o,ServerData);	
	}

var APP = {};
var HOOK = {};

function ServerData(js) {
	var ax,cmd,api,v;
	if (HOOK.OnServerData) HOOK.OnServerData(js);
	
	if (js.err) alert(js.err);
	
	if (js.cmd) {
		for(ax in js.cmd) {
			api = js.cmd[ax];
			cmd = api.api;
			
			if (cmd=='info') alert(api.data);
			if (cmd=='href') {
				top.location.href=api.data;
				return;
				}
			if (cmd=='html') {
				v = document.getElementById('pant');
				if (v) v.innerHTML=api.data; 
				}
				
			if (APP[cmd]) APP[cmd](api.data); else alert("API `"+cmd+"` not defined!");
				
			}
		}

	}
