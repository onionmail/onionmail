/*
 * Copyright (C) 2014 by Tramaci.Org
 * This file is part of OnionMail (http://onionmail.info)
 * 
 * OnionMail is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.tramaci.onionmail;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;

public class SrvHTTPRequest extends Thread{
	protected Socket con = null;
	protected OutputStream O = null;
	protected InputStream Ir=null;
	protected BufferedReader I = null;
	protected SrvIdentity Mid = null;
	protected String Query="";
	protected String Path="";
	protected boolean isPost=false;
	protected String Sid=null;
	protected String BasePath=null;
	protected String ServerName=null;
	protected String ReqFile=null;
	protected String ext="html";
	protected int Status = 200;
	protected String StatusText="OK";
	protected String Directory="";
	protected String BaseFile="";
	protected String Extension="";
	
	protected HashMap <String,String> Get = new HashMap <String,String>();
	protected HashMap <String,String> Post = new HashMap <String,String>();
	protected HashMap <String,String> Session = new HashMap <String,String>();
	protected HashMap <String,String> QHead = new HashMap <String,String>();
	protected HashMap <String,String> RHead = new HashMap <String,String>();
	protected HashMap <String,String> RCookye = new HashMap <String,String>();
	
	protected byte[] PostRaw=null;
	protected byte[] Reply=null;
	protected boolean rsNoLen=false;
	protected InputStream RF = null;
	
	private HTTPServer Parent = null;
	
	public volatile int stat=ST_WaitRequest ;
	public volatile boolean dismissed=false;
	public volatile long Ltcr=0;
	
	public boolean isKeepAlive = true;
	public long keepAliveTcr = 0; 
		
	private int pipelN=0;
	private boolean isCurKeep=false;
	
	public static final int ST_WaitRequest = 0;
	public static final int ST_Request=1;
	public static final int ST_Post = 2;
	public static final int ST_Reply = 3;
	public static final int ST_End = 4;
	
	private void KAReset() throws Exception {
	
		Query="";
		Path="";
		isPost=false;
		Sid=null;
		ReqFile=null;
		ext="html";
		Status = 200;
		StatusText="OK";
		Directory="";
		BaseFile="";
		Extension="";
		
		Get = new HashMap <String,String>();
		Post = new HashMap <String,String>();
		Session = new HashMap <String,String>();
		QHead = new HashMap <String,String>();
		RHead = new HashMap <String,String>();
		RCookye = new HashMap <String,String>();
		
		PostRaw=null;
		Reply=null;
		rsNoLen=false;
		if (RF!=null) try { RF.close(); } catch(Exception I) {}
		RF = null;
		dismissed=false;
		stat=SrvHTTPRequest.ST_WaitRequest;
		Ltcr=System.currentTimeMillis();
		}
	
	public void WebLog(String s) {
		if (Parent.LogFile==null) return;
		String lp = J.IP2String(con.getInetAddress())+"\t"+(isPost ? "P" : "G");
		if (Sid!=null) lp+="S"; else lp+="-";
		lp+= (isCurKeep ? "K":"C")+"\t"+pipelN+"\t";
		lp+=Integer.toString(Status);
		lp+= "\t"+Path+"\t"+Query+"\t";
		if (QHead.containsKey("user-agent")) lp+="U=`"+QHead.get("user-agent")+"`\t";
		if (s!=null) 	lp+=s;
		lp=lp.trim();
		Parent.WebLog(true,lp);
		}
	
	SrvHTTPRequest(SrvIdentity s,Socket co,HTTPServer sp) throws Exception {
		super();
		Parent=sp;
		Mid=s;
		con=co;
		ServerName=Mid.HTTPServerName !=null ? Mid.HTTPServerName : Mid.Config.HTTPServerName;
		BasePath = Mid.HTTPBasePath!=null ? Mid.HTTPBasePath+"/" : Mid.Maildir+"/http/";
		BasePath=BasePath.replace("//", "/");
		
		Ir = con.getInputStream();
		O=con.getOutputStream();
		I = J.getLineReader(Ir);
		start();
		}
		
	private void HTTPProcFile() throws Exception {
				
		String [] tk = Path.split("\\/");
		int cx = tk.length-1;
		BaseFile = tk[cx];
		tk[cx]="";
		Directory = J.Implode("/", tk);
		Directory=Directory.replace("//", "/");
		tk=BaseFile.split("\\.+");
		cx=tk.length-1;
		if (cx>0) Extension=tk[cx].toLowerCase(); else Extension="";
		tk=null;
		
		if (Path.contains(".denied.")) {
			StatusText="Forbidden: Access Denied";
			Status=403;
			Reply=StatusText.getBytes();
			}
		
		Integer prm = Mid.HTTPAccess.get(Path);
		if (prm==null) prm = Mid.HTTPAccess.get(Directory);
		if (prm!=null) {
			String s = Session.get("access");
			int x = s!=null ? Integer.parseInt(s) : 16;
			int y = x & prm;
			if ( (prm & 8) == 0 && y==0) {
				StatusText="Forbidden: Access Denied";
				Status=403;
				Reply=StatusText.getBytes();
				return;
				}
			}
		
		if (Path.compareTo(Parent.CounterSvg)==0) {
			SVGCounter();
			return;
			}
		
		if (Path.endsWith(".api")) {
			HTTPApi();
			return;
			}
		
		if (Path.endsWith("/config-v1.1.xml")) {
			Reply = Stdio.file_get_bytes(Mid.Maildir+"/config-v1.1.xml");
			RHead.put("content-type", "text/xml");
			return;
			}
				
		if (Path.endsWith("/rulez.txt")) {
			SA_RULEZ();
			if (Reply!=null) return;
			}
				
		if (Path.endsWith("/"+Mid.Nick+".pem")) {
			byte[] der = Mid.MyCert.getEncoded();
			String st=J.Base64Encode(der);
			der=null;
			String q="";
			cx = st.length();
			for (int ax=0;ax<cx;ax++) {
				q+=st.charAt(ax);
				if (ax%75==74) q+="\n";
				}
			st="-----BEGIN CERTIFICATE-----\n"+q.trim()+"\n-----END CERTIFICATE-----\n";
			st=st.replace("\n", "\r\n");
			Reply = st.getBytes();
			st="";
			RHead.put("content-type", "application/x-pem-file");
			return;
			}
		
		if (Path.endsWith("/"+Mid.Nick+".asc")) {
			String pk = Mid.UserGetPGPKey("server");
			if (pk!=null) {
				if (Mid.Config.PGPSpoofVer!=null) try {
						cx = Mid.Config.PGPSpoofVer.length;
						if (cx!=0) {
							int r = 1;
							if (cx>1) r = (int) ((0x7FFFFFFFFFFFFFFFL & Stdio.NewRndLong()) % cx);
							String spoof = Mid.Config.PGPSpoofVer[r];
							pk = PGP.FilterPGPNSAsMarker(pk, spoof);
							}
						} catch(Exception E) { Mid.Config.EXC(E, "PGP:SpoofNSA:8"); }
				
				RHead.put("content-type", "text/plain");
				RHead.put("content-disposition","attachment; filename=\""+Mid.Nick+".asc\"");
				Reply=pk.getBytes();
				pk=null;
				return;
				}
			}
				
		File F = new File(ReqFile);
			
		if (!F.getAbsolutePath().startsWith(new File(BasePath).getAbsolutePath())) {
			WebLog("Path trasversal `"+ReqFile+"`");
			throw new PException("@500 Access denied");
			}
				
		if (!F.exists() || F.isDirectory() || F.isHidden()) {
			Status=404;
			StatusText="File not found";
			Reply=StatusText.getBytes();
			return;
			}
		
		if (ReqFile.endsWith(Parent.Etex)) {
			EtexFile();
			return;
			}
		
		if (Post.size()==0 && Get.size()==0) {
			Boolean cac=null;
			Boolean cab=null;
			if (Extension.length()>0) cac = Mid.HTTPCached.get(Extension);
			cab = Mid.HTTPCached.get(Directory);
			if (cab!=null) cac=cab;
			if (cac!=null && cac==true) {
				if (ProcCache(F)) return;
				}
			}
		
		RF = new FileInputStream(ReqFile);
				
		}
		
	public void run() {
		try {
			isCurKeep=Parent.KeepAlive!=0;
			for(pipelN=1;pipelN<=Parent.Pipelining;pipelN++) {
					isCurKeep=pipelN!=Parent.Pipelining;
					
					Ltcr=System.currentTimeMillis();
					stat=SrvHTTPRequest.ST_WaitRequest;
					
					if (!con.isConnected() || con.isClosed()) break;
					con.setSoTimeout((int)Mid.Config.MaxHTTPReq);
					if (Ir.available()>Parent.MaxReqBuf) throw new Exception("Request buffer too big");
					
					String li=null;
					try {
						li = I.readLine();
						} catch(Exception to) {
							break;
							}
					
					if (li==null) {
						if (isCurKeep || pipelN!=1) break;
						throw new Exception("Disconnected");
						}
							
					Ltcr=System.currentTimeMillis();
					stat=SrvHTTPRequest.ST_Request;
					
					if (li.length()>256) throw new Exception("HTTP Line too long "+li.length()+" `"+li.substring(0,64)+"` ...");
					String[] tok = li.split("\\s");
					if (tok.length!=3) throw new Exception("Invalid request: `"+li+"`");
					isPost = tok[0].compareTo("POST")==0;
					if (!isPost && tok[0].compareTo("GET")!=0) throw new Exception("Invalid trequest method `"+tok[0]+"`");
					
					if (tok[2].compareTo("HTTP/1.1")!=0 && tok[2].compareTo("HTTP/1.0")!=0) throw new Exception("Invalid protocol `"+tok[2]+"`");
					li = tok[1];
					tok=li.split("\\?",2);
					li=tok[0];
					if (tok.length>1) Query=tok[1];
					if (li.endsWith("/")) li+=Parent.IndexFile;
					tok=li.split("\\/");
					if (tok.length==0) throw new Exception("Invalid HTTP Path E1 `"+li+"`");
					int cx = tok.length;
					int dx=cx-1;
						for (int ax=0;ax<cx;ax++) {
							if (
									tok[ax].startsWith(".") 		|| 
									tok[ax].contains("..")			||
									!tok[ax].matches("[a-zA-Z0-9\\.\\-\\_]{0,40}")
									) throw new Exception("Invalid HTTP Path E2 `"+li+"`");
									if (ax==0 && tok[ax].length()!=0) throw new Exception("Invalid HTTP Path E3 `"+li+"`");
									if (ax!=0 && tok[ax].length()==0 && ax!=dx) throw new Exception("Invalid HTTP Path E3 `"+li+"`");
									if (ax==dx) {
									String[] tk = tok[ax].split("\\.");
									int al = tk.length-1;
									if (al>-1) 	ext = tk[al].toLowerCase().trim();
									}
							}
				
					Path = J.Implode("/", tok);
								
					if (Query.length()>0) Get = parseQuery(Query,"GET");
					
					QHead = J.ParseHeaders(I);
					con.setSoTimeout((int)Mid.Config.MaxHTTPRes);
					
					Ltcr=System.currentTimeMillis();
					stat=SrvHTTPRequest.ST_Post;
					if (isPost) {
						if(!QHead.containsKey("content-length") &&  !QHead.containsKey("content-type")) throw new Exception("Invalid POST E1");
						int pl = 0;
						try { pl = Integer.parseInt(QHead.get("content-length")); } catch(Exception E) { throw new Exception("Invalid POST E2"); }
						
						if (pl<0) throw new Exception("Invalid POST E3"); 
						if (pl>8192) throw new Exception("Invalid POST E4");
						PostRaw = new byte[pl];
						for (int ax=0;ax<pl;ax++) PostRaw[ax]=(byte) I.read();
						
						
						li = QHead.get("content-type");
						if (li==null) li="text/plain";
						li = li.toLowerCase();
									
						if (li.contains("application/x-www-form-urlencoded")) {
							li = new String(PostRaw);
	
							Post=parseQuery(li,"POST");
							PostRaw=null;
							}
							
						}
							
					if (QHead.containsKey("cookie")) {
						li  = QHead.get("cookie");
						li=li.trim();
						tok = li.split("\\;+");
						cx = tok.length;
						for (int ax=0;ax<cx;ax++) {
							String[] tk = tok[ax].split("\\=",2);
							if (tk.length!=2) continue;
							RCookye.put(tk[0].trim(), tk[1].trim());
							}
						}
										
					if (RCookye.containsKey("PHPSESSID")) {
						Sid = RCookye.get("PHPSESSID");
						getSession();
						}			
								
					
					ReqFile = (BasePath+"/"+Path).replace("//", "/");
					Ltcr=System.currentTimeMillis();
					stat=SrvHTTPRequest.ST_Reply;
					
					if (Mid.Config.MIMETypes.containsKey(ext)) {
						RHead.put("content-type",Mid.Config.MIMETypes.get(ext) );
						} else RHead.put("content-type","text/html; charset=UTF-8");
					
					WebLog(null);
					
					RHead.put("server", ServerName);
					RHead.put("date", Mid.TimeString());
					if (Parent.Headers!=null) for(String k:Parent.Headers.keySet()) RHead.put(k, Parent.Headers.get(k));
					HTTPProcFile();
					//WebLog(null);
							
					if (Reply!=null) RHead.put("content-length", Integer.toString(Reply.length));
					if (!rsNoLen && RF!=null) RHead.put("content-length", Integer.toString(RF.available()));
					if (Session!=null) saveSession();
					
					boolean kal;
					if (QHead.containsKey("connection") && QHead.get("connection").compareToIgnoreCase("keep-alive")==0) kal=true; else kal=false;
					
					if (kal!=false &&  !isCurKeep) RHead.put("connection", "close"); else {
							RHead.put("keep-alive", Integer.toString(Parent.KeepAlive));
							RHead.put("connection", "keep-alive");
							}
					
					if (Math.floor(Status/100)==2) {
							String r = RHead.get("content-type");
							if (r!=null && r.toLowerCase().contains("text/")) Parent.UpdateStats(false,false); 
							} else Parent.UpdateStats(true,false); 
					
					if (Reply == null && RF == null) Reply = new byte[0]; //No Content!
					
					li="HTTP/1.1 "+Status+" "+StatusText+"\r\n";
					O.write(li.getBytes());
					li = J.CreateHeaders(RHead);
					li+="\r\n";
					Ltcr=System.currentTimeMillis();
					O.write(li.getBytes());
					li=null;
					if (Reply!=null) {
						O.write(Reply);
						} else {
						long sz = RF.available();
						int blo =(int)(sz>>9);
						Reply = new byte[512];
						for (int ax=0;ax<blo;ax++) {
							Ltcr=System.currentTimeMillis();
							RF.read(Reply);
							O.write(Reply);
							}
						blo = RF.available();
						if (blo>0) {
							Reply = new byte[blo];
							Ltcr=System.currentTimeMillis();
							RF.read(Reply);
							O.write(Reply);
							}
						RF.close();
						RF=null;
						}
					Reply=null;
					if (isCurKeep) KAReset(); else break;
		}
			} catch(Exception E) {
				Parent.UpdateStats(true,false);
				String r = E.getMessage();
				WebLog("Error "+ r!=null ? r:"");
				stat=SrvHTTPRequest.ST_Reply;
				Ltcr=System.currentTimeMillis();
				if (r!=null && r.startsWith("@")) {
					r=r.substring(1);
					WebLog("Error "+r);
					String x = "ERROR "+r+"\r\n";
					r="HTTP/1.1 "+r+"\r\n";
					r+="Content-type: text/plain; charset=ISO-8859-1\r\n";
					r+="Connection: close\r\n";
					r+="Content-length: "+x.length()+"\r\n\r\n"+x;
					try {
						con.setSoTimeout(2000);
						O.write(r.getBytes());
						} catch(Exception I) {}
					dismissed=true;	
					} else {
						Mid.Config.EXC(E, Mid.Nick+".HTTP");
						WebLog("Exception "+E.getMessage());
						if (Mid.Config.Debug) E.printStackTrace();
					}
			}
		stat=SrvHTTPRequest.ST_End;
		Ltcr=System.currentTimeMillis();
		try {	con.close(); } catch(Exception I) {}
		try {	I.close(); } catch(Exception I) {}
		try {	Ir.close(); } catch(Exception I) {}
		try {	O.close(); } catch(Exception I) {}
		dismissed=true;
	}

	public static HashMap <String,String> parseQuery(String qry,String err) throws Exception {
		HashMap <String,String> rs = new HashMap <String,String> ();
		if (qry.length()>0) {
				String[] tok = qry.split("\\&");
				int cx = tok.length;
				for (int ax=0;ax<cx;ax++) {
					String tk[] = tok[ax].split("\\=",2);
					if (tk.length!=2) {
						if (!tok[ax].endsWith("=")) throw new Exception("Invalid HTTP QUERY "+err+" E1 `"+qry+"`");
						tk=new String[] {tk[0],""};
						}
					if (!tk[0].matches("[a-z0-9A-Z\\-\\_]{1,40}"))  throw new Exception("Invalid HTTP QUERY "+err+" E2 `"+qry+"`");
					rs.put(tk[0], java.net.URLDecoder.decode(tk[1],"UTF-8"));
					}
				}
		return rs;
	}

	protected void getSession() {
		try {
			if (Sid==null) {
				Session=null;
				return;
				}	
			byte[] by = Stdio.md5a(new byte[][] { Sid.getBytes() , Mid.Subs[9] });
			String fs = Mid.Maildir+"/tmp/S"+Stdio.Dump(by)+".tmp";
			
			if (!new File(fs).exists()) {
				Session=null;
				WebLog("No session for `"+Sid+"`");
				return;
				}
			
			byte[] b = Stdio.file_get_bytes(fs);
			byte[] k = Stdio.md5a(new byte[][] { Sid.getBytes() , Mid.Subs[10] });
			byte[] i = Stdio.md5a(new byte[][] { Sid.getBytes(), k});
			b=Stdio.AESDec(Stdio.GetAESKey(k),i, b);
			try {
				if (b.length==0) Session =null; else Session= J.HashMapUnPack(b);
				} catch(Exception E1) {
					Session=null;
					WebLog("Lost Session (Server restart change the session key).");
					}
			} catch(Exception E) {
				WebLog("HTTP Session Error: "+E.getMessage());
				if (Mid.Config.Debug) E.printStackTrace();
				Session= null;
				}
		}
	
	protected void saveSession() {
		try {
			if (Sid==null) return ;	
			byte[] by = Stdio.md5a(new byte[][] { Sid.getBytes() , Mid.Subs[9] });
			String fs = Mid.Maildir+"/tmp/S"+Stdio.Dump(by)+".tmp";
			byte[] b = J.HashMapPack(Session);
			byte[] k = Stdio.md5a(new byte[][] { Sid.getBytes() , Mid.Subs[10] });
			byte[] i = Stdio.md5a(new byte[][] { Sid.getBytes(), k});
			b=Stdio.AESEnc(Stdio.GetAESKey(k),i, b);
			Stdio.file_put_bytes(fs, b);
			
			} catch(Exception E) {
				WebLog("HTTP Session Save Error: "+E.getMessage());
				if (Mid.Config.Debug) E.printStackTrace();
				return ;
				}
		}
	
	protected void deleteSession() {
		try {
			if (Sid==null) return ;	
			byte[] by = Stdio.md5a(new byte[][] { Sid.getBytes() , Mid.Subs[9] });
			String fs = Mid.Maildir+"/tmp/S"+Stdio.Dump(by)+".tmp";
			if (new File(fs).exists()) J.Wipe(fs, false);
			Sid=null;
			Session=null;
			
			RHead.put("set-cookie", "PHPSESSID=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
			} catch(Exception E) {
				WebLog("HTTP Session Delete Error: "+E.getMessage());
				if (Mid.Config.Debug) E.printStackTrace();
				return ;
				}
		}
	
	protected void createSession() {
		String so = Mid.Nick+"\n"+Long.toString(System.currentTimeMillis(),36)+"\n"+Stdio.NewRndLong()+"\n"+Long.toString(Stdio.NewRndLong(),36);
		byte[] sn = Stdio.md5a(new byte[][] { so.getBytes() , Mid.Subs[4]}) ;
		so = J.md2st(sn);
		so+=Long.toString(Stdio.NewRndLong(),36)+Long.toString(Stdio.NewRndLong(),36);
		if (so.length()>26) so=so.substring(0,26);
		sn=null;
		Sid=so;
		Session = new HashMap <String,String>();
		Session.put("sid", Sid);
		Session.put("created", Long.toString((long)(System.currentTimeMillis() + Mid.TimerSpoof)/1000L));
		saveSession();
		RHead.put("set-cookie", "PHPSESSID="+Sid);
			
		}
	
	public boolean isConnected() { return con.isConnected() && !con.isClosed(); }
	public boolean isOld() {
		if (Ltcr==0) return false;
		
		long d = System.currentTimeMillis() - Ltcr;
		
		if (
				(
						stat==SrvHTTPRequest.ST_Request				||
						stat==SrvHTTPRequest.ST_WaitRequest		||
						stat==SrvHTTPRequest.ST_Post	
						) 
				&& d>Mid.Config.MaxHTTPReq) 
				return true;

		if (stat==SrvHTTPRequest.ST_Reply && d>Mid.Config.MaxHTTPRes) return true;
		if (stat==SrvHTTPRequest.ST_End && d>1000) return true; 
	
		if (!con.isConnected()) return true;
		if (con.isClosed()) return true;
		
		return false;
	}
	
	public void End() {
		try {	con.close(); } catch(Exception I) {}
		try {	I.close(); } catch(Exception I) {}
		try {	Ir.close(); } catch(Exception I) {}
		try {	O.close(); } catch(Exception I) {}
		dismissed=true;
		try {	this.interrupt();  } catch(Exception I) {}
		}

	public String toHtml(String b) {
		b=b.replace("&", "&amp;");
		b=b.replace("<", "&lt;");
		b=b.replace(">", "&gt;");
		b=b.replace("\"", "&quot;");
		b=b.replace("'", "&#39;");
		return b;
	}

	private void redirect(String st) throws Exception {
		
		if (Session!=null) saveSession();
		
		Status=302;
		StatusText="Found";
		Reply=StatusText.getBytes();
		if (!st.startsWith("/")) st="/"+st;
		
		if (!st.contains("://")) {
			if (QHead.containsKey("host")) {
				String a = QHead.get("host");
				if (!a.contains("//")) a="http://"+a;
				if (!a.endsWith("/")) st=a+st; else st="http://"+Mid.Onion+st;
				} else st="http://"+Mid.Onion+st;
			}
		
		RHead.put("location", st);
		if (RF!=null) {
			RF.close();
			RF=null;
			}
		return;
	}
	
	private void EtexFile() throws Exception {
		HashMap <String,Boolean> chk = null;
		HashMap <String,String> chkv=null;
		
		if (Parent.Checks!=null) try {

			chk = WebCheck.eval(Path, Parent.Checks, QHead, Session,Parent.Identity.HTTPETEXVar , Get, Post);
			for (String k:chk.keySet()) {
				Boolean fact = chk.get(k);
				
				if (fact==null || fact==false) continue;
				WebCheck act = Parent.Checks.get(k);
				if (act==null) continue;
				if (act.action==WebCheck.WCA_NOP) continue;
				if (act.action==WebCheck.WCA_LOG) WebLog(act.actionPar);
				
				if (act.action==WebCheck.WCA_REDIRECT) {
					redirect(act.actionPar);
					return;
					}
				
				if (act.action==WebCheck.WCA_404) {
					Status=404;
					StatusText="File not found";
					Reply=StatusText.getBytes();
					return;
					}
				
				if (act.action==WebCheck.WCA_DENY) {
					Status=403;
					StatusText="Forbidden";
					Reply=StatusText.getBytes();
					return;
					}
				
				
				if (act.action==WebCheck.WCA_SET) {
					String tok1[] = act.actionPar.split("\\=",2);
					tok1[0]=tok1[0].toLowerCase();
					tok1[0]=tok1[0].trim();
					tok1[1]=tok1[1].trim();
					String pox[] = tok1[0].split("\\.",2);
					pox[0]=pox[0].trim();
					pox[1]=pox[1].trim();
					
					if (pox[0].compareTo("s")==0) {
						if (Session==null) Session = new HashMap <String,String>();
						Session.put(pox[1], tok1[1]);
						}
					
					if (pox[0].compareTo("h")==0) RHead.put(pox[1], tok1[1]);
					if (pox[0].compareTo("p")==0) Post.put(pox[1], tok1[1]);	
					if (pox[0].compareTo("g")==0) Get.put(pox[1], tok1[1]);
					
					if (pox[0].compareTo("s")==0) {
						if (chkv==null) chkv = new HashMap <String,String>();
						chkv.put(pox[1], tok1[1]);
						}
					
					}
				
				}
			} catch(Exception E) {
				String ms = E.getMessage();
				if (ms!=null && ms.startsWith("@")) {
					WebLog("WebCheck Error: "+ms.substring(1));
					} else {
						Parent.Identity.Log("WebCheck Exception: "+E.toString());
						if (Parent.Identity.Config.Debug) E.printStackTrace();
					}
			}
		
		RHead.put("content-type", "text/html; charset=UTF-8");
		Reply =  Stdio.file_get_bytes(ReqFile);
		String li = new String(Reply,"UTF-8");
		Reply=null;
		
		for (int ax=0;ax<10;ax++) {
			int pox = li.indexOf("<$inc[");
			if (pox==-1) break;
			int poy = li.indexOf("]$inc>");
			if (poy==-1) break;
			String ifl = li.substring(pox+6,poy);
			
			if (ifl.startsWith("/")) ifl=BasePath+ifl; else {
				ifl=BasePath+"/"+Directory+"/"+ifl;
				ifl=ifl.replace("//", "/");
				}
			
			try {
				String dta  =new String(Stdio.file_get_bytes(ifl),"UTF-8");
				if (ifl.endsWith(".txt")) {
						dta = toHtml(dta);
						dta = dta.replace("\n", "<br>");
						}
				li = li.substring(0,pox)+dta+li.substring(poy+6);
				dta=null;
				} catch(Exception E) {
					WebLog("SubFile Error: `"+ifl+"` "+E.getMessage());
					Status=500;
					StatusText="Server error";
					Reply=StatusText.getBytes();
					return;
				}
			ifl=null;
			}
		
		if (Path.compareTo(Parent.LogonEtex)==0) {
			if (Session==null) createSession();
			String s = Session.get("logonretry");
			int rt = s!=null ? Integer.parseInt(s) : 0;
			String lo = Post.get("om-lo");
			String pa =Post.get("om-pa");
			String cap0 = Session.get("cap");
			String cap1 = Post.get("om-cap");
			
			Session.remove("access");
			Session.remove("cap");
			Session.remove("om-lo");
			Session.remove("om-pa");
			
			boolean acc=false;
			boolean val=true;
			String err="";
			if (
					lo!=null 		&&
					pa!=null		&&
					cap0!=null	&&
					cap1!=null	) {
					if (cap0.compareToIgnoreCase(cap1)!=0) {
						err="Invalid CAPTCHA code";
						acc=false;
						val=false;
						}
				
				if (rt>3) val=false;
					
				if (val) {
					if (
						J.CheckCryptPass( Mid.HTTPRootLogin!=null ? Mid.HTTPRootLogin : Mid.Nick , lo)  	&&
						J.CheckCryptPass( Mid.HTTPRootPass!=null ? Mid.HTTPRootPass : Mid.PassWd , pa) ) acc=true; else {
							acc=false;
							rt++;
							err="Access denied";
							}
						} else if (rt>3) {
							acc=false;
							err="Access denied";
							}
					
					if (val && acc) {
						Session.put("access",Integer.toString(HTTPServer.ACCESS_ROOT));
						redirect(Parent.AdminIndex);
						return;
						}
				   } else err="";
				Session.put("erro", err);
				Session.put("logonretry", Integer.toString(rt));
				
				}
		
		if (li.contains("<!-- SESSION -->")) { 
				createSession(); 
				}
		
		if (li.contains("<!-- NSESSION -->") && !RCookye.containsKey("PHPSESSID")) { 
				createSession(); 
				}
		
		if (li.contains("<!--#RULEZ#-->")) {
			SA_RULEZ();
			RHead.put("content-type", "text/html; charset=UTF-8");
			if (Reply!=null) {
			String x = new String(Reply);
			Reply=null;
			x="<pre>"+toHtml(x)+"</pre>";
			li=li.replace("<!--#RULEZ#-->", x);
			x=null;
			} else li.replace("<!--#RULEZ#-->", "NO RULEZ FILE");	
		}
				
		for (String k:Mid.HTTPETEXVar.keySet()) {
			li=li.replace("<!--@"+k+"@-->",toHtml(	Mid.HTTPETEXVar.get(k)));
			}
				
		if (Session!=null && !Session.containsKey("erro")) Session.put("erro","");
				
		li=li.replace("<!--#NICK#-->", Mid.Nick);
		li=li.replace("<!--#ONION#-->", Mid.Onion);
		li=li.replace("<!--#EXIT#-->", Mid.EnterRoute ? "1":"0");
		if (li.contains("<!--#SHA1#-->")) li=li.replace("<!--#SHA1#-->", LibSTLS.GetCertHash(Mid.MyCert));
		
		if (chk!=null) {
			for(String k:chk.keySet()) {
				String s = chk.get(k) ? "1":"0";
				li=li.replace("%["+k+"]%", s);
				if (k.contains("-")) {
					String xx[] = k.split("\\-",2);
					li=li.replace("%["+xx[0]+"]%", s);			
					}
				}
			}
		
		if (chkv!=null) {
			for(String k:chkv.keySet()) {
				String s = toHtml(chkv.get(k));
				li=li.replace("%{"+k+"}%", s);
				if (k.contains("-")) {
					String xx[] = k.split("\\-",2);
					li=li.replace("%["+xx[0]+"]%", s);			
					}
				}
			}
		
		if (Session!=null && Post.size()!=0) {
				for (String k:Post.keySet()) {
					if (k.startsWith("om-")) {
						Session.put(k, Post.get(k));
						}
					}
				}		
		
		if (li.contains("<!--#CAPTCHA#-->") && Session!=null) {
				if (TextCaptcha.isEnabled()) {
					CaptchaCode C= TextCaptcha.generateCaptcha(Parent.CAPTCHASize, Parent.CAPTCHAMode);
					Session.put("cap", C.code);
					Session.put("om-cap", "");
					String st = toHtml(C.image);
					st="<pre>"+st+"</pre>";
					li=li.replace("<!--#CAPTCHA#-->", st);
					} else {
					Session.put("cap", "");
					Session.put("om-cap", "");
					li=li.replace("<!--#CAPTCHA#-->", "(No CAPTCHA)");
					}
				}
		
		if (Path.compareTo(Parent.NewUserEtex)==0) {
			boolean rs = SA_NEWUSER();
			WebLog("NewUser "+ (rs ? "OK" : "ERR"));
			if (Session!=null && Session.containsKey("erro")) Session.put("newusererr", Session.get("erro"));
			if (!rs) return;
			}
		
		if (Session!=null) saveSession();
		
		if (li.contains("<!--$")) {
			if (Session==null) {
				WebLog("Session lost");
				redirect(Parent.ErrorPage+"?e=se");
				return;
				}
			
				for (String k:Session.keySet()) {
					String a="<!--$"+k+"$-->";
					String c="<!--("+k+")-->";
					String b=Session.get(k);
					b=toHtml(b);
					li=li.replace(a, b);
					li=li.replace(c, b);
					}
				li=li.replaceAll("\\<\\!\\-\\-\\([a-zA-Z0-9]+\\)\\-\\-\\>", "");
			}
						
		if (li.contains("<!--$")) {
			if (Session!=null) Session.put("erro", "No fields");
			int i = li.indexOf("<!--$");
			if (i>-1) {
				int f =li.indexOf("$-->", i);
				String field = li.substring(i+5,f);
				WebLog("Missing field `"+field+"`\t" +((Session==null) ? "S=NULL" : ("S=`"+Session.toString()+"`")));
				}
			li=null;
			redirect(Parent.ErrorPage+"?e=nf");
			return;
			}
		
		Reply = li.getBytes("UTF-8");
		if (li.contains("<!-- DESTROY -->")) deleteSession();
		if (li.contains("<!-- KDESTROY -->")) {
			if (Session!=null && Session.containsKey("erro") && Session.get("erro").length()==0) 	deleteSession();
			}
		
		
	}
	
	private boolean SA_NEWUSER() throws Exception {
		if (Session==null) redirect(Parent.RegisterEtex);
		String local = Session.get("om-localpart");
		String voucher = Session.get("om-voucher");
		String cap0 = Session.get("cap");
		String cap1 = Session.get("om-cap");
		Session.put("erro", "");
		if (
					local==null 		||
					voucher==null	||
					cap0==null			||
					cap1==null			)
			{
			Session.put("erro", "Invalid fields.");
			redirect(Parent.RegisterEtex);
			return false;
			}
		
		if (cap0.compareToIgnoreCase(cap1)!=0) {
			Session.put("erro", "Invalid CAPTCHA code.");
			redirect(Parent.RegisterEtex);
			return false;
			}
		
		Session.put("cap", J.RandomString(8));
		Session.remove("om-cap");
		
		if(
					!local.matches("[a-z0-9\\-]{3,40}") 		||
					local.endsWith(".op")								||
					local.endsWith(".list")								||
					local.endsWith(".onion")							||
					local.endsWith(".app")							||
					local.startsWith(".") 								|| 
					local.endsWith(".") 									|| 
					local.contains("..")									||
					local.contains("sysop")							)
		{
			Session.put("erro", "Invalid user name.");
			redirect(Parent.RegisterEtex);
			return false;
			}
			
		if (Mid.UsrExists(local)) {
			Session.put("erro", "User arleady exists");
			redirect(Parent.RegisterEtex);
			return false;
			}
		
		Session.put("erro","");
		
		boolean vca=false;
		if (voucher.length()>0) try {
			voucher = voucher.trim();
			if (Mid.VoucherTest(voucher, true)==1) vca=true;
			} catch(Exception E) {
				WebLog("Voucer "+E.getMessage());
				Session.put("erro", "Voucher error");
				redirect(Parent.RegisterEtex);
				return false;
				}
		
		if (!vca) try {
			Mid.CanAndCountCreateNewUser();
			} catch(Exception E) {	
				Log("Can "+E.getMessage());
				Session.put("erro", "Too many user registered today or in this hour.");
				redirect(Parent.RegisterEtex);
				return false;
				}
		try {
			
			if (Parent.Config.isManuReserverdUser(local)) throw new Exception("@Blocked or reserved username.");
			
			String smtpp = J.GenPassword(Mid.Config.PasswordSize, Mid.Config.PasswordMaxStrangerChars);
			String pop3p = J.GenPassword(Mid.Config.PasswordSize, Mid.Config.PasswordMaxStrangerChars);
			
			Session.put("smtpp", smtpp);
			Session.put("pop3p", pop3p);
			HashMap <String,String> P = new HashMap <String,String>();
			P.put("lang",Mid.DefaultLang);
			P.put("flag", Const.USR_FLG_TERM);
			Mid.UsrCreate(local,pop3p, smtpp, 1,P);
		} catch(Exception E) {
		String st=E.getMessage();
			if (st==null) st="@Error";
			if (st.startsWith("@")) Session.put("erro", st.substring(1)); else Session.put("erro", "N/A");
			Mid.Config.EXC(E,Mid.Nick+".HTTPNewUser");
			redirect(Parent.ErrorPage);
			return false;
			}
		
		ExitRouteList EL = Mid.GetExitList();
		ExitRouterInfo SE = EL.selectBestExit();
		Session.put("kvmat", "0");
		Session.put("vmat","");
		Session.put("vmatpass","");
		Session.put("verro","");
		
			if (SE!=null && SE.canVMAT) try {
				VirtualRVMATEntry RVM = Mid.VMATRegister(local+"@"+SE.domain,local);
				if (RVM!=null) {
					Session.put("kvmat", "1");
					Session.put("vmat",RVM.mail);
					Session.put("vmatpass",RVM.passwd);
					}
			} catch(Exception E) {
			String st=E.getMessage();
			if (st==null) st="@Error";
			if (st.startsWith("@")) Session.put("verro", st.substring(1)); else Session.put("verro", "N/A");
			Log(Mid.Nick+".HTTPNewVMAT "+st);	
			}
	Session.put("erro", "");
	if (Mid.Config.Debug) Log("New user `"+local+"`");
	return true;
	}

	private void SA_RULEZ() throws Exception {
		String rul="";

		rul+=Mid.Maildir+"/rulez.eml\n";
		rul+=Mid.Maildir+"/rulez.txt\n";
		rul+=Mid.Maildir+"/rulez.rul\n";
		rul+=Mid.Config.RootPathConfig+"rulez.eml\n";
		rul+=Mid.Config.RootPathConfig+"rulez.rul\n";
		rul+=Mid.Config.RootPathConfig+"rulez.txt";
		rul=rul.trim();

		for(String tr: rul.split("\\n+")) {
			
					if (new File(tr).exists()) {
						boolean isr = tr.endsWith(".rul");
						
						FileInputStream r=null;
						BufferedReader l=null;
						MailBoxFile  ru=null;
						HashMap <String,String> H=null;
						if (isr) {
							ru = new MailBoxFile();
							ru.OpenAES(tr, Mid.Sale, false);
							String tmp="";
							while(true) {
								String li = ru.ReadLn();
								if (li==null || li.length()==0) break;
								tmp+=li+"\r\n";
								}
							
							l = J.getLineReader( new ByteArrayInputStream( tmp.getBytes()));
							H = J.ParseHeaders(l);
							H = J.FilterHeader(H);
							tmp=null;
							
							} else {
							r = new FileInputStream(tr);
							l = J.getLineReader(r);
							H = J.ParseHeaders(l);
							H = J.FilterHeader(H);
							}
						

						if (!H.containsKey("subject")) H.put("subject", Mid.Nick+" RULEZ ("+Mid.Onion+")");
						if (H.containsKey("content-type")) RHead.put("content-type", H.get("content-type"));
						
						String msg="";
						while(true) {
							String s;
							if (isr) s= ru.ReadLn(); else s = l.readLine();
							
							if (s==null) break;
							s=s.replace("\r", "");
							s=s.replace("\n", "");
							msg+=s+"\n";
							}
						if (isr) ru.Close(); else {
							l.close();
							r.close();
							}
						Reply = msg.getBytes();
						break;
						}		
					}
			}
	
	public void HTTPApi() throws Exception {
		RHead.put("content-type", "application/json");
		
		String rs="{\"apiVer\":\"1.0\",\n";
		boolean includ=false;
		File fa =new File(ReqFile);
		if (!fa.exists()) {
			rs+="\"err\":\"API not found\"}";
			Reply = rs.getBytes();
			fa=null;
			return;
			}

		if (fa.length()>0 && fa.length()<65536) includ=true;
		
		if (Path.endsWith("/voucher.api")) {
			if (
					Session!=null		&&
					Session.containsKey("access") &&
					(J.parseInt(Session.get("access")) & HTTPServer.ACCESS_ROOT)!=0 ) {
					int day;
					if (Get.containsKey("day")) day = J.parseInt(Get.get("day")); else day=2;
					String s = Mid.VoucherCreate(day);
					s=s.replace("/", "\\/");
					rs+="\"voucher\":\""+s+"\",\n";
					}
			}
		
		if (Path.endsWith("/voucher-test.api")) {
			if (
					Session!=null		&&
					Session.containsKey("access") &&
					Get.containsKey("voucher")	&&
					Get.containsKey("save") &&
					(J.parseInt(Session.get("access")) & HTTPServer.ACCESS_ROOT)!=0 ) {
					String vo = Get.get("voucher");
					boolean sv = Config.parseY(Get.get("save"));
					int r = Mid.VoucherTest(vo, sv);
					rs+="\"stat\":"+Integer.toString(r)+",\n";
					if (sv && r == Mid.VOUCHER_OK) { 
						rs+="\"stats\":\"BAD_DELETED\",\n";
						} else {
						if (r==Mid.VOUCHER_OK) rs+="\"stats\":\"OK\",\n";
						if (r==Mid.VOUCHER_OLD) rs+="\"stats\":\"BAD_OLD\",\n";
						if (r==Mid.VOUCHER_UNKNOWN) rs+="\"stats\":\"BAD_UNKNOWN\",\n";
						if (r==Mid.VOUCHER_USED) rs+="\"stats\":\"BAD_USED\",\n";
						}
					}
				}
		
		if (Path.endsWith("/friends.api")) {
			String[] ls = Mid.RequildFriendsList();
				rs+="\"friends\":[";
				int cl = ls.length-1;
				for (int al=0;al<=cl;al++) {
					rs+="\""+ls[al]+"\"";
					if (al!=cl) rs+=",";
					}
				rs+="],\n";
				}
		
		if (Path.endsWith("/elist.api")) {
			ExitRouteList el = Mid.GetExitList();
			ExitRouterInfo[] ls = el.getAll();
			int cl = ls.length-1;
			rs+="\"elist\":[";
			for (int al=0;al<=cl;al++) {
				rs+="{"; 
				rs+="\"dom\":\""+ls[al].domain+"\",";
				rs+="\"flg\":\"";
				if (ls[al].canMX) rs+="M";
				if (ls[al].canVMAT) rs+="V";
				if (ls[al].isBad) rs+="B";
				if (ls[al].isDown) rs+="D";
				if (ls[al].isExit) rs+="X";
				if (ls[al].isLegacy) rs+="L";
				if (ls[al].isTrust) rs+="M";
				rs+="\"}";
				if (al!=cl) rs+=",";
				}
			rs+="],\n";
			}
		
		if (Path.endsWith("/stats.api")) {
				rs+="\"smtps\":" +Integer.toString(Mid.statsMaxRunningSMTPSession)+",\n";
				rs+="\"mexit\":" +Integer.toString(Mid.statMaxExit)+",\n";
				rs+="\"mexitt\":" +Integer.toString(Mid.statMaxExitTrust)+",\n";
				rs+="\"mexitb\":" +Integer.toString(Mid.statMaxExitBad)+",\n";
				rs+="\"mexitd\":" +Integer.toString(Mid.statMaxExitDown)+",\n";
				rs+="\"msin\":" +Integer.toString(Mid.StatMsgIn)+",\n";
				rs+="\"msout\":" +Integer.toString(Mid.StatMsgOut)+",\n";
				rs+="\"msinet\":" +Integer.toString(Mid.StatMsgInet)+",\n";
				rs+="\"errs\":" +Integer.toString(Mid.StatError)+",\n";
				rs+="\"spam\":" +Integer.toString(Mid.StatSpam)+",\n";
				rs+="\"tor2tor\":" +Integer.toString(Mid.StatTor2TorBy)+",\n";
				rs+="\"to2inet\":" +Integer.toString(Mid.StatTor2InetBy)+",\n";
				rs+="\"inet2tor\":" +Integer.toString(Mid.StatInet2TorBy)+",\n";
				rs+="\"recv\":" +Long.toString(Mid.StatRecvMSGBytes)+",\n";
				rs+="\"send\":" +Long.toString(Mid.StatSendMSGBytes)+",\n";
				rs+="\"httph\":" +Integer.toString(Parent.Hits)+",\n";
				rs+="\"httpe\":" +Integer.toString(Parent.Errs)+",\n";
				rs+="\"stat\":" +Integer.toString(Mid.Status)+",\n";
				}
			
		if (Path.endsWith("/threads.api")) {
				rs+="\"thr\":" +Integer.toString(Main.CurThreads)+",\n";
				rs+="\"maxthr\":" +Integer.toString(Main.MaxThreads)+",\n";
				rs+="\"fuffa\":" +Integer.toString(Main.CurFuffaThreads)+",\n";
				rs+="\"maxfuffa\":" +Integer.toString(Main.MaxFuffaThreads)+",\n";
				rs+="\"maxfuffa\":" +Integer.toString(Main.MaxFuffaThreads)+",\n";
				rs+="\"runsmtp\":" +Integer.toString(Mid.statsRunningSMTPSession )+",\n";
				rs+="\"maxsmtp\":" +Integer.toString(Mid.statsMaxRunningSMTPSession )+",\n";
				rs+="\"runpop3\":" +Integer.toString(Mid.statsRunningPOP3Session )+",\n";
				rs+="\"maxpop3\":" +Integer.toString(Mid.statsMaxRunningPOP3Session )+",\n";
				rs+="\"count\":[";
				int cl = Main.StatsKThreadsXHour.length;
				for (int al=0;al<cl;al++) rs+=Short.toString(Main.StatsKThreadsXHour[al])+",";
				rs+=Short.toString(Main.MaxThreads)+"],\n";
				}
		
		if (Path.endsWith("/statshit.api")) {
				rs+="\"msin\":" +Integer.toString(Mid.StatMsgIn)+",\n";
				rs+="\"msout\":" +Integer.toString(Mid.StatMsgOut)+",\n";
				rs+="\"msinet\":" +Integer.toString(Mid.StatMsgInet)+",\n";
				rs+="\"errs\":" +Integer.toString(Mid.StatError)+",\n";
				rs+="\"spam\":" +Integer.toString(Mid.StatSpam)+",\n";
				rs+="\"httph\":" +Integer.toString(Parent.Hits)+",\n";
				rs+="\"httpe\":" +Integer.toString(Parent.Errs)+",\n";
				}
		
		if (Path.endsWith("/webstats.api")) {
				rs+="\"httph\":" +Integer.toString(Parent.Hits)+",\n";
				rs+="\"httpe\":" +Integer.toString(Parent.Errs)+",\n";
				rs+="\"curday\":" +Short.toString(Parent.StatCDay)+",\n";
				rs+="\"count\":" +Integer.toString(Parent.Count)+",\n";
				rs+="\"hitsh\":[";
					int cx = Parent.HitsH.length-1;
					for (int ax=0;ax<=cx;ax++) {
						rs+=Short.toString(Parent.HitsH[ax]);
						if (ax!=cx) rs+=",";
						}
				rs+="],\n";
				
				rs+="\"errsh\":[";
					cx = Parent.ErrsH.length-1;
					for (int ax=0;ax<=cx;ax++) {
						rs+=Short.toString(Parent.ErrsH[ax]);
						if (ax!=cx) rs+=",";
						}
				rs+="],\n";
				
				rs+="\"hitsd\":[";
					cx = Parent.HitsD.length-1;
					for (int ax=0;ax<=cx;ax++) {
						rs+=Short.toString(Parent.HitsD[ax]);
						if (ax!=cx) rs+=",";
						}
				rs+="],\n";
				
				rs+="\"errsd\":[";
					cx = Parent.ErrsD.length-1;
					for (int ax=0;ax<=cx;ax++) {
						rs+=Short.toString(Parent.ErrsD[ax]);
						if (ax!=cx) rs+=",";
						}
				rs+="],\n";
				
				rs+="\"countd\":[";
					cx = Parent.CountD.length-1;
					for (int ax=0;ax<=cx;ax++) {
						rs+=Integer.toString(Parent.CountD[ax]);
						if (ax!=cx) rs+=",";
						}
				rs+="],\n";
				
				}
		
		if (Path.endsWith("/can.api")) {
				rs+="\"canusr\":" + (Mid.NewUsrEnabled ? "true" : "false") + ",\n";
				rs+="\"canusrh\":" + (Mid.NewUsrLastHourCnt>Mid.NewUsrMaxXHour ? "false" : "true") + ",\n";
				rs+="\"canusrd\":" + (Mid.NewUsrLastDayCnt>Mid.NewUsrMaxXDay ? "false" : "true") + ",\n";
				
				rs+="\"canlst\":" + (Mid.NewLstEnabled ? "true" : "false") + ",\n";
				rs+="\"canlsth\":" + (Mid.NewLstLastHourCnt>Mid.NewLstMaxXHour ? "false" : "true") + ",\n";
				rs+="\"canlstd\":" + (Mid.NewLstLastDayCnt>Mid.NewLstMaxXDay ? "false" : "true")+",\n";
				}
		
		if (Path.endsWith("/config.api")) {
			rs += "\"maxmsgxusr\":"+Long.toString(Mid.MaxMsgXuser)+",\n";
			rs += "\"maxmsgsize\":"+Long.toString(Mid.MaxMsgSize/1024)+",\n";
			rs += "\"boxsize\":"+Long.toString((Mid.MaxMsgSize*Mid.MaxMsgXuser)/1024)+",\n";
			rs += "\"maxmlsize\":"+Long.toString(Mid.MaxMailingListSize)+",\n";
			rs += "\"maxmultimsg\":"+Long.toString(Mid.MultiDeliverMaxRCPTTo)+",\n";
			rs += "\"maxspam\":"+Long.toString(Mid.MaxSpamEntryXUser)+",\n";
			rs += "\"debug\":" + (  Mid.Config.Debug ? "true":"false")+",\n";
			rs += "\"autodelete\":"+( Mid.AutoDeleteReadedMessages ? "true":"false")+",\n";
			rs += "\"exitroute\":" +( Mid.EnterRoute ? "true":"false")+",\n";
			rs += "\"exitnotice\":" +( Mid.ExitNoticeE ? "true":"false")+",\n";
			rs += "\"logvoucher\":"+ ( Mid.LogVoucherTo!=null ? "true":"false")+",\n";
			rs += "\"vmat\":true,\n";
			rs += "\"msgxhour\":" +  Integer.toString(Mid.MaxMsgXUserXHour)+",\n";
			rs += "\"nick\":\""+Mid.Nick+"\",\n";
			rs += "\"sha1\":\""+LibSTLS.GetCertHash(Mid.MyCert)+"\",\n";
			rs +="\"onion\":\""+Mid.Onion+"\",\n";
			}
		
		if (Path.endsWith("/ver.api")) {
			if (Mid.NoVersion) {
					rs+="\"ver\":\"OnionMail\",\n";
				} else {
					rs+="\"ver\":\"OnionMail "+Main.getVersion()+"\",\n";
					rs+="\"vid\":\""+Long.toHexString(Main.VersionID)+"\",\n";
				}
			}
		
		if (includ) {
			String s = new String(Stdio.file_get_bytes(ReqFile),"UTF-8");
			rs+=s;
			s=null;
			}
		
		rs+="\"ok\":true}";				
						
		Reply = rs.getBytes();
		
		}
	
	private boolean ProcCache(File F) {
	
		long dt = F.lastModified() - Parent.RNDTim;
		long et = F.length() ^ dt ^ Parent.RNDEtag;
		String dts =  J.TimeStandard(dt);
		String ets = "\""+ Long.toHexString(et&0x7FFFFFFFFFFFFFFFL)+"-"+ Long.toHexString(dt&0x7FFFFFFFFFFFFFFFL)+"\"";
		
		RHead.put("etag", ets);
			
		String st = QHead.get("if-modified-since");
		if (st!=null && dts.compareToIgnoreCase(st)==0) {
			ProcCached();
			return true;
			}
			
		st = QHead.get("if-none-match");
		if (st!=null && ets.compareToIgnoreCase(st)==0) {
			ProcCached();
			return true;
			}
		
		RHead.put("last-modified", dts);
		return false;
	}
	
	public void ProcCached() {
		Status = 304;
		StatusText = "Not Modified";
		Reply = StatusText.getBytes();
		}

	private void SVGCounter() throws Exception {
		long tcr = System.currentTimeMillis();
		
		long dt =(long) Math.floor(tcr/86400000L);
		dt*=86400000L;
		dt -= Parent.RNDTim ^ (Parent.RNDEtag % 8640000000L);
		long et =  dt ^ Parent.RNDEtag;
		et^=et<<1;
		
		String dts =  J.TimeStandard(dt);
		String ets = "\""+ Long.toHexString(et&0x7FFFFFFFFFFFFFFFL)+"-"+ Long.toHexString(dt&0x7FFFFFFFFFFFFFFFL)+"\"";
		RHead.put("etag", ets);
		
		String st = QHead.get("if-modified-since");
		if (st!=null && dts.compareToIgnoreCase(st)==0) {
			ProcCached();
			return;
			}
			
		st = QHead.get("if-none-match");
		if (st!=null && ets.compareToIgnoreCase(st)==0) {
			ProcCached();
			return;
			}
		
		RHead.put("last-modified", dts);
		
		byte[] font = new byte[] {
		//		 --GFEDCBA						
				0b00111111	, //0
				0b00000110	, //1
				0b01011011	, //2
				0b01001111	, //3
				0b01100110	, //4
				0b01101101	, //5
				0b01111101	, //6
				0b00000111	, //7
				0b01111111	, //8
				0b01101111	  //9
				} 						;
		
		InputStream I =  DynaRes.class.getResourceAsStream("/resources/svg");
		int cx = I.available();
		byte[] b = new byte[cx];
		I.read(b);
		I.close();
		String svg = new String(b,"UTF-8");
		b=null;
		String[] tok = svg.split("\\n+",3);
		svg=tok[2];
		tok[2]=null;
		int wpx = Integer.parseInt(tok[0].trim());
		int ppx =  Integer.parseInt(tok[1].trim());
		//int cday =(int) (Math.floor(tcr/86400000L) % 30);
		Parent.UpdateStats(false, true);
		String data="";
		if (!Parent.hideCounter) {
			st =Integer.toString(Parent.Count+ Parent.CountStart);
			cx = st.length();
			int pox=0;		
			for (int ch=0;ch<cx;ch++) {
				int c = st.charAt(ch)-48;
				if (c<0 || c>9) continue;
				byte by = font[c];
				for (int al=0;al<7;al++) {
					if ((by & 1<<al)==0) continue;
					char i = 'a';
					i+=al;
					data+="<use xlink:href=\"#"+i+"\" x=\""+pox+"\" y=\"0\" />\n";
					}
				pox+=ppx;
				}
			}
		
		svg=svg.replace("%HEI%", Integer.toString(Parent.CountChHeight!=0 ? Parent.CountChHeight : (ppx*2)));
		svg=svg.replace("%WPX%",Integer.toString(Parent.CountChWidth!=0 ? (Parent.CountChWidth*cx) : (wpx*cx )));
		svg=svg.replace("%WH%", Integer.toString(ppx * cx));
		svg=svg.replace("%COL%", Parent.CountColor);
		svg=svg.replace("%DATA%", data);
		data=null;
		Reply = svg.getBytes("UTF-8");
		RHead.put("content-type", "image/svg+xml");
		}
	
	public void Log(String st) { Mid.Config.GlobalLog(Config.GLOG_Server|Config.GLOG_Event,Mid.Nick+"/H", st); 	}
	public void Log(int flg,String st) { Mid.Config.GlobalLog(flg | Config.GLOG_Server|Config.GLOG_Event,Mid.Nick+"/H", st); 	}
}
