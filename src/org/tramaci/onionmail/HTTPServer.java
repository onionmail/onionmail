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

import java.io.File;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Date;
import java.util.HashMap;

import javax.net.ssl.SSLSocket;

public class HTTPServer extends Thread {
	public Config Config;
	public SrvIdentity Identity = null;
	
	private ServerSocket srv = null;
	
	public volatile boolean running = true;
	public volatile int numTasks=0;
	public SrvHTTPRequest[] Connection = null;
	
	public FileOutputStream LogFile = null;
	private boolean LogMultiServer=false;
	
	public HashMap <String,WebCheck> Checks=null;
	
	public volatile int Hits=0;
	public volatile int Errs=0;
	public volatile int Count=0;
	public volatile int CountStart = 0;
	public volatile String CountColor="FF0000";
	public volatile String CounterSvg="/counter.svg";
	public volatile String LogonEtex="/logon.etex";
	public volatile String Etex = ".etex"; //ADD .
	public volatile String AdminIndex="/admin/index.etex";
	public volatile String NewUserEtex="/newuser.etex";
	public volatile String ErrorPage="/error.html";
	public volatile String RegisterEtex="/register.etex";
	public volatile String IndexFile="index.etex";
	public volatile int CAPTCHAMode = 0;
	public volatile int CAPTCHASize=6;
	public volatile boolean HTTPSServer = false;
	public volatile short CountChWidth = 0;
	public volatile short CountChHeight = 0;
	public volatile short LastSavedCounter = 0;
	public volatile boolean hideCounter=false;
	
	public HashMap <String,String> Headers = null;
	
	public volatile int[] CountD = new int[30];
	public volatile short[] HitsH = new short[24];
	public volatile short[] ErrsH = new short[24];
	public volatile short[] HitsD = new short[30];
	public volatile short[] ErrsD = new short[30];
	public volatile short StatCDay=0;
	public volatile short StatCHour=0;
	
	public volatile long RNDEtag = 0;
	public volatile long RNDTim = 0;
	
	public volatile int KeepAlive=5; //Seconds
	public volatile int Pipelining=4;
	public volatile int MaxReqBuf=8192;
			
	public static final int ACCESS_DENIED = 0;
	public static final int ACCESS_USER = 1;
	public static final int ACCESS_LIST = 2;
	public static final int ACCESS_ROOT = 4;
	public static final int ACCESS_OK = 8;
	
	private long LastClear =0;
	public int SessionTimeOut=900000;
	private static final int MAGIC_STATS = 0x3c81;
	HTTPServer(Config C,SrvIdentity serv) throws Exception {
		super();
		Config = C;
		Identity = serv;
		running=false;
		
		RNDTim = Math.abs(Stdio.NewRndLong() % 31536000000L)+31536000000L;
		RNDEtag = Stdio.NewRndLong();
		KeepAlive = C.HTTPKeepAlive;
		Pipelining = C.HTTPPipelining;
		MaxReqBuf=C.HTTPMaxBuffer;
		CAPTCHAMode = C.TextCaptchaMode;
		CAPTCHASize = C.TextCaptchaSize;
		HTTPSServer = serv.HTTPSServer;
				
		String lf=null;
		if (serv.HTTPLogFile!=null) {
			LogMultiServer=false;
			lf = serv.HTTPLogFile;
			} else if (C.HTTPLogFile!=null) {
			LogMultiServer=true;
			lf =C.HTTPLogFile;
			}
		
		if (lf!=null) LogFile = new FileOutputStream(lf,true);
		
		String ev = Identity.HTTPBasePath+"/config.denied.conf";
		
		if (new File(ev).exists()) try {
	
			String[] li = new String(Stdio.file_get_bytes(ev),"UTF-8").split("\\n+");
			int cx = li.length;
			for (int ax=0;ax<cx;ax++) {
				li[ax]=li[ax].trim();
				if (li[ax].length()==0) continue;
				String[] tok;
				if (li[ax].contains("#")) {
					int pox = li[ax].indexOf('#')-1;
					if (pox<0) continue;
					li[ax] = li[ax].substring(0,pox);
					}
				if (li[ax].length()==0) continue;
				tok = li[ax].split("\\s+",2);
				if (tok.length!=2) {
						Log(Config.GLOG_Bad + Config.GLOG_Server, "config.denied.conf: "+(ax+1)+"Ignored: "+li);
						WebLog("Error in line "+(ax+1)+" Ignored: "+li[ax]);
						continue;
						}
				
				if (tok[0].startsWith("@")) {
					tok[0]=tok[0].toLowerCase();
					
					if (tok[0].compareTo("@log")==0) {
						WebLog("Log: "+tok[1].trim());
						continue;
						}
					
					if (tok[0].compareTo("@countstart")==0) {
						CountStart = J.parseInt(tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@countcolor")==0) {
						if (tok[1].matches("[0-9a-fA-F]{6}"))  CountColor = tok[1].toUpperCase();
						Identity.HTTPETEXVar.put(tok[0],"#"+tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@hidecounter")==0) {
						hideCounter = Config.parseY(tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@captchamode")==0) {
						int a=0;
						tok[1]=tok[1].toUpperCase();
						String[] txk=tok[1].split("\\s+");
						if (tok[1].contains("X")) a |= TextCaptcha.MODE_SWX;
						if (tok[1].contains("Y")) a |= TextCaptcha.MODE_SWY;
						if (tok[1].contains("N")) a |= TextCaptcha.MODE_NOISE;
						if (tok[1].contains("I")) a |= TextCaptcha.MODE_INV;
						if (tok[1].contains("S")) a |= TextCaptcha.MODE_SYM;
						if (tok[1].contains("R")) a |= TextCaptcha.MODE_RANDOM;
						if (tok[1].contains("8")) a |= TextCaptcha.MODE_UTF8;
						if (tok[1].contains("U")) a |= TextCaptcha.MODE_NUMBERONLY;
						CAPTCHAMode=a;
							
						if (txk.length>1) {
							CAPTCHASize = Config.parseInt(txk[1].trim(), "characters", 4, 10);							
							}
						continue;
						}
					
					if (tok[0].compareTo("@etex-ext")==0) {
						if (tok[1].matches("[0-9a-zA-Z]{1,8}"))  Etex = "."+tok[1];
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
				
					if (tok[0].compareTo("@acc-del")==0) {
						if (tok[1].compareTo("*")==0) {
							Identity.HTTPAccess = new HashMap <String,Integer>();
							} else {
							Config.AddHTTPAccess(Identity.HTTPAccess, tok[1],0, Identity.HTTPBasePath);	
							}
						continue;
						}
					
					if (tok[0].compareTo("@acc-root")==0) {
						int a = Identity.HTTPAccess.containsKey(tok[1]) ? Identity.HTTPAccess.get(tok[1]) : 0;
						Config.AddHTTPAccess(Identity.HTTPAccess, tok[1], a | HTTPServer.ACCESS_ROOT, Identity.HTTPBasePath);
						continue;
						}
					
					if (tok[0].compareTo("@acc-usr")==0) {
						int a = Identity.HTTPAccess.containsKey(tok[1]) ? Identity.HTTPAccess.get(tok[1]) : 0;
						Config.AddHTTPAccess(Identity.HTTPAccess, tok[1], a | HTTPServer.ACCESS_USER, Identity.HTTPBasePath);
						continue;
						}
					
					if (tok[0].compareTo("@acc-list")==0) {
						int a = Identity.HTTPAccess.containsKey(tok[1]) ? Identity.HTTPAccess.get(tok[1]) : 0;
						Config.AddHTTPAccess(Identity.HTTPAccess, tok[1],a | HTTPServer.ACCESS_LIST, Identity.HTTPBasePath);
						continue;
						}
					
					if (tok[0].compareTo("@acc-ok")==0) {
						int a = Identity.HTTPAccess.containsKey(tok[1]) ? Identity.HTTPAccess.get(tok[1]) : 0;
						Config.AddHTTPAccess(Identity.HTTPAccess, tok[1], a| HTTPServer.ACCESS_OK, Identity.HTTPBasePath);
						continue;
						}
					
					if (tok[0].compareTo("@acc-deny")==0) {
						int a = Identity.HTTPAccess.containsKey(tok[1]) ? Identity.HTTPAccess.get(tok[1]) : 0;
						Config.AddHTTPAccess(Identity.HTTPAccess, tok[1], a | HTTPServer.ACCESS_DENIED, Identity.HTTPBasePath);
						continue;
						}
					
					if (tok[0].compareTo("@counter-svg")==0) {
						if (!tok[1].startsWith("/")) tok[1]="/"+tok[1];
						if (tok[1].endsWith(".svg"))  CounterSvg = tok[1]; else throw new Exception("Invalid value in line "+(ax+1)+" `"+tok[1]+"`");
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@logon-etex")==0) {
						if (!tok[1].startsWith("/")) tok[1]="/"+tok[1];
						if (tok[1].length()>1)  LogonEtex = tok[1]; else throw new Exception("Invalid value in line "+(ax+1)+" `"+tok[1]+"`");
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@admin-index")==0) {
						if (!tok[1].startsWith("/")) tok[1]="/"+tok[1];
						if (tok[1].length()>1)  AdminIndex = tok[1]; else throw new Exception("Invalid value in line "+(ax+1)+" `"+tok[1]+"`");
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@newuser-etex")==0) {
						if (!tok[1].startsWith("/")) tok[1]="/"+tok[1];
						if (tok[1].length()>1)  NewUserEtex = tok[1]; else throw new Exception("Invalid value in line "+(ax+1)+" `"+tok[1]+"`");
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@error-page")==0) {
						if (!tok[1].startsWith("/")) tok[1]="/"+tok[1];
						if (tok[1].length()>1)  ErrorPage = tok[1]; else throw new Exception("Invalid value in line "+(ax+1)+" `"+tok[1]+"`");
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@register-etex")==0) {
						if (!tok[1].startsWith("/")) tok[1]="/"+tok[1];
						if (tok[1].length()>1)  RegisterEtex = tok[1]; else throw new Exception("Invalid value in line "+(ax+1)+" `"+tok[1]+"`");
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
						
					if (tok[0].compareTo("@count-chw")==0) {
						CountChWidth = (short) Config.parseInt(tok[1], "pixels x character", 4, 256);
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@count-chh")==0) {
						CountChHeight = (short) Config.parseInt(tok[1], "pixels", 4, 256);
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@index")==0) {
						if (
								!tok[1].matches("[a-zA-Z0-9_\\-\\.]+") 	|| 
								tok[1].contains("..")	||
								tok[1].startsWith(".") 		) throw new Exception("Invalid index file `"+tok[1]+"`");
						IndexFile = tok[1];
						Identity.HTTPETEXVar.put(tok[0],tok[1]);
						continue;
						}
					
					if (tok[0].compareTo("@header")==0) {
						tok = tok[1].split("\\:",2);
						if (tok.length!=2) throw new Exception("Invalid header in line "+(ax+1));
						tok[0]=tok[0].trim();
						tok[1]=tok[1].trim();
						if (Headers==null) Headers=new HashMap <String,String>();
						Headers.put(tok[0], tok[1]);
						continue;
						}
					
					WebLog("Error in line "+(ax+1)+" `"+tok[0]+"` Unknown command.");
					} else Identity.HTTPETEXVar.put(tok[0].trim(), tok[1].trim());
				}
			} catch(Exception E) {
				WebLog("Error in Config.Denied "+E.getMessage());
				Log("Error in Config.Denied "+E.getMessage()); 
				if (Config.Debug) E.printStackTrace();
			}
		
		Identity.HTTPETEXVar.put("@randstart",Long.toString(Stdio.NewRndLong()));	
		
		ev = Identity.HTTPBasePath+"/webcheck.denied.conf";
		if (new File(ev).exists()) try { Checks = WebCheck.FileParser(ev); } catch(Exception E) {
				Identity.Log("WebCheck: Loading error: "+E.getMessage());
				if (Identity.Config.Debug) E.printStackTrace();
	
				}
		
		srv = new ServerSocket(Identity.LocalHTTPPort,0,Identity.LocalIP); 
		
		running=true;
		Connection = new SrvHTTPRequest[Config.MaxHTTPSession];
		LoadStat();
		start();
		}
		
	public void Garbage() {	
		int cx = Connection.length;
		for (int ax=0;ax<cx; ax++) {
			if (Connection[ax]==null) continue;
			if (!Connection[ax].isConnected()) {
					Connection[ax].End();
					Connection[ax]=null;
					} else if (Connection[ax].isOld()) {
						int x = Connection[ax].stat;
						Connection[ax].End();
						Connection[ax]=null;
						if (Config.Debug) WebLog("Session "+ax+" is too old" + x);
					}	
			}
		}
	
	public void End() {
			if (Connection!=null) try {
				int cx = Connection.length;
				for (int ax=0;ax<cx;ax++) if (Connection[ax]!=null) Connection[ax].End();
				} catch(Exception I) {}
			
			try { srv.close(); } catch(Exception E) {}
			try {SaveStat(); } catch(Exception E) { WebLog("Can't save stats "+E.getMessage()); }
			if (LogFile!=null) try{ LogFile.close(); } catch(Exception I) {}
			LogFile=null;
			running=false;
			try { this.interrupt(); } catch(Exception E) {}
			Connection=null;
			System.gc();
		}
	
	public void run() {
		
		Socket con=null;
		
		while(running) {
			Garbage();	
			int cx = Connection.length;
			int si=-1;
			int InumTask=0;
			for (int ax=0;ax<cx;ax++) {
				if (Connection[ax]!=null && (!Connection[ax].isConnected() || Connection[ax].isOld())) {
					Connection[ax].End();
					Connection[ax]=null;
					}
				if (Connection[ax]==null) { 
						si=ax; 
						break;
						}
			}
			for (int ax=0;ax<cx;ax++) if (Connection[ax]!=null) InumTask++;
			numTasks = InumTask;
			
			try {
					con = srv.accept();
					
					if (HTTPSServer) {
						SSLSocket SL = LibSTLS.AcceptSSL(con, Identity.SSLServer, Identity.Onion);
						con = (Socket) SL;
						}
					
					Connection[si] = new SrvHTTPRequest(Identity,con,this);
					long d = System.currentTimeMillis() - LastClear;
					if (d>SessionTimeOut) CleanupSession();
					
					} catch(Exception E) {
					String msg=E.getMessage();
					Log("HTTP: "+ (con!=null ? con.getRemoteSocketAddress().toString() : "???") +" -> `"+Identity.Onion+"` Error "+msg+"\n"); 
					WebLog("Error "+msg);
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			Garbage();
			}
		
		}
	
		public void CleanupSession() {
			LastClear=System.currentTimeMillis();
			long Older = LastClear-SessionTimeOut;
			try {
				File tmp = new File(Identity.Maildir+"/tmp/");
				String[] lst = tmp.list();
				if (lst==null) return;
				int cx = lst.length;
				int dx=0;
				for (int ax=0;ax<cx;ax++) {
					String cf = lst[ax];
					if (!cf.startsWith("S") || !cf.endsWith(".tmp")) continue;
					cf = Identity.Maildir+"/tmp/"+cf;
					long ft = new File(cf).lastModified();
					if (ft<Older) {
						J.Wipe(cf,true);
						dx++;
						}
					}
				WebLog("Old session files "+dx+" deleted");
				} catch(Exception E) {
					WebLog("Error on Session clear: "+E.getMessage());
				}
			
		}
	
		public synchronized void UpdateStats(boolean fErr,boolean byCnt)  {
			try {
				long tcr = System.currentTimeMillis() + Identity.TimerSpoof;
				int cday =(int) (Math.floor(tcr/86400000L) % 30);
				int chour=(int) (Math.floor(tcr/3600000L) % 24);
				boolean save=false;
				
				if (cday!=StatCDay) {
					StatCDay=(short) cday;
					ErrsD[StatCDay]=0;
					HitsD[StatCDay]=0;
					CountD[StatCDay]=0;
					save=true;
					}
				
				if (chour!=StatCHour) {
					StatCHour=(short) chour;
					ErrsH[StatCHour]=0;
					HitsH[StatCHour]=0;
					save=true;
					}
				
				if (fErr) {
					Errs++;
					ErrsH[StatCHour]++;
					ErrsD[StatCDay]++;
					} else {
					
					if (byCnt) {
						CountD[StatCDay]++;
						Count++;
						} else {
							HitsH[StatCHour]++;
							HitsD[StatCDay]++;
							Hits++;
						}
					}
				
				if (save) {
						short lsc = (short) (Math.floor(tcr/20000L) % 4);
						if (lsc!=LastSavedCounter) {
							SaveStat();
							LastSavedCounter=lsc;
							}
						}
			} catch(Exception E) {
				WebLog("Can't update stats "+E.getMessage());
			}
			
		}
		
		private void SaveStat() throws Exception {
			int x = (int)((System.currentTimeMillis()+Identity.TimerSpoof)/86400000L);
			
			byte[] dta = Stdio.MxAccuShifter(new byte[][] {
							Stdio.Stosxi(new int[] { Hits,  Errs, StatCDay, StatCHour,x, Count  },4)			,
							Stdio.Stosw(HitsH)											,
							Stdio.Stosw(ErrsH)											,
							Stdio.Stosw(HitsD)											,
							Stdio.Stosw(ErrsD)											,
							Stdio.Stosxi(CountD, 4)									}
							,
							HTTPServer.MAGIC_STATS)
							;
					
					Stdio.file_put_bytes(Identity.Maildir+"/wwwstats", dta);		
			}
		
		private void LoadStat() {
			try {
				int x = (int)((System.currentTimeMillis()+Identity.TimerSpoof)/86400000L);
				String fs = Identity.Maildir+"/wwwstats";
				if (!new File(fs).exists()) return;
				byte[] dta = Stdio.file_get_bytes(fs);
				byte[][] F = Stdio.MxDaccuShifter(dta, HTTPServer.MAGIC_STATS);
				int[] H = Stdio.Lodsxi(F[0], 4);
				Hits = H[0];
				Errs = H[1];
				if (x==H[4]) {
					StatCDay =(short) ((H[2]&0x7FFF)%24);
					StatCHour =(short) ((H[3]&0x7FFF)%30);
					} else {
					StatCDay=-1;
					StatCHour=-1;
					}
				if (H.length>5) Count=H[5];
				H=null;
				HitsH = Stdio.Lodsw(F[1]);
				ErrsH = Stdio.Lodsw(F[2]);
				HitsD = Stdio.Lodsw(F[3]);
				ErrsD = Stdio.Lodsw(F[4]);
				if (F.length>5) CountD = Stdio.Lodsxi(F[5], 4);
				F=null;
				} catch(Exception E) {
					WebLog("Can't load stats "+E.getMessage());
					HitsH = new short[24];
					ErrsH = new short[24];
					HitsD = new short[30];
					ErrsD = new short[30];
					}
		}
		public void WebLog(String St) { WebLog(false,St); }
		
		@SuppressWarnings("deprecation")
		public void WebLog(boolean pox,String St) {
			Date D = new Date(System.currentTimeMillis() + Config.TimeSpoof);
			String h = (D.getYear()+1900)+"-"+
							J.Int2Str(D.getMonth()+1,2)+"-"+
							J.Int2Str(D.getDate(),2)+" "+
							J.Int2Str(D.getHours(),2)+":"+
							J.Int2Str(D.getMinutes(),2)+":"+
							J.Int2Str(D.getSeconds(),2)+"."+
							J.Int2Str((int)(System.currentTimeMillis() % 1000),4);
			String tid = Long.toHexString(Thread.currentThread().getId());
			h += " "+J.Spaced(J.Limited(tid,8), 8)+" ";
			h += pox ? "W ": "S ";
			if (LogMultiServer) h+=Identity.Nick+" \t";
			h+=St.trim()+"\n";
			
			if (LogFile==null) return;
			
			synchronized (LogFile) {
				try {
					LogFile.write(h.getBytes());					
					} catch(Exception E) {}
				} 
			}
	
 		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, "HTTP "+Identity.Nick, st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server,  "HTTP "+Identity.Nick, st); 	}
		
}

