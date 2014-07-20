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

public class HTTPServer extends Thread {
	private Config Config;
	public SrvIdentity Identity = null;
	
	private ServerSocket srv = null;
	
	public volatile boolean running = true;
	public volatile int numTasks=0;
	public SrvHTTPRequest[] Connection = null;
	
	public FileOutputStream LogFile = null;
	private boolean LogMultiServer=false;
	
	public volatile int Hits=0;
	public volatile int Errs=0;
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
		
		String lf=null;
		if (serv.HTTPLogFile!=null) {
			LogMultiServer=false;
			lf = serv.HTTPLogFile;
			} else if (C.HTTPLogFile!=null) {
			LogMultiServer=true;
			lf =C.HTTPLogFile;
			}
		
		if (lf!=null) LogFile = new FileOutputStream(lf,true);

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
			int cx = Connection.length;
			for (int ax=0;ax<cx;ax++) if (Connection[ax]!=null) Connection[ax].End();
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
		
		//long tcr = System.currentTimeMillis();
		
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
					Connection[si] = new SrvHTTPRequest(Identity,con,this);
					long d = System.currentTimeMillis() - LastClear;
					if (d>SessionTimeOut) CleanupSession();
					
					} catch(Exception E) {
					Log("HTTP: "+con.getRemoteSocketAddress().toString()+" -> `"+Identity.Onion+"` Error "+E.getMessage()+"\n"); 
					WebLog("Error "+E.getMessage());
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
	
		public void UpdateStats(boolean fErr)  {
			try {
				long tcr = System.currentTimeMillis() + Identity.TimerSpoof;
				int cday =(int) (Math.floor(tcr/86400000L) % 30);
				int chour=(int) (Math.floor(tcr/3600000L) % 24);
				boolean save=false;
				
				if (cday!=StatCDay) {
					StatCDay=(short) cday;
					ErrsD[StatCDay]=0;
					HitsD[StatCDay]++;
					save=true;
					}
				
				if (chour!=StatCHour) {
					StatCHour=(short)chour;
					ErrsH[StatCHour]=0;
					HitsH[StatCHour]=0;
					save=true;
					}
				
				if (fErr) {
					Errs++;
					ErrsH[StatCHour]++;
					ErrsD[StatCDay]++;
					} else {
					Hits++;
					HitsH[StatCHour]++;
					HitsD[StatCDay]++;
					}
				
				if (save) SaveStat();
			} catch(Exception E) {
				WebLog("Can't update stats "+E.getMessage());
			}
			
		}
		
		private void SaveStat() throws Exception {
			int x = (int)((System.currentTimeMillis()+Identity.TimerSpoof)/86400000L);
			
			byte[] dta = Stdio.MxAccuShifter(new byte[][] {
							Stdio.Stosxi(new int[] { Hits,  Errs, StatCDay, StatCHour,x },4)			,
							Stdio.Stosw(HitsH)											,
							Stdio.Stosw(ErrsH)											,
							Stdio.Stosw(HitsD)											,
							Stdio.Stosw(ErrsD)											}
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
				
				H=null;
				HitsH = Stdio.Lodsw(F[1]);
				ErrsH = Stdio.Lodsw(F[2]);
				HitsD = Stdio.Lodsw(F[3]);
				ErrsD = Stdio.Lodsw(F[4]);
				F=null;
				} catch(Exception E) {
					WebLog("Can't load stats "+E.getMessage());
					HitsH = new short[24];
					ErrsH = new short[24];
					HitsD = new short[30];
					ErrsD = new short[30];
					}
		}
		
		@SuppressWarnings("deprecation")
		public void WebLog(String St) {
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
			if (LogMultiServer) h+=Identity.Nick+" \t";
			h+=St.trim()+"\n";
			
			synchronized (LogFile) {
				try {
					LogFile.write(h.getBytes());					
					} catch(Exception E) {}
				} 
			}
	
 		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, "HTTP "+Identity.Nick, st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server,  "HTTP "+Identity.Nick, st); 	}
		
}

