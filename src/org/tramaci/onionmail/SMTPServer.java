/*
 * Copyright (C) 2013 by Tramaci.Org
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

import java.net.ServerSocket;
import java.net.Socket;

public class SMTPServer extends Thread {
	private Config Config;
	public SrvIdentity Identity = null;
	
	private ServerSocket srv = null;
	
	public boolean running = true;
	
	private SrvSMTPSession[] Connection = null;
	
	SMTPServer(Config C,SrvIdentity serv) throws Exception {
		super();
		Config = C;
		Identity = serv;
		running=false;
		if (serv.EnterRoute) srv = new ServerSocket(Identity.LocalPort); else srv = new ServerSocket(Identity.LocalPort,0,Identity.LocalIP);
				
		running=true;
		Connection = new SrvSMTPSession[Config.MaxSMTPSession];
		Identity.Spam = new Spam(Config,Identity);
		start();
		}
	
	public void Garbage() {	
		int cx = Connection.length;
		for (int ax=0;ax<cx; ax++) {
			if (Connection[ax]==null) continue;
			if (!Connection[ax].isConnected()) {
					Connection[ax].End();
					Connection[ax]=null;
					if (Config.Debug) Log("Session "+ax+" is disconnected");
					} else if (Connection[ax].isOld()) {
						Connection[ax].End();
						Connection[ax]=null;
						if (Config.Debug) Log("Session "+ax+" is too old");
					}	
			}
		}
	
	public void End() {
			int cx = Connection.length;
			for (int ax=0;ax<cx;ax++) if (Connection[ax]!=null) Connection[ax].End();
			try { srv.close(); } catch(Exception E) {}
			running=false;
			try { this.interrupt(); } catch(Exception E) {}
			Connection=null;
			System.gc();
		}
	
	public void run() {
		
		Socket con=null;
		
		long tcr = System.currentTimeMillis();
		while(running) {
			Garbage();	
			int cx = Connection.length;
			int si=-1;
			for (int ax=0;ax<cx;ax++) {
				if (Connection[ax]!=null && (!Connection[ax].isConnected() || tcr>Connection[ax].EndTime)) {
					Connection[ax].End();
					Connection[ax]=null;
					}
				if (Connection[ax]==null) { 
						si=ax; 
						break;
						}
			}
			
			try {
					con = srv.accept();
					if (Identity.BlackList!=null) {
						if (Identity.BlackList.getIP(con.getInetAddress())>5) {
							try {
								con.setSoTimeout(100);
								con.getOutputStream().write("451 Greylisted, please try again in 86400 seconds\r\n".getBytes());
								Identity.StatSpam++;
								} catch(Exception I) {} 
							
							con.close();
							Log(Config.GLOG_Spam,"IP Blocked! `"+J.IP2String(con.getInetAddress())+"`");
							continue;
							}						
						}
					} catch(Exception E) {
						if (srv.isClosed()) return;
					Log("SMTP Connection Error X1: "+E.toString()+"\n");
					Identity.StatError++;
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			
			if (si==-1) {
				Log("SMTP Connection Drop: "+con.getRemoteSocketAddress().toString()+"\n");
				try { con.close(); } catch(Exception N) {}
				continue;
				}
			
			if (Config.Debug) Log("SMTP Connection: "+con.getRemoteSocketAddress().toString()+"\n");
			try {
					Connection[si] = new SrvSMTPSession(Config,Identity,con);
					} catch(Exception E) {
					Log("SMTP: "+con.getRemoteSocketAddress().toString()+" -> `"+Identity.Onion+"` Error "+E.getMessage()+"\n");
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			Garbage();
			}
		
		}
		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, "SMTP "+Identity.Nick, st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server,  "SMTP "+Identity.Nick, st); 	}
}
