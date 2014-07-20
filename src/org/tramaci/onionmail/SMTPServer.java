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
	
	public static final short SM_TorServer = 0;
	public static final short SM_InetServer=1;
	public static final short SM_InetAlt=3;
	
	public short serverMode = SM_TorServer;
	
	SMTPServer(Config C,SrvIdentity serv,short srvMode) throws Exception {
		super();
		Config = C;
		Identity = serv;
		running=false;
		serverMode = srvMode;
		
		if ((serverMode&1)!=0 && !serv.EnterRoute) throw new Exception("Invalid server configuration");
		if (serverMode==SM_TorServer) srv = new ServerSocket(Identity.LocalPort,0,Identity.LocalIP);
		if (serverMode==SM_InetServer) {
			if (Identity.ExitIP!=null) srv = new ServerSocket(Identity.LocalPort,0,Identity.ExitIP); else srv = new ServerSocket(Identity.LocalPort);
			}
		if (serverMode==SM_InetAlt) {
			if (Identity.ExitIP!=null) srv = new ServerSocket(Identity.ExitAltPort,0,Identity.ExitIP); else srv = new ServerSocket(Identity.ExitAltPort);
			}
		
		/*oldcode
		if (serv.EnterRoute) {
				if (Identity.ExitIP!=null) srv = new ServerSocket(Identity.LocalPort,0,Identity.ExitIP); else srv = new ServerSocket(Identity.LocalPort); 
				} else srv = new ServerSocket(Identity.LocalPort,0,Identity.LocalIP);
		*/
		
		running=true;
		Connection = new SrvSMTPSession[Config.MaxSMTPSession];
		if (Identity.Spam==null) Identity.Spam = new Spam(Config,Identity);
		start();
		}
	
	/*oldcode
	SMTPServer(Config C,SrvIdentity serv,int port) throws Exception {
		super();
		Config = C;
		Identity = serv;
		running=false;
		if (serv.EnterRoute) srv = new ServerSocket(port); else srv = new ServerSocket(port,0,Identity.LocalIP);
				
		running=true;
		Connection = new SrvSMTPSession[Config.MaxSMTPSession];
		Identity.Spam = new Spam(Config,Identity);
		start();
		}
	*/
	
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
			int numTask=0;
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
			for (int ax=0;ax<cx;ax++) if (Connection[ax]!=null) numTask++;
			Identity.statsRunningSMTPSession=numTask;
			
			if (numTask>Identity.statsMaxRunningSMTPSession) Identity.statsMaxRunningSMTPSession=numTask;	
			try {
					con = srv.accept();
					if (Identity.BlackList!=null) {
						int spams=Identity.BlackList.getIP(con.getInetAddress());
						if (spams>5) {
							try {
								if (spams>10) {
									con.close();
									Log(Config.GLOG_Spam,"IP fast blocked! `"+J.IP2String(con.getInetAddress())+"`");
									continue;
									}
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
				Log("SMTP Connection Drop: "+J.IP2String(con.getInetAddress()));
				try { con.close(); } catch(Exception N) {}
				continue;
				}
			
			if (Config.Debug) Log("SMTP Connection: "+J.IP2String(con.getInetAddress()));
			try {
					Connection[si] = new SrvSMTPSession(Config,Identity,con,this);
					} catch(Exception E) {
					Log("SMTP: "+con.getRemoteSocketAddress().toString()+" -> `"+Identity.Onion+"` Error "+E.getMessage()+"\n"); //TODO Cambiare ip2string
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			Garbage();
			}
		
		}
		public void Log(String st) { 
				char m='?';
				if (serverMode==SMTPServer.SM_TorServer) m='T';
				if (serverMode==SMTPServer.SM_InetServer) m='I';
				if (serverMode==SMTPServer.SM_InetAlt) m='A';
				Config.GlobalLog(Config.GLOG_Server, "SMTP/"+m+" "+Identity.Nick, st); 	
				}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server,  "SMTP "+Identity.Nick, st); 	}
}
