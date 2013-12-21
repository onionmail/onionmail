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

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;


public class ControlService extends Thread {

	public Config Config;
	public SrvIdentity Identity[] = null;
	
	private ServerSocket srv = null;
	
	public boolean running = true;
	public SSLSocketFactory SSLServer = null;
	
	public ControlSession[] Connection = null;
	public boolean isPublic=false;
	
	ControlService(Config C,SrvIdentity serv,int ControlPort,InetAddress ControlIP) throws Exception {
		super();
		Config = C;
		Identity = new SrvIdentity[1];
		Identity[0] = serv;
		SSLServer = Identity[0].SSLServer;
		running=false;
		srv = new ServerSocket(ControlPort,0,ControlIP);
		running=true;
		Connection = new ControlSession[Config.MaxControlSessions];
		isPublic=true;
		start();
		}
	
	ControlService(Config C,SMTPServer[] serv) throws Exception {
		super();
		Config = C;
		
		int cx = serv.length;
		Identity = new SrvIdentity[cx];
		for (int ax=0;ax<cx;ax++) {
				if (serv[ax].Identity==null) throw new Exception("Server "+ax+" is NULL");
				Identity[ax] = serv[ax].Identity;
				}
		
		running=false;
		srv = new ServerSocket(C.ControlPort,0,C.ControlIP);
				
		running=true;
		Connection = new ControlSession[Config.MaxControlSessions];
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
					if (SSLServer!=null) {
						if (Identity.length>1) throw new Exception("SSL Mode can run with only one server!");
						con = LibSTLS.AcceptSSL(con, SSLServer, Identity[0].Onion);
						}					
					} catch(Exception E) {
					Log("Control Connection Error X1: "+E.toString()+"\n");
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			
			if (si==-1) {
				Log("Control Connection Drop: "+con.getRemoteSocketAddress().toString()+"\n");
				try { con.close(); } catch(Exception N) {}
				continue;
				}
			
			if (Config.Debug) Log("Control Connection: "+con.getRemoteSocketAddress().toString()+"\n");
			try {
					Connection[si] = new ControlSession(this,con);
					Connection[si].isPublic = isPublic;
					
					} catch(Exception E) {
					Log("Control: "+con.getRemoteSocketAddress().toString()+" ->  Error "+E.getMessage()+"\n");
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			Garbage();
			}
		
		}
	
	public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, "CTRL_S", st); 	}
	public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server, "CTRL_S", st); 	}	

	protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}

	

