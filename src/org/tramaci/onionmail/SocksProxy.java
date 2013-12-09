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


public class SocksProxy extends Thread {

	public int OnionPort = 80;
	public String OnionRoute = "";
	public InetAddress IP= null;
	public long EndTime =-1;
	private Config Config;
	private ServerSocket srv = null;
	
	public boolean running = true;
	
	private SocksConnection[] Connection = null;
	
	SocksProxy(Config C,String Host,InetAddress ip,int port) throws Exception {
		super();
		Config = C;
		running=false;
		OnionPort=port;
		IP = ip;
		OnionRoute=Host.toLowerCase();
		if (Config.Debug) Log("NewSock "+ip.toString()+" "+port+"\n");
		srv = new ServerSocket(port,0,ip);
		running=true;
		EndTime=System.currentTimeMillis() + Config.OnionTTL;
		Connection = new SocksConnection[Config.MaxConnectionXPort];
		start();
		}
	
	public void Refresh() {	EndTime=System.currentTimeMillis() + Config.OnionTTL; }
	
	public void End() {
			int cx = Connection.length;
			for (int ax=0;ax<cx;ax++) if (Connection[ax]!=null) Connection[ax].End();
			try { srv.close(); } catch(Exception E) {}
			running=false;
			EndTime =0;
			try { this.interrupt(); } catch(Exception E) {}
			Connection=null;
			System.gc();
		}
	
	public void Garbage() {
		int cx = Connection.length;
		long tcr=System.currentTimeMillis();
		boolean empty=true;
		for (int ax=0;ax<cx;ax++) {
			if (Connection[ax]!=null && (!Connection[ax].connected() || tcr>Connection[ax].EndTime)) {
					Connection[ax].End();
					Connection[ax]=null;
					}
			
			if (Connection[ax]!=null) empty=false; 
			}
		System.gc();
		if (!empty) Refresh();
	}
	
	public void run() {
		
		Socket con=null;
		
		long tcr = System.currentTimeMillis();
		while(running) {
				
			int cx = Connection.length;
			int si=-1;
			for (int ax=0;ax<cx;ax++) {
				if (Connection[ax]!=null && (!Connection[ax].connected() || tcr>Connection[ax].EndTime)) {
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
					if (!FireWallizer.IPCan(Config, con.getRemoteSocketAddress())) {
							Log("FireWallize.Proxy: "+con.getRemoteSocketAddress().toString()+" Drop!\n");
							con.close();
							continue;
							}
					} catch(Exception E) {
					Log("Connection Error X1: "+E.toString()+"\n");
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			
			if (si==-1) {
				Log("Connection Drop: "+con.getRemoteSocketAddress().toString()+"\n");
				try { con.close(); } catch(Exception N) {}
				continue;
				}
			
			if (Config.Debug) Log("Connection: "+con.getRemoteSocketAddress().toString()+"\n");
			try {
					Connection[si] = new SocksConnection(con,Config,OnionRoute,OnionPort);
					} catch(Exception E) {
					Log("SOCK: "+con.getRemoteSocketAddress().toString()+" -> `"+OnionRoute+"` Error "+E.getMessage()+"\n");
					try { con.close(); } catch(Exception N) {}
					continue;
					}
			Refresh();
			}
		
		}
	public void Log(String st) { Config.GlobalLog(Config.GLOG_Event, "SOCKSProxy", st); 	}
}
