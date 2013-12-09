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
import java.net.BindException;
import java.net.InetAddress;

public class OnionRouter {

	private Config Config = null;
	private SocksProxy[] SOCKS = null;
	private LocalIANA IANA = null;

	private long NextGarbage=0;
	
	OnionRouter(Config C) throws Exception {
		long tcr = System.currentTimeMillis();
		Config=C;
		NextGarbage = tcr+Config.GarbageFreq;
		SOCKS = new SocksProxy[Config.MaxHosts];
		IANA = new LocalIANA(Config);
		
	}
	
	public void End() {
		try {
			int cx = SOCKS.length;
				for (int ax=0;ax<cx;ax++) {
					if (SOCKS[ax]==null) continue;
					SOCKS[ax].running=false;
					SOCKS[ax].Garbage();
					SOCKS[ax].End();
					SOCKS[ax]=null;
				}
			} catch(Exception E) { Config.EXC(E, "OnionRouter.End"); }
		}
	
	public void Garbage() {
		try {
			long tcr = System.currentTimeMillis();
			int cx = SOCKS.length;
				for (int ax=0;ax<cx;ax++) {
					if (SOCKS[ax]==null) continue;
					if (tcr>SOCKS[ax].EndTime || !SOCKS[ax].running ||!SOCKS[ax].isAlive()) {
						SOCKS[ax].running=false;
						SOCKS[ax].Garbage();
						SOCKS[ax].End();
						SOCKS[ax]=null;
						}
				if (SOCKS[ax]!=null) SOCKS[ax].Garbage();
				}
			} catch(Exception E) { Config.EXC(E, "OnionRouter.Garbage"); }
		}
	

	public DNSPacket QueryDNS(DNSPacket D) throws Exception {
		boolean MX = false;
		long tcr = System.currentTimeMillis();
		
		int cx = 0;
		if (tcr>NextGarbage) {
				NextGarbage = tcr+Config.GarbageFreq;
				Garbage();
				}
			
		if (Config.DNSEnableMX) {
			if (D.qtype ==DNSPacket.TYP_MX) MX=true;
			D.AddMXReply(10, Config.OnionTTL);
			}
		
		XOnionParser ONION = XOnionParser.fromString(Config,D.Host);
		if (MX && ONION.Port!=25) ONION.Port=25;
		
		cx = Config.NoPort.length;
		for (int ax=0;ax<cx;ax++) if (Config.NoPort[ax]==ONION.Port) {
				Log("Port "+ONION.Port+" not permitted!");
				D.rcode = DNSPacket.RE_ErrNotExists;
				return D;
				}
		
		cx = SOCKS.length;
		int bp = -1;
		
		for(int ax=0;ax<cx;ax++) {
			if (SOCKS[ax]==null) continue;
			if (SOCKS[ax].OnionRoute == ONION.Onion && SOCKS[ax].OnionPort == ONION.Port) {
				bp=ax;
				break;
				}
			}
		
		if (bp==-1) {
			for(int ax=0;ax<cx;ax++) {
				if (SOCKS[ax]==null) {
					InetAddress ip = IANA.getIP();
					try {
						SOCKS[ax] = new SocksProxy(Config,ONION.Onion, ip,ONION.Port);
						} catch(BindException BE) {
						Log("SockProxy: Port in use "+ip.toString()+":"+ONION.Port);	
						throw BE;
						}
					bp=ax;
					break;
					}
				}
			} else SOCKS[bp].Refresh();
		
		if (bp==-1) throw new Exception("OnionRouter: No onion resource available\n");
		if (!MX || Config.DNSAddAMX) D.AddReply(DNSPacket.TYP_A, Config.OnionTTL, null, SOCKS[bp].IP.getAddress());
        D.rcode=0;
        return D;
	}
	public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, "OnionRouter", st); 	}
}
