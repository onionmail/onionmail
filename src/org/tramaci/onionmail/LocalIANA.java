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


public class LocalIANA {
	public Config Config;
	private int[] Used; 

	private int Startip;
	
	LocalIANA(Config C) {
		Config=C;
		Used = new int[Config.MaxHosts];
		Startip = IP2Long(Config.LocalNet.getAddress());
		int cx = C.NoIP.length;
		for (int ax=0;ax<cx;ax++) reserveIP(C.NoIP[ax]);
		}
	
	public InetAddress getIP() throws Exception {
		int cx = Config.MaxHosts;
		int tcr = (int)(System.currentTimeMillis()/1000);
		
		for (int ax=0;ax<cx;ax++) if (Used[ax]>0 && tcr>Used[ax]) Used[ax]=0;
		for (int ax=0;ax<cx;ax++) {
			int t0 = Startip + Config.LocalFisrtIp+ax;
			int t1 = t0&255;
			if (t1==0 || t1==255) continue;
			
			if (Used[ax]==0) {
				Used[ax]=-1;
				byte[] b0 = Long2IP(t0);
				return InetAddress.getByAddress(b0);
			}
		}
		throw new Exception("LocalIANA: No IP Available!");
		}
	
	public void reserveIP(InetAddress ip)  {
		int h=0;
		try {
			byte[] b0 = ip.getAddress();
			h = IP2Long(b0);
			h-=Config.LocalFisrtIp;
			h-=Startip;
			if (h<0 || h>=Config.MaxHosts) return;
			Used[h] = -2;
			} catch(Exception E) { Log("LocalIANA.reserveIP: "+ip.toString()+" "+h+" Error: "+E.toString()+"\n"); }
		}
	
	public void relaxIP(InetAddress ip) throws Exception {
		byte[] b0 = ip.getAddress();
		int h = IP2Long(b0);
		h-=Config.LocalFisrtIp;
		h-=Startip;
		if (h<0 || h>=Config.MaxHosts) throw new Exception("LocalIANA: Unknown IP "+ip.toString()+" in "+h);
		if (Used[h]==-2)  throw new Exception("LocalIANA: Reserved IP "+ip.toString()+" in "+h);
		Used[h] = (int)(System.currentTimeMillis()/1000) + 1 + Config.LocalIPReleaseTime;
		
	}
	
	public static byte[] Long2IP(int dta) {
		byte[] re = new byte[4];
		for (int al=0;al<4;al++) {
			re[3-al] = (byte)(dta&255);
			dta>>=8;
			}
		return re;
		}
	
	public static int IP2Long( byte dta[]) {
		int dd=0;
		for (int ax=0;ax<4;ax++) {
			dd<<=8;
			dd |= (int)(255&dta[ax]);
			}
		return dd;
	}

		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, "L_IANA", st); 	}
		//public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server, "L_IANA", st); 	}
}
