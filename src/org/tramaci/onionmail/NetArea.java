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


public class NetArea {
	private InetAddress IP = null;
	private int FirstIp = 0;
	private int Mask = 0;
	
	private static final int REV = 0xFFFFFFFF;
	
	NetArea(InetAddress ip, int bits) {
		IP = ip;
		FirstIp = IP2Long(ip.getAddress());
		Mask = 1<<(bits&31);
		Mask--;
	}
	
	public boolean isInNet(int ip) {
		int c = ip&255;
		if (c==0 || c==255) return false;
		ip &=REV ^ Mask;
		int t = FirstIp&(REV ^ Mask);
		return ip == t;
		}
			
	public boolean isInNet(byte[] ip) { return isInNet(IP2Long(ip)); }
	
	public boolean isInNet(InetAddress ip) { return isInNet( IP2Long( ip.getAddress())); }
	
	public int getMask() { return Mask; }
	
	public InetAddress getFirstIP() { return IP; }
	
	public int getNumberOfFirstIP() {
		return FirstIp & Mask;
	}
	
	public InetAddress getNetIP()  {
		int c = FirstIp & (REV^ Mask);
		try {
			return InetAddress.getByAddress(Long2IP(c));
		} catch(Exception E) { return IP; }
	}
	
	public String getString() {
		try {
			return InetAddress.getByAddress(Long2IP(FirstIp)).toString()+ "/"+Mask;
		} catch(Exception E) { return "?"; }
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
	
	public static int getMaskByMax(int max) {
		max&=0x7FFFFFFF;
		int rs =1;
		for (int ax=0;ax<31;ax++) {
			if ((max&(1<<ax))!=0) rs=ax;
			}
		rs = 1<<(rs&31);
		rs--;
		return rs;
	}
	
}
