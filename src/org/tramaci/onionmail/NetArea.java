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

	private int FirstIp = 0;
	private int Mask = 0;
	private int nBits=0;
	
	NetArea(InetAddress ip, int bits) {
		nBits=bits;
		FirstIp = IP2Long(ip.getAddress());
		long ax = 0xFFFFFFFF00000000L>>bits;
		ax&=0x00000000FFFFFFFFL;
		Mask = (int)ax;
		FirstIp&=Mask;
		}
	
	public static NetArea ParseNet(String st) throws Exception {
			try {
				String[] tok = st.split("\\/");
				st=tok[0];
				int Nbt;
				if (tok.length==1) Nbt=32; else Nbt= Integer.parseInt(tok[1]);
				if (Nbt<0 || Nbt>32) throw new Exception();
				tok = st.split("\\.");
				if (tok.length!=4) throw new Exception();
				byte[] b = new byte[4];
				for (int ax=0;ax<4;ax++) {
					int c = Integer.parseInt(tok[ax]);
					if (c<0 || c>255) throw new Exception();
					b[ax]=(byte)(255&c);
				}
				if (Nbt<0 || Nbt>0xFFFFFFFFL) throw new Exception();
				return new NetArea( InetAddress.getByAddress(b) ,Nbt);
				
				} catch(Exception E) {
					throw new Exception("Invalid CIDR Network Area `"+st+"`");
				}
		}
		
	public boolean isInNet(int ip) {
		int t = ip&Mask;
		return FirstIp == t;
		}
			
	public boolean isInNet(byte[] ip) { return isInNet(IP2Long(ip)); }
	
	public boolean isInNet(InetAddress ip) { return isInNet( IP2Long( ip.getAddress())); }
	
	public int getMask() { return Mask; }
	
	public InetAddress getFirstIP() throws Exception { return InetAddress.getByAddress(Long2IP(FirstIp+1)); }
	
	public int getNumberOfFirstIP() {
		int ax= 32-nBits;
		ax = 1<<ax;
		ax--;
		return ax;
		}
	
	public InetAddress getNetIP() throws Exception { return InetAddress.getByAddress(Long2IP(FirstIp)); }
		
	public String getString() {
		try {
			return InetAddress.getByAddress(Long2IP(FirstIp)).toString()+ "/"+nBits;
		} catch(Exception E) { return "?"; }
	}
	
	public String toString() {
		try {
			return J.IP2String(InetAddress.getByAddress(Long2IP(FirstIp)))+"/"+nBits;
		} catch(Exception E) { return ""; }
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
