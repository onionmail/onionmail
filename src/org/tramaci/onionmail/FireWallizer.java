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
import java.net.InetSocketAddress;
import java.net.SocketAddress;


public class FireWallizer {
	
	public static boolean IPCan(Config C,SocketAddress ip)  {
		InetSocketAddress isa = (InetSocketAddress) ip;
		return IPCan(C,isa.getAddress());
	}
	
	public static boolean IPCan(Config C,InetAddress ip)  {
		
		if (C.NetAllowIp!=null) {
			int cx = C.NetAllowIp.length;
			for (int ax=0;ax<cx;ax++) {
				if (C.NetAllowIp[ax]==null) continue;
				if (C.NetAllowIp[ax].equals(ip)) return true;
				}
			}
		
		if (C.NetNoAllowIp!=null) {
			int cx = C.NetNoAllowIp.length;
			for (int ax=0;ax<cx;ax++) {
				if (C.NetNoAllowIp[ax]==null) continue;
				if (C.NetNoAllowIp[ax].equals(ip)) return false;
				}
			}
		
		if (C.NetAllow!=null) return C.NetAllow.isInNet(ip);
		
		if (C.NetDisallowAll) return false;
		return true;
	}	
}
