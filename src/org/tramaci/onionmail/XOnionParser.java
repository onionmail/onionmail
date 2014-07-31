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


public class XOnionParser {
		public String Onion = "";
		public String Key = "";
		public int Port = 80;
		public String Tld="";
		public String Full="";
		private static Config Config = null;
		XOnionParser(Config C) {
			Config=C;
			Port=C.DefaultPort;
		}
		
		public static String getKey(String onion) { ///XXX Ok
			String[] Tok = onion.split("\\.+");
			if (!onion.endsWith(".onion")) return null;
			int cx = Tok.length;
			cx-=2;
			if (cx<0) return null;
			return Tok[cx].trim().toLowerCase();
		}
		
		public static XOnionParser fromString(Config C,String Onion) throws Exception {
		XOnionParser Q = new XOnionParser(C);
		Onion=Onion.toLowerCase();
		Onion=Onion.trim();
		String[] tok = Onion.split("\\.");
		int cx = tok.length;
		if (cx<2) throw new Exception("XOnionParser: Invalid host "+Onion);	
		if (tok[cx-1].length()==0) cx--;
		String sport = null;
		if (cx>2) sport = tok[cx-3]; else sport=""+C.DefaultPort;
		Q.Port=80;
		if (sport.matches("[0-9]+")) {
			sport=sport.trim();
			try { Q.Port = Integer.parseInt(sport); } catch(Exception E) { C.GlobalLog(Config.GLOG_Event, "OnionParser", " Invalid proto "+sport); } 
				} else {
				sport=sport.toLowerCase().trim();
				if (!C.PortName.containsKey(sport)) {
					Q.Port=C.DefaultPort;
					C.GlobalLog(Config.GLOG_Event, "OnionParser", " Unknown proto "+sport);
				} else {
					Q.Port = C.PortName.get(sport);
				}
			}
		Q.Tld = tok[cx-1];		
		Q.Key =tok[cx-2];
		Q.Onion = Q.Key+"."+Q.Tld;
		Q.Full = Integer.toString(Q.Port)+"."+Q.Key+"."+Q.Tld;
		return Q;
		}
		
		public String toString() { return Port+"."+Key+"."+Tld; }
		public static boolean isOnion( String st) {  return st.matches("[a-z2-7]{16}\\.onion"); }
		public  boolean isOnion() { return XOnionParser.isOnion(Onion); }
	
}
