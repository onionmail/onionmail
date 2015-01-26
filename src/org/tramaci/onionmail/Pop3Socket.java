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

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;

public class Pop3Socket {

		private Socket sok;
		private DataInputStream in; 
		private BufferedReader br;
		private OutputStream O;
		
		Pop3Socket(Socket soki) throws Exception {
			sok=soki;
			in = new DataInputStream(sok.getInputStream());
			br = new BufferedReader(new InputStreamReader(in));
			O = sok.getOutputStream();
		}
		
		public void close() {
			try { sok.close(); } catch(Exception i) {}
			try { in.close(); } catch(Exception i) {}
			try { br.close(); } catch(Exception i) {}
			try { O.close(); } catch(Exception i) {}
		}
		
		public String ReadLn() throws Exception { return br.readLine(); }
		public void WriteLn(String st) throws Exception { O.write((st+"\r\n").getBytes()); }
		
		public boolean isConnected() { return sok.isConnected() && !sok.isClosed(); }
		
		public  Pop3Cmd getcmd() throws Exception{
			Pop3Cmd Q = new Pop3Cmd();
	
			String li="";
			li=br.readLine();
			if (li==null) throw new Exception("INTP.CMD.1 Incomplete I/O sequence");
			li=li.trim();
			
			String[] tok = li.split(" ",3);
			int pc = tok.length;
			if (pc<2) throw new Exception("INTP.CMD.2 Incomplete I/O sequence");
			
			Q.cmd = tok[0].toUpperCase().trim();
			int cx = Integer.parseInt("0"+tok[1].trim());
			if (pc==3) {
				Q.par=tok[2].trim();
				Q.pars=Q.par.split(" ");
				}
			
			if (cx>0) {
				Q.lin = new String[cx];
				for (int ax=0;ax<cx;ax++) {
						li=br.readLine();
						if (li==null) throw new Exception("INTP.CMD.3 Incomplete I/O sequence");
						li=li.trim();
						Q.lin[ax]=li;
					}
			
			}
			return Q;
			
		} 

		public static String recmd( boolean ok, String rcod,String msg,String[] lin) {
				String ho="";
				int cx=0;
				
				if (ok) ho="+"; else ho="-";
				if (rcod==null | rcod=="") {
					if (ok) rcod="OK"; else rcod="ERR";
					}
				
				if (lin != null) cx = lin.length;
				
				rcod = rcod.replace(" ","");
				ho+=rcod+" "+cx+" "+msg+"\n";
				if (cx>0) for(int ax=0;ax<cx;ax++) ho+=lin[ax]+"\n";
				
				return ho;
			}
		
		public  RdCmd  rdcmd ()  throws Exception {
				RdCmd Q = new RdCmd();
				String li="";
				li=br.readLine();
				if (li==null) throw new Exception("INPT:INC.1 Empty cmd response");
				li=li.trim();
				if (li.charAt(0)=='+') Q.ok=true; else Q.ok=false;
				li=li.substring(1);
				li+="    ";
				String tok[] = li.split(" ", 3);
				int cx = Integer.parseInt("0"+tok[1]);
				Q.cod = tok[0].trim();
				Q.msg=tok[2].trim();
				if (cx>0) {
					Q.lin = new String[cx];
					try {
						for (int ax=0;ax<cx;ax++) {
							li=br.readLine();
							li=li.trim();
							Q.lin[ax]=li;
							}
					 } catch(Exception E) { throw new Exception("INPT:INC.2 Incomplete cmd response"); }
					}
						return Q;
				}
		
		
}
