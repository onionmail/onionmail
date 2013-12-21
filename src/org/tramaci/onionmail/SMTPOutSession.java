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
import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;

public class SMTPOutSession {
		public String HostName=null;
		public Socket RS=null;
		public BufferedReader RI=null;
		public OutputStream RO=null;
		public String MailTo=null;
		public String MailFrom=null;
		public HashMap <String,String> Hldr=null;
		public MailBoxFile MBF=null;
		public String Msg=null;
		public BufferedReader I=null;
		public OutputStream O=null;
		public boolean isTor=false;
		public boolean SupTLS=false;
		public boolean SupTorm=false;
		public boolean DirectMode=false;
		public String HelloData=null;
		public int HelloMode=0;
		public String QFDN=null;
		public boolean convExit=false;
		public String OriginalFrom=null;
		public boolean isInternet=false;
		public boolean SupTKIM=false;
		
		SMTPOutSession(String Server,String MailTo,String MailFrom,HashMap <String,String> Hldr,MailBoxFile MBF,String Msg,BufferedReader I, OutputStream O) {
		
			this.I = I;
			this.O=O;
			if (I!=null && O!=null) DirectMode=true;
			this.Hldr =Hldr;
			this.MailFrom=MailFrom;
			this.MailTo = MailTo;
			this.MBF = MBF;
			this.Msg=Msg;
			
		}
		
		public void Send(String str) throws Exception { 
			str+="\r\n";
			O.write(str.getBytes());
			}
		
		public void Close() {
			
				try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
				try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
				try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
		}
	
		protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
