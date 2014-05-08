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
import javax.net.ssl.SSLSocket;

public class SrvAction {
	public  SrvIdentity Mid=null;
	public String Server=null;
	private Socket	RS=null;
	public OutputStream RO=null;
	public BufferedReader RI=null;
	private SMTPReply Re=null;
	public String HostName=null;
	public boolean SupTLS=false;
	public boolean SupTORM=false;
	public boolean SupTKIM=false;
	public boolean SupVMAT=false;
	public boolean SupMF2=false;
	public boolean SupMX=false;
	
	public boolean DoInSSL=true;
	public boolean DoInTKIM=true;
	public boolean ForceSSL = true; 
	public boolean ForceTKIM = true; 
	public MXRecord[] MX = null;	
	public boolean InternetConnection=false;
	
	public String Tag="SrvAction";
	
	public SMTPReply firstReply=null;
	
	public Object[] RES=null;
	public Object[] REQ=null;
	
	public ExitRouterInfo currentExit=null;
	
	SrvAction(SrvIdentity s,String connectTo,String t) {
		Mid=s;
		Server=connectTo.toLowerCase().trim();
		Tag=t;
		HostName =s.Onion;
		}
	
	SrvAction(SrvIdentity s,MXRecord[] MXArray,String t) {
		Mid=s;
		MX = MXArray;
		Server=MXArray[0].Host.toLowerCase().trim();
		Tag=t;
		HostName =s.Onion;
		}
		
	public void Do() throws Exception {
		
		try {
			if (MX==null) MX = new MXRecord[] { new MXRecord(1,Server) };
			int cx = MX.length-1;
			for (int ax=0;ax<=cx;ax++) try {
					Server=MX[ax].Host.toLowerCase().trim();
					if (Mid.Config.Debug) Mid.Log("SrvAction "+Tag+" `"+Server+"` via "+(InternetConnection ? "Inet" : "Tor"));
					if (InternetConnection) RS = new Socket(Server,25); else  RS = J.IncapsulateSOCKS(Mid.Config.TorIP, Mid.Config.TorPort, Server,25);
					break;
				} catch(Exception E) {
				if (currentExit!=null) currentExit.setResult(false);
				if (ax==cx) throw E;	
				Mid.Log("NetworkError: on `"+Server+"` "+E.getMessage().replace("@",""));	
				}
						
			RO = RS.getOutputStream();
			RI  =J.getLineReader(RS.getInputStream());
			RS.setSoTimeout(Mid.Config.MaxSMTPSessionInitTTL);
			Re = new SMTPReply(RI);
			firstReply=Re;
			if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote)"); 
			Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+HostName);
			if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
			SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
			SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
			SupTKIM = SrvSMTPSession.CheckCapab(Re,"TKIM");
			
			if (SupTORM) {
				SupVMAT = SrvSMTPSession.CheckTormCapab(Re, "VMAT");
				SupMF2 = SrvSMTPSession.CheckTormCapab(Re, "MF2");
				SupMX = SrvSMTPSession.CheckTormCapab(Re, "MX");
				}
			
			if (!SupTLS && DoInSSL && ForceSSL) throw new Exception("@500  Doesn't support STARTTLS `"+Server+"`");
			if (!SupTORM && ForceTKIM) throw new Exception("@500 Doesn't support TORM `"+Server+"`");
			if (!SupTKIM && ForceTKIM)  throw new Exception("@500 Doesn't support TKIM `"+Server+"`");
						
			if (SupTLS && DoInSSL) try {
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"STARTTLS");
				if (Re.Code<200 || Re.Code>299) throw new Exception("@500 STARTLS Error `"+Server+"`");
				SSLSocket SS = LibSTLS.ConnectSSL(RS, Mid.SSLClient,Server);
				Mid.CheckSSL(SS, Server,Tag);
				RO = null;
				RO = SS.getOutputStream();
				RI=null;
				RI=J.getLineReader(SS.getInputStream());
				RS=SS;	
				
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+HostName);
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
				SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
				SupTKIM = SrvSMTPSession.CheckCapab(Re,"TKIM");
				if (SupTORM) {
					SupVMAT = SrvSMTPSession.CheckTormCapab(Re, "VMAT");
					SupMF2 = SrvSMTPSession.CheckTormCapab(Re, "MF2");
					SupMX = SrvSMTPSession.CheckTormCapab(Re, "MX");
					}
				
			} catch(Exception SSL) {
					if (currentExit!=null) currentExit.isBad=true;
					throw SSL;
					}
						
			if (SupTKIM && DoInTKIM) {
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"TKIM");
				if (Re.Code<299 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (remote)"); //chkkk
				byte[] rnd = Re.getData();
				try { rnd = Stdio.RSASign(rnd, Mid.SSK); } catch(Exception E) { 
						Mid.Config.EXC(E, Tag+".RSASign(`"+Server+"`)");
						rnd = new byte[0];
						}
				SMTPReply.Send(RO,220,J.Data2Lines(rnd, "TKIM/1.0 REPLY"));
				Re = new SMTPReply(RI);
				if (Re.Code<200 || Re.Code>299) Mid.Log(Config.GLOG_Event,Tag+": `"+Server+"` Error: "+Re.toString().trim());
				}
			
			if (currentExit!=null) currentExit.setResult(true);
			
			OnSession(RI,RO);
			try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception Ii) {}
			try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
			try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
			try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
			} catch(Exception E) {
				try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
				try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
				try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
				throw E;
			} 
		}
	
	public void OnSession(BufferedReader RI,OutputStream RO) throws Exception { Mid.Log(Tag+": NOP");	}
}
