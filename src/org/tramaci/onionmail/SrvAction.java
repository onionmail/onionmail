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

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
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
	
	public boolean acceptAllCrt=false;
	
	public SSLParameters SSLParam = null;
	public SSLSession SSLSess = null;
				
	public String Tag="SrvAction";
	
	public SMTPReply firstReply=null;
	
	public Object[] RES=null;
	public Object[] REQ=null;
	
	public static final int  APOX_INIT=0;
	public static final int  APOX_CONNECT=1;
	public static final int  APOX_HELLO=2;
	public static final int  APOX_STARTTLS=3;
	public static final int  APOX_STARTTLS_HELLO=4;
	public static final int  APOX_TKIM=5;
	public static final int  APOX_SESSION=6;
	public static final int  APOX_END=7;
	public int ActionPosition = APOX_INIT;
	
	public ExitRouterInfo currentExit=null;
	public boolean TKIMOk=false;
	public boolean isInSSL=false;
	public boolean TestTKIM=false;
	public SSLSocket SSLSocketPointer=null;
	
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
			ActionPosition= APOX_CONNECT;
			TKIMOk=false;
			isInSSL=false;
			if (MX==null) MX = new MXRecord[] { new MXRecord(1,Server) };
			int cx = MX.length-1;
			for (int ax=0;ax<=cx;ax++) try {
					Server=MX[ax].Host.toLowerCase().trim();
					if (Mid.Config.Debug) Mid.Log("SrvAction "+Tag+" `"+Server+"` via "+(InternetConnection ? "Inet" : "Tor"));
					if (InternetConnection) {
							if (Mid.ExitIP!=null) RS =  new  Socket(Server,25, Mid.ExitIP, 0); else RS = new Socket(Server,25); 
							} else  RS = J.IncapsulateSOCKS(Mid.Config.TorIP, Mid.Config.TorPort, Server,25);
					break;
				} catch(Exception E) {
				if (currentExit!=null) currentExit.setResult(false);
				if (ax==cx) throw E;	
				Mid.Log("NetworkError: on `"+Server+"` "+E.getMessage().replace("@",""));	
				}
						
			RO = RS.getOutputStream();
			RI  =J.getLineReader(RS.getInputStream());
			RS.setSoTimeout(Mid.Config.MaxSMTPSessionTTL);
			ActionPosition= APOX_HELLO;
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
			
			isInSSL=false;
			
			if (SupTLS && DoInSSL) try {
				ActionPosition= APOX_STARTTLS;
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"STARTTLS");
				if (Re.Code<200 || Re.Code>299) throw new Exception("@500 STARTLS Error `"+Server+"`");
				
				SSLSocket SS=null;
				try {
					SS = LibSTLS.ConnectSSL(RS, Mid.SSLClient,Server);
					} catch(Exception SE) {
						if (Mid!=null) Mid.SSLErrorTrack(Server, SrvIdentity.SSLEID_Err);
						throw SE;
					}
				SSLSocketPointer=SS;
				
				try {
					SSLParam = SS.getSSLParameters();
					SSLSess = SS.getSession();
					} catch(Exception I) {}
				
				if (!acceptAllCrt) {
						try {
							Mid.CheckSSL(SS, Server,Tag);
							
							} catch(Exception E) {
								if (E instanceof SException) {
									SException SE = (SException) E;
									SE.SSLParam=SSLParam;
									SE.SSLSess=SSLSess;
									SE.Host=HostName;
									OnSSLError(SE);
									}
								throw E;
								}
						} else if (Mid.Config.Debug) Mid.Log("SrvAction: AllCRT");
								
				RO = null;
				RO = SS.getOutputStream();
				RI=null;
				RI=J.getLineReader(SS.getInputStream());
				RS=SS;	
				isInSSL=true;
				ActionPosition= APOX_STARTTLS_HELLO;
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
				ActionPosition= APOX_TKIM;
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"TKIM");
				if (Re.Code<299 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (remote)"); //chkkk
				byte[] rnd = Re.getData();
				if (rnd.length!=256) throw new PException("@550 Invalid remote TKIM/RAND data: "+Tag+" `"+Server+"`"); 
				try { rnd = Stdio.RSASign(rnd, Mid.SSK); } catch(Exception E) { 
						Mid.Config.EXC(E, Tag+".RSASign(`"+Server+"`)");
						rnd = new byte[0];
						}
				SMTPReply.Send(RO,220,J.Data2Lines(rnd, "TKIM/1.0 REPLY"));
				Re = new SMTPReply(RI);
				if (Re.Code<200 || Re.Code>299) {
						TKIMOk=false;
						Mid.Log(Config.GLOG_Event,Tag+": `"+Server+"` Error: "+Re.toString().trim());
						if (!TestTKIM) throw new Exception("@"+Re.Code+" TKIM Error: "+Re.Msg[0]);
						} else TKIMOk=true;
				} else TKIMOk=false;
			
			if (currentExit!=null) currentExit.setResult(true);
			ActionPosition= APOX_SESSION;
			OnSession(RI,RO);
			try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception Ii) {}
			try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
			try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
			try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
			ActionPosition= APOX_END;
			} catch(Exception E) {
				try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
				try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
				try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
				throw E;
			} 
		}
	
	public void OnSession(BufferedReader RI,OutputStream RO) throws Exception { Mid.Log(Tag+": NOP");	}
	public void OnSSLError(SException Erro) throws Exception { Mid.Log(Tag+": SSLError: "+Erro.getMessage()); }
	
}
