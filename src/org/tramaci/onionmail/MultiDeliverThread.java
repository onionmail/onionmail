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

//XXX TODO  Bug fix: From header in VMAT mode!

package org.tramaci.onionmail;

import java.io.BufferedReader;
import java.io.File;
import java.util.HashMap;

public class MultiDeliverThread extends Thread { 
	
	public SrvIdentity Mid=null;
	public boolean running=false;
	public int status=0;
	
	private MailBoxFile Message=null;
	private HashMap <String,String> Hldr = null;
	private HashMap <String,String> HldrInet = null;
	
	private String[] MailTo = null;
	private String[] Error = null;
	private boolean[] toTor = null;
	private String[] MailToInet=null;
	private String MailFrom=null;
	private String MailFromInet=null;
	public long Started=0;
	private String ExitDom="";
	
	public void run() {
		
		try {
			Started=System.currentTimeMillis();
			
			
			boolean errs=false;
			int cx = MailTo.length;
			for (int ax=0;ax<cx;ax++) {
					try {
				
						String to = MailTo[ax];
						String srv = J.getDomain(to);
						
						HashMap <String,String> Hldr2 =(HashMap <String,String>) (toTor[ax] ?  Hldr.clone() : HldrInet.clone());
								
						Hldr2.put("delivery-date", Mid.TimeString());
						
						
						
						if (srv.compareTo(Mid.Onion)==0) Mid.SendLocalMessageStream(to, Hldr2, null, Message); else Mid.SendRemoteSession(to, MailFrom,Hldr2, Message,null);
						
						} catch(Exception E) {
							String ms = E.getMessage();
							errs=true;
							if (Mid.Config.Debug) E.printStackTrace();
							if (ms==null) ms="NULL";
							if (ms.startsWith("@")) {
								ms=ms.substring(1);
								Error[ax] = "To `"+MailTo[ax]+"` Error: "+ms;
								Mid.Log("Mul to `"+J.UserLog(Mid, MailTo[ax])+"` Error: "+ms+"\n");
								Mid.StatError++;
								} else {
								String ms2="Error X"+Long.toHexString(ms.hashCode() & 0x7FFFFFFFFFL);
								if (ms.contains("Socks:") || E instanceof java.net.ConnectException) {
										ms2="Network error";
										if (MailTo[ax].endsWith(".onion") || ms.contains("H5B")) ms2+=" Onion route is down";
										if (E instanceof java.net.ConnectException) ms2="Connection error "+Integer.toHexString((""+E.getMessage()).hashCode());
										}
								
								if (E instanceof InterruptedException) ms2="Operation Timeout";
								if (E instanceof java.net.SocketException) ms2="Network Socket error "+Integer.toHexString((""+E.getMessage()).hashCode());
								if (E instanceof java.net.NoRouteToHostException) ms2="No route to host";
								if (E instanceof java.net.SocketTimeoutException) ms2="Network timeout";
								if (E instanceof java.net.UnknownHostException) ms2="Unknown host";
								
								Error[ax] = "To `"+MailTo[ax]+"` Error: "+ms2;
								Mid.Log("Mul Exc `"+J.UserLog(Mid,MailTo[ax])+"` Error: "+ms+"\n");
								Mid.StatException++;
								}
						}
					
					Message.Rewind();
				}
					
		Message.Destroy(Mid.Config.MailWipeFast);
		Message=null;
		System.gc();
		if (!errs) {
			running=false;
			return;
			}
	
		HashMap <String,String> H = SrvSMTPSession.ClassicHeaders("server@"+Mid.Onion, MailFrom);
		 H.put("subject", "Mail delivery failed: returning message to sender");
		 String msg="This message was created automatically by mail delivery software.\n"+
				 "A message that you sent could not be delivered to one or more of its recipients.:\n\n";

		for (int ax=0;ax<cx;ax++) {
			if (Error[ax]!=null) msg+=Error[ax].trim()+"\n";
			}
		 
		 msg+="\n------ This is a copy of the headers of message ------\n\n";
		 msg+=J.CreateHeaders(Hldr).replace("\r\n", "\n").trim();
		 msg+="\n------\n\n\t"+Mid.Nick+"\n";
		 
		 H.put("auto-submitted" ,"auto-replied");
		 H.put("return-path", "<>");
		 H.put("x-generated" ,"server dsn");
		 
		 Mid.SendMessage(MailFrom, H, msg);
				 
		} catch(Exception ME) { Mid.Config.EXC(ME, "MulSend `"+Mid.Nick+"`"); }
		running=false;
		Started=0;
		int cx= Main.MultiTthread.length;
		for (int ax=0;ax<cx;ax++) if (Main.MultiTthread[ax]==this) Main.MultiTthread[ax]=null;
	}
	
	public void End() {
		try { this.interrupt(); } catch(Exception E) {};
		
		String fd=null;
		if (Message!=null) try { 
				Message.Destroy(Mid.Config.MailWipeFast);
				} catch(Exception E) { 
						Mid.Config.EXC(E, Mid.Nick+".DultiDevEnd");
						if (Message!=null) try {
								fd=Message.getFileName();
								if (fd!=null) {
									try { Message.Close(); } catch(Exception I) {}
									File f = new File(fd);
									if (f.exists()) J.Wipe(fd, Mid.Config.MailWipeFast);
									if (f.exists() && !f.delete()) throw new Exception("Can't delete `"+fd+"`");
									}
								} catch(Exception EF) {
								Mid.Config.EXC(E, Mid.Nick+".DultiDevEnd.delete");	
								}
						}
		
		Message=null;
		running=false;
		Started=0;	
	}
		
	MultiDeliverThread(SrvIdentity Srv,String from, String[] to, HashMap <String,String> H,BufferedReader M) throws Exception {
		Mid=Srv;
		//Main.echo("DDD `"+from+"` "+H+"\n");
		
		if (Mid.EnterRoute) ExitDom = Mid.ExitRouteDomain; else {
				ExitRouteList RL= Mid.GetExitList();
				ExitRouterInfo ri = RL.selectBestExit();
				if (ri!=null) ExitDom = ri.domain; 
				}
		
		Hldr = H;
		
		int cx = to.length;
		MailTo = new String[cx];
		
		for (int ax=0;ax<cx;ax++) {
			if (!to[ax].endsWith(".onion")) {
				String lp = J.getLocalPart(to[ax]);
				String dm =J.getDomain(to[ax]);
				VirtualRVMATEntry VM = Mid.VMAT.loadRVMATinTor(lp, dm);
				if (VM!=null) {
					dm = J.getDomain(VM.onionMail);
					if (dm.compareTo(Mid.Onion)==0) {
						if (Config.Debug) Mid.Log("MRouteLocalInVMAT `"+J.UserLog(Mid, to[ax])+"` > `"+J.UserLog(Mid, VM.onionMail)+"`");
						MailTo[ax]=VM.onionMail;
						}
					}
				}
			if (MailTo[ax]==null) MailTo[ax]=to[ax];
			}
		
		MailFrom=from.toLowerCase().trim();
		if (MailFrom.endsWith(".onion")) MailFromInet = Srv.mailTor2Inet(MailFrom, ExitDom); else MailFromInet=MailFrom; //XXX Verificare
		
		cx=MailTo.length;
		toTor = new boolean[cx];
		Error = new String[cx];
		MailToInet = new String[cx];
		
		Hldr.put("message-id", J.RandomString(16)+"@"+Mid.Onion);
		Hldr.put("date", Mid.TimeString());
		Hldr.put("delivery-date", Mid.TimeString());
		
		HldrInet = new HashMap <String,String>();
		for (String k:Hldr.keySet()) HldrInet.put(k, Hldr.get(k));
		
		String t="";
		for (int ax=0;ax<cx;ax++) {
			toTor[ax]=MailTo[ax].endsWith(".onion");
			if (toTor[ax]) MailToInet[ax]=J.MailOnion2Inet(Srv.Config, MailTo[ax], ExitDom); else MailToInet[ax]=MailTo[ax];
			t+="<"+MailToInet[ax]+">\n";
			}
		t=t.trim();
		t=t.replace("\n",", ");
		
		Hldr.put("sender", from);
		Hldr.put("errors-to","<>");
		
		HldrInet.put("sender", MailFromInet);
		HldrInet.put("errors-to","<>");
		HldrInet.put("from", MailFromInet);
		HldrInet.put("to",t);
						
		Mid.Log("MultiDeliver Exit=`"+(ExitDom!=null ? ExitDom: "<N/A>")+"`");
		
		long t0 = System.currentTimeMillis();
		t0=t0^t0<<1;
		
		String Tmp = Mid.Maildir+"/md"+Long.toString(t0,36)+".tmp";
				
		long MessageBytes=0;
		MailBoxFile TM = new MailBoxFile();
		TM.OpenTMP(Tmp);
		while(true) {
			J.RunCheck();
			String li = M.readLine();
			if (li==null)  {
				TM.Destroy(true);
				throw new Exception("@500 Socket error");
				}
			
			if (li.compareTo(".")==0) break;
			MessageBytes+=li.length()+2;
			if (MessageBytes>Mid.MaxMsgSize) {
				TM.Destroy(true);
				throw new Exception("@500 Message too big");
				}
			
			TM.WriteLn(li.replace("\r\n", ""));
			}
		TM.WriteLn(".");
		TM.TMPRead();
		Message=TM;
		running=true;
		this.start();
	}
	
	

}
