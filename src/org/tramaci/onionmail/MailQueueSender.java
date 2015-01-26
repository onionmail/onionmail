/*
 * Copyright (C) 2014 by Tramaci.Org
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

import java.util.HashMap;

public class MailQueueSender extends Thread {
	
	public MsgQueueEntry Q = null; 
	private SrvIdentity Mid = null;
	private MailBoxFile MS = null;
	public long Scad = 0;
	public boolean running=false;
	public String DSN=null;
	private String file = null;
	
	public void End() {
		running=false;
		Scad=1;
		try { this.interrupt(); } catch(Exception I) {}
		try { MS.Close(); MS=null; } catch(Exception I) {};
		try { J.Wipe(file, Mid.Config.MailWipeFast); } catch(Exception I) {}
		
		}
	
	MailQueueSender(MsgQueueEntry qe,SrvIdentity srv) throws Exception {
		super();
		Q=qe;
		Mid = srv;
		MS = new MailBoxFile();
		file = Q.FileName(Mid);
		MS.OpenAES(file, Q.Key, false);
		Scad = System.currentTimeMillis()+(Mid.Config.QueueTimeOut*1000L);
		running=true;
		start();
		}

	public void run() {
		
		try {
			Mid.Log("Retry to send");
			Mid.SendRemoteSession(Q.MailTo, Q.MailFrom, Q.HLDR, MS, Q.VMATTo);
			Mid.Log("Complete");
			} catch(Exception E) {
				String ms = E.getMessage();
				if (ms==null || !ms.startsWith("@")) {
				Mid.Config.EXC(E, Mid.Nick+".Queue");
				if (Mid.Config.Debug) E.printStackTrace();
				} else {
					ms=ms.substring(1);
					Mid.Log("Queue Error: "+ms);
					DSN=ms;
					}
				}
		
	try {
		MS.Close();
		J.Wipe(file,Mid.Config.MailWipeFast);
		} catch(Exception E) {
			Mid.Config.EXC(E, Mid.Nick+".QueueDel");
			if (Mid.Config.Debug) E.printStackTrace();
			}
	
	if (running & DSN!=null) {
				try {
					Mid.Log("Sending DSN");
					HashMap <String,String> H = SrvSMTPSession.ClassicHeaders("server@"+Mid.Onion,Q.MailFrom);
					H.put("x-failed-recipients",Q.MailTo);
					H.put("date", Mid.TimeString());
					DynaRes Re = DynaRes.GetHinstance(Mid.Config, "dsn", Mid.DefaultLang);
					Re.Par.put("mailerr", Q.MailTo);
					Re.Par.put("erro", "SMTP error from remote mail server: "+DSN);
					Re = Re.GetH(H);
					Re.Res+=J.CreateHeaders(Q.HLDR);
				
					Mid.SendMessage(Q.MailFrom, Re.Head,Re.Res);
					} catch(Exception E) {
						String ms = E.getMessage();
						if (ms==null || !ms.startsWith("@")) {
							Mid.Config.EXC(E, Mid.Nick+".Queue");
							if (Mid.Config.Debug) E.printStackTrace();
							} else {
								ms=ms.substring(1);
								Mid.Log("Queue DSN Error: "+ms);
								}
					}
				}
	running=false;
	}
}
