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

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.HashMap;

public class Application {
	public String localPart = null;
	public int accessMode  = 0;
	public String commandLine = null;
	public int  runMode=0;
	public volatile int statsHit=0;
	public volatile int statsError=0;
	public int maxReLength = 32000;
	public int maxMsgLength=32000;
	public String charSet="UTF-8";
	public boolean encode=true;
	public boolean Debug = false;
	
	public HashMap <String,String> ENV = null;
	public String Path=null;
	
	public static final int ACCESS_USER=1;
	public static final int ACCESS_SYSOP=2;
	public static final int ACCESS_INET=4;
	public static final int ACCESS_TOR=8;
	
	public static final int RUN_SMTP = 1;
	public static final int RUN_BATCH = 2;
	public static final int RUN_APP=3;
	
	public void Run(SrvIdentity S, String mailFrom, HashMap <String,String> Hldr, String msg) throws Exception {
		Process p=null;
		BufferedReader stdIn=null;
		BufferedReader stdErr=null;
		OutputStream stdOut=null;  
		SMTPReply Re=null;
		boolean isErr=false;
		if (msg.length()>maxMsgLength) throw new PException("@550 Message too long");
		try {
			//exec(String command, String[] envp, File dir)
				HashMap<String,String> En = new HashMap<String,String>();
				if (ENV!=null) for (String k:ENV.keySet()) En.put(k, ENV.get(k));
				En.put("server-nick", S.Nick);
				En.put("server-onion", S.Onion);
				En.put("mail-from", mailFrom);
				En.put("server-time", Long.toString(S.Time()));
				En.put("server-timestr", S.TimeString());
				String env = "";
				for (String k:En.keySet()) env+=k+"="+En.get(k)+"\n";
				String[] envA = env.split("\\n+");
				env=null;
				En=null;
				System.gc();
				
				//exec(String command, String[] envp, File dir)
				p = Runtime.getRuntime().exec(commandLine,envA, Path == null ? null : new File(Path));
	           
				stdIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
				InputStream err = p.getErrorStream();
	            stdErr = new BufferedReader(new InputStreamReader(err));
	            stdOut = p.getOutputStream();
           	    
	            if (err.available()>0) { isErr=true; throw new Exception(); } 
	            
	            if (runMode==RUN_SMTP) {
	            	Re = new SMTPReply(stdIn);
	            if (Config.Debug && Debug) S.Log("APP: "+Re.toString());
	            	if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (app/init)");
	            	Re = SrvSMTPSession.RemoteCmd(stdOut,stdIn,"EHLO "+S.Nick);
	            if (Config.Debug && Debug) S.Log("APP EHLO: "+Re.toString());
	            	if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (app/ehlo)");
	            	Re = SrvSMTPSession.RemoteCmd(stdOut,stdIn,"MAIL FROM: "+mailFrom);
	            if (Config.Debug && Debug) S.Log("APP FROM: "+Re.toString());
	            	if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (app/from)");
	            	Re = SrvSMTPSession.RemoteCmd(stdOut,stdIn,"RCPT TO: "+localPart+"@"+S.Onion);
	           if (Config.Debug && Debug) S.Log("APP TO: "+Re.toString());	
	            	if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (app/to)");
	            	Re = SrvSMTPSession.RemoteCmd(stdOut,stdIn,"DATA");
	            if (Config.Debug && Debug) S.Log("APP DATA: "+Re.toString());
	            	if (Re.Code<300 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (app/data)");
					}
	            
	       if (err.available()>0) { isErr=true; throw new Exception(); }     
	       if (	runMode==RUN_APP) Hldr.put("from", mailFrom);
	       if (runMode!=RUN_BATCH) {
	    	   	Hldr.put("x-server", S.Nick);
	    	   	Hldr.put("envelope-from", mailFrom);
	    	   	if (!Hldr.containsKey("subject")) Hldr.put("subject", " ");
	    	   	String s = J.CreateHeaders(Hldr);
	    	   	s=s.trim();
	    	   	s+="\r\n\r\n";
	    	   	stdOut.write(s.getBytes());
	    	   	stdOut.flush();
	    	   	}
	       
	       if (err.available()>0) { isErr=true; throw new Exception(); }
	       stdOut.write(msg.getBytes());
	       stdOut.write("\r\n.\r\n".getBytes());
	       stdOut.flush();
	       if (err.available()>0) { isErr=true; throw new Exception(); }
	       
	       String rmsg="";
	       String li;
	      
	       if (runMode==RUN_SMTP) {
	    	 Re = new SMTPReply(stdIn);
	     if (Config.Debug && Debug) S.Log("APP DATA_RE: "+Re.toString());
	    	 
	    	 if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (app/data)");
	       	}
	       
	       if (runMode==RUN_APP) {
	    	  li = stdIn.readLine();
	    	  if (li!=null && li.contains("@")) {
	    		String[] tok = li.split("\\@",2);
	    		li = "@"+tok[1].trim();
	    		if (!li.matches("\\@[0-9]{3} *")) throw new PException("@550 Invalid Exception"); else throw new PException(li);
	    	  	}
	      	}
	      
	      HashMap <String,String> H=null;
	      if (runMode!=RUN_BATCH) {
	        		H = J.ParseHeaders(stdIn);
	        		if (!H.containsKey("subject")) H.put("subject", "Application Reply");
	        		}
	        
	         while ((li = stdIn.readLine()) != null) {
                li=li.trim();
                if (err.available()>0) { isErr=true; throw new Exception(); }
                if (li.compareTo(".")==0) break;
                rmsg+=li+"\n";
                if (rmsg.length()>maxReLength) throw new PException("@550 Reply message too long");
	         	}
	        
	        if (err.available()>0) { isErr=true; throw new Exception(); } 
	        if (p!=null) try { p.destroy(); p=null; } catch(Exception I) {}		
			if (stdIn!=null) try { stdIn.close(); } catch(Exception I) {}
			if (stdErr!=null) try { stdErr.close(); } catch(Exception I) {}
			if (stdOut!=null) try { stdOut.close(); } catch(Exception I) {}
			
			rmsg=rmsg.trim();
			if (rmsg.length()>0) {
				Hldr = SrvSMTPSession.ClassicHeaders(localPart+"@"+S.Onion, mailFrom);
				Hldr.put("content-type", "text/plain; charset="+charSet);
				if (encode) {
						Hldr.put("content-transfer-encoding", "base64");
						rmsg=J.msgBase64Encode(rmsg);
						}
				if (runMode!=RUN_BATCH && H!=null) Hldr.putAll(H); else Hldr.put("subject", "application reply");
				S.Log("APP `"+localPart+"` Ok");
				Hldr.put("x-generated", "server app");
				S.SendMessage(mailFrom, Hldr, rmsg);
				if (Config.Debug && Debug) S.Log("APP: Ok "+Hldr.get("subject"));
				statsHit++;
				}
			
			} catch(Exception E) {
				statsError++;
				String erro="";
				String mse=null;
				if (isErr) {
					String li ="";
					  while ((li = stdErr.readLine()) != null) {
						  	li=li.trim();
						  	if (li.startsWith("@")) {
						  		li+=" ";
						  		mse="@550 "+li.substring(1).trim(); 
						  		} else erro+=li+"\n";
						  	}
						} else {
						mse = E.getMessage();
						if (mse!=null && !mse.startsWith("@")) mse=null;
						}
						
					if (mse==null && erro.length()>0) {
						Hldr = SrvSMTPSession.ClassicHeaders(localPart+"@"+S.Onion, mailFrom);
						Hldr.put("content-type", "text/plain; charset="+charSet);
						Hldr.put("subject", "application error");
						if (encode) {
								Hldr.put("content-transfer-encoding", "base64");
								erro=J.msgBase64Encode(erro);
								}
						S.Log("APP `"+localPart+"` Error");
						S.SendMessage(mailFrom, Hldr, erro);
						} 
					
				if (p!=null) try { p.destroy(); } catch(Exception PE) { S.Config.EXC(PE, S.Nick+".App.`"+localPart+"`.endProcess"); }		
				if (stdIn!=null) try { stdIn.close(); } catch(Exception I) {}
				if (stdErr!=null) try { stdErr.close(); } catch(Exception I) {}
				if (stdOut!=null) try { stdOut.close(); } catch(Exception I) {}
				
				if (mse!=null) {
						S.Log("APP `"+localPart+"` Error: "+mse.substring(1));
						throw new Exception(mse);
						}
				throw E;
			}
	}
}
