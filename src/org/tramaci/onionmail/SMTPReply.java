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

public class SMTPReply {
	public int Code = 0;
	public String[] Msg = new String[0];
	
	private static final int MaxReplyLine = 8192;
	private static final String Err1="SMTP Reply format Error";
	
	public void Send(OutputStream O) throws Exception {
		O.write(
					createReply(Code,Msg).getBytes()
					)	;
		}
	
	
	public static void Send(SrvSMTPSession S,int code,String msg) throws Exception {
		S.O.write(
					createReply(code,msg).getBytes()
					)	;
	}
	
	
	public static void Send(OutputStream O,int code,String msg) throws Exception {
		O.write(
					createReply(code,msg).getBytes()
					)	;
	}

	public static void Send(OutputStream O,int code,String[] li) throws Exception {
		O.write(
					createReply(code,li).getBytes()
					)	;
	}
	
	public static void Send(SrvSMTPSession S,int code,String[] li) throws Exception {
		S.O.write(
					createReply(code,li).getBytes()
					)	;
	}
	
	
	SMTPReply(BufferedReader I) throws Exception {
		String msg="";
		Code=0;
			for (int ax=0;ax<MaxReplyLine;ax++) {
				String li = I.readLine();
				if (li==null) throw new Exception("@550 Connection lost!");
				li=li.trim();
				if (li.length()<4) throw new Exception(Err1);
				String[] Tok = null;
				boolean ultimo = false;
				
				if (li.charAt(3)==' ') {
					Tok = li.split(" ",2);
					ultimo=true;
					} else {
					Tok = li.split("\\-",2);
					if (Tok.length!=2) throw new Exception(Err1);
					}
				
				if (Tok.length!=2) throw new Exception(Err1);
				if (ax==0) {
					Code = J.parseInt(Tok[0]);
					if (Code<100 || Code>999) throw new Exception(Err1);
					} else {
					int a = J.parseInt(Tok[0]);
					if (a!=Code) throw new Exception(Err1);
					}
			li=Tok[1].trim();
			msg+=li+"\n";
			if (ultimo) break;
			}
		
		msg=msg.trim();
		Msg = msg.split("\\n");
	} 
	
	SMTPReply(int code ,String msg) {
		Code = code;
		msg=msg.trim();
		String[] li = msg.split("\\n");
		int cx =li.length;
		Msg = new String[cx];
		for (int ax=0;ax<cx;ax++) {
			Msg[ax] = li[ax].trim();
			}
	}
	
	SMTPReply(int code,byte[] data,String extra) {
		Msg = J.Data2Lines(data, extra);
		Code=code;
	}
	
	SMTPReply(int code,String[] data,String extra) {
		Msg = data;
		Code=code;
	}
	
	public byte[] getData() throws Exception { return J.Lines2Data(Msg); }
	
	public byte[] getData(String[] EXTRA) throws Exception { return J.Lines2DataX(Msg,EXTRA);}
	
	public String toString() { return createReply(Code,Msg);	}
	
	public static String createReply(int code, String msg) {
		String li[] = msg.split("\\n");
		int cx = li.length-1;
		String out="";
		for (int ax=0;ax<=cx;ax++) {
			out+=Integer.toString(code + 1000).substring(1);
			if (ax!=cx) out+="-"; else out+=" ";
			out+=li[ax].trim()+"\r\n";
		}
		return out;
	}
	
	public static String createReply(int code, String[] li) {
		int cx = li.length-1;
		String out="";
		for (int ax=0;ax<=cx;ax++) {
			out+=Integer.toString(code + 1000).substring(1);
			if (ax!=cx) out+="-"; else out+=" ";
			out+=li[ax].trim()+"\r\n";
		}
		return out;
	}
	
	public String[] CheckCapabilty(String quale) {
		if (Msg==null || Msg.length==0) return null;
		int cx = Msg.length;
		String q="";
		for (int ax=1;ax<cx;ax++) {
			if (Msg[ax].compareTo(quale)==0) {
					q+=quale+"\n";
					continue;
					}
			
			if (Msg[ax].startsWith(quale+" ")) {
					int lz = quale.length()+1;
					if (Msg[ax].length()<lz+1) {
							q+=quale+"\n";
							continue;
							}
					q+=Msg[ax].substring(lz).trim()+"\n";
					}	
			}
		q=q.trim();
		return q.split("\\n+");
	}
	
}
