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
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;

import javax.net.ssl.SSLSocket;

import org.tramaci.onionmail.MailBox.Message;


public class SrvPop3Session extends Thread {

	public SrvIdentity Mid = null;
	
	private Socket sok;
	private DataInputStream in; 
	private BufferedReader br;
	private OutputStream O;

	private Config Config = null;
	public long EndTime = 0;	
	public int LoginHash = 0;	
	private String Login=null;
	private MailBox MB = null;
	
	private POP3Server ParentServer;
	
	private boolean Deleted[];
	private boolean DeleteR[];
	private int MsgSize[];
	private int MsgNum;
	private int BoxSize=0;
	private int BoxLen;
	private int BoxSizeo;
	
	private boolean TLSON=false;
	public boolean isDismissed = false;
		
	private void BeginPOP3Session() throws Exception {

		Mid.StatPop3++;
		String inf="";
		try { this.ZZ_Exceptionale(); } catch(Exception E) { inf = J.GetExceptionalInfo(E); }
		inf = Stdio.Dump(Stdio.md5(inf.getBytes()));
		inf +=" "+Mid.GetRunString();
			
		Reply(true,"POP3 "+Mid.Onion+" INF "+inf);
		String Pass=null;
		
		while(isConnected() && !isOld()) {
			String[] Tok = 	ReadCommands(5,new String[] {"QUIT","USER ","PASS ","CAPA","APOP","STLS","STARTTLS"});
			if (Tok[0].compareTo("QUIT")==0)  {
					Reply(true);
					close();
					return;
					}			
			
			boolean fn=false;
			
			if (Tok[0].compareTo("STLS")==0||Tok[0].compareTo("STARTTLS")==0)  {
					if (TLSON) {
							Reply(false,"Command not permitted when TLS active");
							continue;
							}
			
					Reply(true,"Begin TLS negotiation");
					SSLSocket SL = LibSTLS.AcceptSSL(sok, Mid.SSLServer, Mid.Onion);
					in = new DataInputStream(SL.getInputStream());
					br = new BufferedReader(new InputStreamReader(in));
					O = SL.getOutputStream();
					sok=SL;
					
					TLSON=true;
					continue;
					}
			
			if (Tok[0].compareTo("CAPA")==0)  {
					CAPA();
					continue;
					}	
			
			if (Tok[0].compareTo("APOP")==0) {
				Reply(false,"Can't use APOP");
				continue;
				}
			
			if (Tok.length==2) {
				
				if (Tok[0].compareTo("USER")==0)  {		
				if (!TLSON) {
						Reply(false,"Authentication too weak, use SSL!");
						continue;
						}	
					fn=true;
					Tok[1]=Tok[1].trim().toLowerCase();
					if (!Mid.UsrExists(Tok[1])) {
						Reply(false,"Unknown user");
						continue;
						}
					Login=Tok[1];
					Reply(true);
					}
				
			if (Tok[0].compareTo("PASS")==0)  {
				if (!TLSON) {
						Reply(false,"Authentication too weak, use SSL!");
						continue;
						}	
					fn=true;
					Tok[1]=Tok[1].trim();
					if (Login==null) {
						Reply(false,"Use USER first!");
						continue;
						}
					
					try {
						Pass=Tok[1];
						MB = Mid.UsrOpenW(Config,Login,Pass);
						} catch(Exception E) {
							if (Config.Debug) { Config.EXC(E, "POP3Pass"); }
							Reply(false," "+E.getMessage());
							continue;
						}
					
					if (MB==null) {
						Reply(false,"Access denied");
						continue;
						}
					break;
					}
				
				} //toklen
			
			if (!fn) Reply(false,"WTF???");
			}
		
		if (MB==null || Login==null) throw new Exception("@Too many errors");
		
		////////////////// mailbox /////////////////////////
			
		LoginHash=0;
		int cx = Login.hashCode();
			
		if (ParentServer.isBoxOpen(cx)) {
			
			Reply(false,"Inbox arleady open");
			ReadCommands(2,new String[] {"QUIT"});
			Reply(true,"consing connection");
			close();
			return;
			}
		LoginHash=cx;

		BoxSize=0;
		MB.UpdateIndex();
		MsgNum = MB.Length();
		BoxLen = MsgNum;
		MsgSize= new int[MsgNum];
		Deleted = new boolean[MsgNum];
		if (Mid.AutoDeleteReadedMessages) DeleteR = new boolean[MsgNum];
		
		String[] UIDL = new String[MsgNum];
		Pass="X";
		Pass=null;
		System.gc();
		
		byte[] UIDLBase = Stdio.md5a( new byte[][] { Login.getBytes() , Mid.Onion.getBytes() , Mid.Sale });
			
		for (int ax=0;ax<MsgNum;ax++) {
			Message m = MB.MsgInfo(ax);
			if (m==null) {
				UIDL[ax] = "null-"+Long.toString(ax,36);
				MsgSize[ax]=0;
				continue;
				}
			MsgSize[ax] = (int) m.Size;
			BoxSize+=MsgSize[ax];
			byte[] b = Stdio.md5a( new byte[][] { m.ID , UIDLBase } );
			long[] H = Stdio.Lodsx(b, 8);
			UIDL[ax] = Long.toString(H[0],36)+"-"+Long.toString(H[1],36);
			try { m.Close(); } catch(Exception I) { if (Config.Debug) Config.EXC(I, "POP3Session(`"+Mid.Nick+"`)"); }
		}
		
		BoxSizeo=BoxSize;
		
		Reply(true);
				
		while(isConnected() && !isOld()) {
			String[] Tok = 	ReadCommands(5,new String[] {"QUIT","STAT","APOP","NOOP","RETR","RSET","LIST","DELE","UIDL","TOP","CAPA","STLS","STARTTLS"});
			if (Tok[0].compareTo("QUIT")==0)  {
					break; 
					}			
			
			if (Tok[0].compareTo("STLS")==0||Tok[0].compareTo("STARTTLS")==0)  {
					Reply(false,"WTF ???");
					continue;
					}
			
			if (Tok[0].compareTo("CAPA")==0)  {
					CAPA();
					continue;
					}	
			
			
			if (Tok[0].compareTo("STAT")==0) {
				Reply(true,MsgNum+" "+BoxSize);
				continue;
				}
			
			if (Tok[0].compareTo("LIST")==0 && Tok.length==1) {
				String q="";
				for (int ax=0;ax<BoxLen;ax++) {
					if (Deleted[ax]) continue;
					q+=toIntPop(ax)+" "+MsgSize[ax]+"\n";
					}
				
				q=q.trim();
				if (q.length()==0) Reply(false,"no such message"); else ReplyA(true,MsgNum+" messages ("+BoxSize+" octects)",q.split("\\n+"));
				continue;
				}
			
			if (Tok[0].compareTo("UIDL")==0 && Tok.length==1) {
				String q="";
				for (int ax=0;ax<BoxLen;ax++) {
					if (Deleted[ax]) continue;
					q+=toIntPop(ax)+" "+UIDL[ax]+"\n";
					}
				
				q=q.trim();
				if (q.length()==0) Reply(false,"no such message"); else ReplyA(true,MsgNum+" messages ("+BoxSize+" octects)",q.split("\\n+"));
				continue;
				}
			
			if (Tok[0].compareTo("LIST")==0 && Tok.length==2) {
				int sel = pIntPop(Tok[1]);
				if (CheckMessage(sel)) Reply(true,toIntPop(sel)+" "+MsgSize[sel]); else Reply(false,"no such message");
				continue;
				}
				
			if (Tok[0].compareTo("UIDL")==0 && Tok.length==2) {
				int sel = pIntPop(Tok[1]);
				if (CheckMessage(sel)) Reply(true,toIntPop(sel)+" "+UIDL[sel]); else Reply(false,"no such message");
				continue;
				}
			
			
			if (Tok[0].compareTo("RETR")==0 && Tok.length==2) {
				int sel = pIntPop(Tok[1]);
				if (!CheckMessage(sel)) {
					Reply(false,"no such message");
					continue;
					}
				RETR(sel,-1);
				DeleteR[sel]=true;
				continue;
				}
						
			if (Tok[0].compareTo("TOP")==0 && Tok.length==3) {
				int maxl =J.parseInt(Tok[2]);
				int sel = pIntPop(Tok[1]);
				if (!CheckMessage(sel)) {
					Reply(false,"no such message");
					continue;
					}
				RETR(sel,maxl);
				continue;
				}
		
			
			if (Tok[0].compareTo("DELE")==0 && Tok.length==2) {
				int sel = pIntPop(Tok[1]);
				if (!CheckMessage(sel)) {
					Reply(false,"no such message");
					continue;
					}
				
				Deleted[sel]=true;
				MsgNum--;
				BoxSize-=MsgSize[sel];
				Reply(true,toIntPop(sel)+" deleted");
				continue;
				}
			
			if (Tok[0].compareTo("RSET")==0 && Tok.length==1) {
				BoxSize=BoxSizeo;
				MsgNum=BoxLen;
				Deleted=new boolean[BoxLen];
				DeleteR=new boolean[BoxLen];
				Reply(true,MsgNum+" messages");
				continue;
			}
			
			Reply(false,"WTF???");		
		}
		
		int errs=0;
		int dels=0;
		if (Mid.AutoDeleteReadedMessages) {
			cx=DeleteR.length;
			for (int ax=0;ax<cx;ax++) Deleted[ax]|=DeleteR[ax];
			DeleteR=null;
			}
		
		for (int ax=0;ax<BoxLen;ax++) {
			if (Config.Debug) Log("Quit & Delete messages");
			if (Deleted[ax]) {
				if (Config.Debug) Log("DeleteMsg `$"+ax+"`");
				Message M = MB.MsgOpen(ax);
				if (M==null) {
						if (Config.Debug) Log("DeleteMsg Can't delete `$"+ax+"` MsgOpen=NULL");
						continue;
						}
				try { MB.RemoveFromIndex(ax); } catch(Exception E) { Log("Can't remove form index "+(ax+1)+"\n"); }
				if (M.FileName==null) {
					Log("Can't remove completely BadBlock $i"+ax+" Will be delete by garbage next time!\n");
					continue;
					}
				
				String fn=M.FileName;
				M.Close();
				M=null;
				
				try { J.Wipe(fn, Config.MailWipeFast); } catch(Exception E) { Config.EXC(E, Mid.Nick+" Wipe `"+M.FileName+"`");  }
				File ms = new File(fn);
				if (ms.exists() && !ms.delete()) {
					errs++;
					 Log("Can't delete file `"+ms.getName()+"`\n");
					} else dels++;
				} 
		}
		if (errs>0) Reply(false,"Can't delete "+errs+" messages"); else Reply(true,dels+" messages deleted");
		close();
		}
	
	private void RETR(int sel,int maxline) throws Exception {
		Message M = MB.MsgOpen(sel);
		
		if (M.deleted) {
			String st="+OK 0 octects\r\n"+
					"From: "+M.MailFrom+"\r\n"+
					"To: "+M.RcptTo+"\r\n"+
					"Subject: "+M.Subject+"\r\n"+
					"Date: "+J.TimeStandard(M.Time, Mid.TimerSpoofFus)+"\r\n"+
					"X-Originated: trash\r\n"+
					"X-Old-Size: "+M.Size+"\r\n"+
					"MIME-Version: 1.0\r\n"+
					"Content-Type: text/plain\r\n"+
					"Content-Transfer-Encoding: 7bit\r\n\r\n";
					
			if (maxline!=0) st+="This message has been deleted from the server by grabage collector.\r\n";
			Write(st+".\r\n");
			return;
		}
		
				Write("+OK "+M.Size+" octects\r\n");
				String li = M.ReadLn();
				if (li==null) {
					M.Close();
					Write(".\r\n");
					return;
					}
				li=li.trim();
				Write(li+"\r\n\r\n");
				
				if (maxline==0) {
					Write(".\r\n");
					return;
					}
				
				int ax=0;
				while(true) {
					li = M.ReadLn();
					if (li==null) break;
					if (!li.endsWith("\r\n")) li+="\r\n";
					if (li.compareTo(".\r\n")==0) li =" .\r\n";
					Write(li);
					if (maxline!=-1) {
						ax++;
						if (ax>=maxline) break;
						}
					}
				Write(".\r\n");
				M.Close();
				M=null;
		
	}
	
	private void CAPA() throws Exception {
		String po="USER\nLOGIN-DELAY 900\n"+
				"EXPIRE "+Integer.toString(Config.MailRetentionDays)+"\n"+
				"UIDL\n";
		
		if (!TLSON) po+="STLS\nSTARTTLS\n";
		po+="IMPLEMENTATION POP3";
		po=po.trim();
		
		ReplyA(true,"Capability list follows", po.split("\\n+"));
	}
	
	private boolean CheckMessage(int sel) throws Exception {
		if (sel<0 || sel>=BoxLen) return false;
		if (Deleted[sel]) return false;
		return true;
	}
	
	private String[] ReadCommands(int maxret,String[] cmds) throws Exception {
		for (int ax=0;ax<maxret;ax++) {
			String li = br.readLine();
			if (li==null) throw new Exception("@Connection closed!");
			li=li.trim();	
			String[] tok = J.GetFuckedTokens(li, cmds);
			if (tok==null) Reply(false,"WTF???"); else return tok;
		}
		throw new Exception("@Too many errors");
	}
	
	///// functions ////////////
	
	public void run() {
		
		try {
			BeginPOP3Session();			
		} catch(Exception E) {
			LoginHash=0;
			if (isConnected()) {
				String st = E.getMessage();
				if (st==null) st="Exception "+E.toString();
				
				if (st.startsWith("@")) {
					try {
						String s = recmd(false,null,st.substring(1),null);
						Write(s+"\r\n");
						Mid.StatError++;
						} catch(Exception I) {}
					close();
					
					if (Config.Debug) Config.EXC(E, "PO3Session"); else Log("POP3 Fatal Error "+st+"\n");
					} else {
					Config.EXC(E, "PO3Session");
					isDismissed=true;
					if (Config.Debug) E.printStackTrace();
					close();
					Mid.StatException++;
					}
				}
			}
		
		if (isConnected()) close();
		isDismissed=true;
		sok=null;
		in=null;
		br=null;
		O=null;
		EndTime=1;
		try { ParentServer.Garbage(); } catch(Exception E) { Config.EXC(E, Mid.Nick+".ParentGarbage"); }
	}
	
	SrvPop3Session(POP3Server pr,Socket soki) throws Exception {
		super();
		Config=pr.Config;
		Mid=pr.Identity;
		ParentServer= pr;
		sok=soki;
		in = new DataInputStream(sok.getInputStream());
		br = new BufferedReader(new InputStreamReader(in));
		O = sok.getOutputStream();
		EndTime = System.currentTimeMillis() + Config.MaxSMTPSessionInitTTL;
		start();
		}
	
	public void close() {
			LoginHash=0;
			try { sok.close(); } catch(Exception i) {}
			try { in.close(); } catch(Exception i) {}
			try { br.close(); } catch(Exception i) {}
			try { O.close(); } catch(Exception i) {}
		}
	
	public boolean isConnected() { 
			if (isDismissed) return false;
			if (sok==null) return false;
			return sok.isConnected() && !sok.isClosed(); 
			}
	
	public String ReadLn() throws Exception { return br.readLine(); }
	public void Write(String st) throws Exception { O.write(st.getBytes()); }
	
	
	public boolean isOld() { return System.currentTimeMillis()> EndTime; }
	
	public void End() {
		isDismissed=true;
		close();
		try {this.interrupt(); } catch(Exception I) {}
	}
	
	private void Reply(boolean state) throws Exception { Reply(state, null); }
	
	private void Reply(boolean state, String data) throws Exception {
		String s = state ? "+OK" : "-ERR";
		if (data!=null && data.length()>0) s+=" "+data;
		s=s.trim();
		s+="\r\n";
		O.write(s.getBytes());
	}
	private void ReplyA(boolean state,String Msg, String[] data) throws Exception {
		String s = state ? "+OK" : "-ERR";
		int cx = data.length;
		if (cx>0) s+=" "+Msg.trim();
		for (int ax=0;ax<cx;ax++) {
			if(data[ax].compareTo(".")==0) data[ax]=". ";
			s+="\r\n"+data[ax];
			}
		s=s.trim();
		s+="\r\n.\r\n";
		O.write(s.getBytes());
	}
		
	private int pIntPop(String st) { try { return Integer.parseInt(st)-1; } catch(Exception E) { return 0; }}
	private String toIntPop(int a) { return Integer.toString(a+1); }
			
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
				ho+=rcod+" "+cx+" "+msg+"\r\n";
				if (cx>0) for(int ax=0;ax<cx;ax++) ho+=lin[ax]+"\r\n";
				
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
		
		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server|Config.GLOG_Event, "POP3S "+Mid.Nick+  (Login!=null ? "/"+Login : ""), st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server|Config.GLOG_Event,"POP3S "+Mid.Nick+  (Login!=null ? "/"+Login : ""), st); 	}		
		protected void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
