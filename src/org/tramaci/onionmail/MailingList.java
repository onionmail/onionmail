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
import java.io.File;
import java.util.HashMap;

import org.tramaci.onionmail.DBCrypt.DBCryptIterator;


public class MailingList {
		public Config Config=null;
		public SrvIdentity Mid=null;
		private String BasicFile=null;

		private int MaxUsr=0;
		private MailBoxFile Message=null;
				
		public String Title="";
		public boolean isOpen = true;
		public boolean isGPG = false;
		public String LocalPart=null;
				
		public static final int TYP_Del = 0;
		public static final int TYP_Usr = 1;
		public static final int TYP_Admin = 2;
		
		public DBCrypt List = null; 
		public DBCryptIterator Iter = null;
		
		private byte[] Salt = null;
				
		public int Length() {
			
			
			if (List==null) {
				Config.GlobalLog(Config.GLOG_Event, Mid.Nick, "ListNull!");
				return 0; 
				}
			if (Iter==null) Iter=List.GetIterator();
			return Iter.Length();
		}
		
		public void Close() throws Exception { 
			if (List!=null) List.Close();
			if (Message!=null) Message.Destroy(true);
			}
		
		public class MLUserInfo {
				int Type	=	0;
				int Errs = 0;
				String Address = null;
				byte[] Pass = null;
				long Pox = -1;
			}
		
		public MLUserInfo NewInfo(int Type,String Addr,String Pass) {
			MLUserInfo U = new MLUserInfo();
			U.Type=Type;
			U.Address=Addr.toLowerCase();
			U.Pass = Stdio.md5(Pass.getBytes());
			return U;
		}
		
		private byte[] PackUser(MLUserInfo U) throws Exception {
			byte[] rec = new byte[96];
			Stdio.NewRnd(rec);
			Stdio.Poke(0, 0x900e, rec);
			rec[2] = (byte)(U.Type&255);
			rec[3] = (byte)(U.Address.length()&255);
			Stdio.Poke(4,U.Errs, rec);
			if (U.Pass==null) {
					U.Pass=new byte[16];
					Stdio.NewRnd(U.Pass);
					for (int ax=0;ax<8;ax++) U.Pass[ax]=0;
					}
			System.arraycopy(U.Pass, 0, rec, 6, 16);
			byte[] a = U.Address.getBytes();
			System.arraycopy(a, 0, rec, 22, a.length);
			return rec;
			}
		
		MLUserInfo UnPackUser(byte[] i) throws Exception {
			MLUserInfo U = new MLUserInfo();
			if (Stdio.Peek(0,i)!=0x900e) throw new Exception("Invalid key");
			U.Type = 255&i[2];
			int le = 255&i[3];
			U.Errs = Stdio.Peek(4, i);
			U.Pass = new byte[16];
			System.arraycopy(i, 6, U.Pass, 0, 16);
			byte[] c = new byte[le];
			System.arraycopy(i, 22, c, 0, le);
			U.Address=new String(c);
			return U;
			}

		public MLUserInfo GetUsr(String Addr) throws Exception {
			Addr=Addr.toLowerCase();
			DBCryptIterator i = List.GetIterator();
			int cx = i.Length();
			for (int ax=0;ax<cx;ax++) {
				byte[] b = i.Next();
				if (b==null) break;
				MLUserInfo U = UnPackUser(b);
				if (U.Address.compareToIgnoreCase(Addr)==0) return U;
				}
			return null;
		}
		
		public void DelUsr(String Addr) throws Exception {
			Addr=Addr.toLowerCase();
			DBCryptIterator i = List.GetIterator();
			int cx = i.Length();
			for (int ax=0;ax<cx;ax++) {
				int idp = i.CurrentIndex();
				byte[] b = i.Next();
				if (b==null) break;
				MLUserInfo U = UnPackUser(b);
				if (U.Address.compareToIgnoreCase(Addr)==0) {
					List.BlockDel(idp);
					List.Update();
					Iter=List.GetIterator();
					return;
					}
				}
		}
		
		public void SetUsr(MLUserInfo O) throws Exception {
			String Addr=O.Address.toLowerCase();
			DBCryptIterator i = List.GetIterator();
			int cx = i.Length();
			for (int ax=0;ax<cx;ax++) {
				int idp = i.CurrentIndex();
				byte[] b = i.Next();
				if (b==null) break;
				MLUserInfo U = UnPackUser(b);
				if (U.Address.compareToIgnoreCase(Addr)==0) {
					byte[] by = PackUser(O);
					List.BlockWrite(idp, by);
					List.Update();
					Iter=List.GetIterator();
					return;
					}
				}
			List.AddBlock(PackUser(O));
			Iter= List.GetIterator();
		}
		
		public MLUserInfo Read() throws Exception {
			if (Iter==null) Iter=List.GetIterator();
			byte[] by = Iter.Next();
			if (by==null) return null;
			return UnPackUser(by);
		}
				
		private String GetBasePath(SrvIdentity s,String lp) throws Exception {
			return s.Maildir+"/inbox/"+Stdio.Dump(Stdio.md5a(new byte[][] { s.Sale , lp.getBytes() ,"@list".getBytes() }))+".ml";
		}
		
		public String GetRulezFile() { return BasicFile+".rul"; }
		
		public boolean Exists()  throws Exception { return new File(GetBasePath(this.Mid,this.LocalPart)+".hdr").exists(); }
		
		MailingList(SrvIdentity s) {
			Mid=s;
			Config=s.Config;
			}
			
		public void Create(int mx) throws Exception {
			MaxUsr=mx;
			BasicFile = GetBasePath(Mid,LocalPart);
			Salt = new byte[64];
			Stdio.NewRnd(Salt);
			
			List = DBCrypt.Create(BasicFile, Salt, MaxUsr, 96);
			List.Close();
			
			Save();
			Load();
			
		}
			
		public void Load() throws Exception {
			BasicFile = GetBasePath(Mid,LocalPart);
			
			byte[] a = Stdio.md5(Mid.Sale);
			byte[] b = Stdio.md5a(new byte[][] { a, Mid.Sale });
			a = Stdio.md5a(new byte[][] { a, Mid.Sale,b });
			
			byte[] inf = Stdio.file_get_bytes(BasicFile+".hdr");
			inf = Stdio.AESDec(Stdio.GetAESKey(a), b, inf);
			a=null;
			b=null;
			System.gc();
			byte[][] F = Stdio.MxDaccuShifter(inf, 0x7c81);
			Title = new String(F[0]);
			Salt=F[1];
			LocalPart=new String(F[2]);
			long[] H = Stdio.Lodsx(F[3], 2);
			MaxUsr=(int) H[1];
			isOpen = (H[2]&1)!=0;
			isGPG = (H[2]&2)!=0;
			List = DBCrypt.Open(BasicFile, Salt);
			Iter = List.GetIterator();
			
		}
			
		public void Rewind() throws Exception { Iter=List.GetIterator(); }
		
		public void Save() throws Exception {
		
			byte[] inf = Stdio.MxAccuShifter(new byte[][] {
				Title.getBytes(),
				Salt,
				LocalPart.getBytes(),
				Stdio.Stosx(new long[] {1, MaxUsr, (isOpen ? 1:0) | (isGPG ? 2:0) },2)
				}, 0x7c81,true) ;
			
			byte[] a = Stdio.md5(Mid.Sale);
			byte[] b = Stdio.md5a(new byte[][] { a, Mid.Sale });
			a = Stdio.md5a(new byte[][] { a, Mid.Sale,b });
			
			inf = Stdio.AESEnc(Stdio.GetAESKey(a), b, inf);
			Stdio.file_put_bytes(BasicFile+".hdr", inf);
			a=null;
			b=null;
			System.gc();
			List.Update();
			
		}	
		
		public static MailingList Open(SrvIdentity s,String local) throws Exception {
			MailingList M = new MailingList(s);
			M.Mid = s;
			M.LocalPart=local;
			M.Load();
			return M;
		}
	
		
	public void ReceiveMessage(BufferedReader M) throws Exception {
		long t0 = Mid.Time();
		t0=t0^t0>>1;
		
		String Tmp = BasicFile+"."+Long.toString(t0,36)+".tmp";
				
		long MessageBytes=0;
		MailBoxFile TM = new MailBoxFile();
		TM.OpenTMP(Tmp);
		while(true) {
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
	}
	
	public ListThread SendMessage(String from,HashMap <String,String> H) throws Exception {
		if (Message==null) throw new Exception("No message");
		ListThread TL = new ListThread(from,H,Message);
		return TL;
	}
		
	public boolean Destroy() throws Exception {
			List.Close();
			boolean bit= true;
			for (String ext : new String[] { ".hdr" , ".dbf" , ".idx" , ".rul" }) {
				String fi = BasicFile+ext;
				if (new File(fi).exists()) try { 
						J.Wipe(fi, Config.MailWipeFast); 
							} catch(Exception E) { 
								if (Config.Debug) E.printStackTrace();
						Config.EXC(E, "MailingList.Destroy `"+LocalPart+"` ("+fi+")"); 
						bit=false; 
						}
			}
			return bit;
		}
			
	public class ListThread extends Thread {
		private String MailFrom=null;
		private HashMap <String,String> Head=null;
		private HashMap <String,String> HeadI=null;
		private MailBoxFile MS=null;
		public boolean running=false;
		public long Started=0;
		
		ListThread(String from,HashMap <String,String> H,MailBoxFile M)	throws Exception {
			super();
			MS=M;
			Head=H;
			MailFrom=from;
			Started=System.currentTimeMillis();
			start();
		}
		
		public void run() {
			running=true;
			try {
				BeginList();
				
			} catch(Exception E) {
					Main.EXC(E, "EXC_GARB"); 
					try { MS.Destroy(true); } catch(Exception I) { Config.EXC(I, "EXC_GARB"); }
		
			}
			running=false;
		}
		
		public void End() {
			running=false;
			try { if (MS!=null) MS.Destroy(true); } catch(Exception I) { Config.EXC(I, "EXC_GARB"); }
			try { this.interrupt(); } catch(Exception E) {}
	
		}
		
			private void BeginList() throws Exception {
						Head.put("from", MailFrom);
						Head.put("error-to","<>");
						String lst= LocalPart+"@"+Mid.Onion;
						Head.put("reply-to",lst);
						Head.put("x-beenthere","list");
						Head.put("list-id",lst);
						Head.put("list-unsubscribe","<mailto:server@"+Mid.Onion+"?subject=LIST%3A%20"+lst+"%20UNSUBSCRIBE>");
						Head.put("list-subscribe","<mailto:server@"+Mid.Onion+"?subject=LIST%3A%20"+lst+"%20SUBSCRIBE>");
						Head.put("list-help","<mailto:server@"+Mid.Onion+"?subject=LIST%3A%20"+lst+"%20RULEZ>");
						Head.put("list-post","<"+lst+">");
						Head.put("message-id", J.RandomString(16)+"@"+Mid.Onion);
						Head.put("X-Mailer", "OnionMail MailingList "+Main.getVersion());
						Head.put("to", lst);
						
						if (Title.length()>0) {
							String St0 = Head.get("subject");
							St0 = St0.replace("["+Title+"]", "");
							St0 = "["+Title+"] "+St0.trim();
							Head.put("subject", St0);
							}
						
						HeadI=Head;
						
						String qfdn=null;
						if (Mid.EnterRoute) {
							qfdn=Mid.ExitRouteDomain;
							} else {
							HashMap <String,String> Conf = Mid.UsrGetConfig(J.getLocalPart(lst));
							String dom = null;
							if (Conf!=null && Conf.containsKey("exitdomain")) dom=Conf.get("exitdomain");
							Conf=null;
							ExitRouteList ER = Mid.GetExitList();
							if (dom==null) qfdn=ER.GetDomain(null); else qfdn=dom;
							if (qfdn==null) Config.GlobalLog(Config.GLOG_Event, Mid.Onion, "MailingList CFG QFDN=null");
							}
						
						HeadI = new HashMap <String,String>();
						for (String K:Head.keySet()) HeadI.put(K,Head.get(K));
						
						if (qfdn!=null) {
								HeadI.put("from", J.MailOnion2Inet(Config, MailFrom, qfdn));
								String ilst = J.MailOnion2Inet(Config, lst, qfdn);
								String srvd = J.MailOnion2Inet(Config, "server@"+Mid.Onion, qfdn);
								HeadI.put("to", ilst);
								HeadI.put("reply-to", ilst);
								HeadI.put("list-id",ilst);
								HeadI.put("x-mat",lst);
								HeadI.put("message-id", J.RandomString(16)+"@"+qfdn);
								HeadI.put("list-unsubscribe","<mailto:"+srvd+"?subject=LIST%3A%20"+lst+"%20UNSUBSCRIBE>");
								HeadI.put("list-subscribe","<mailto:"+srvd+"?subject=LIST%3A%20"+lst+"%20SUBSCRIBE>");
								HeadI.put("list-help","<mailto:"+srvd+"?subject=LIST%3A%20"+lst+"%20RULEZ>");
								
							} else Config.GlobalLog(Config.GLOG_Event, Mid.Onion, "MailingList CFG QFDN=null");
									
						Iter = List.GetIterator();
						int ecx= Iter.Length();						
						for (int eax=0;eax<ecx;eax++) {
							byte[] by = Iter.Next();
							if (by==null) break;
							MLUserInfo U = UnPackUser(by);
							if (U==null) break;
							if (U.Type==0) continue;
							MS.Rewind();
										
							try {
								String Srv = J.getDomain(U.Address);
								
								if (Srv.compareTo(Mid.Onion)==0) {
										Head.put("envelope-to", U.Address);
										Head.put("Date", Mid.TimeString());
										Mid.SendLocalMessage(J.getLocalPart(U.Address), Head,MS);
										} else {
										HashMap <String,String> HO;
										if (U.Address.endsWith(".onion")) {
												HO =Head;
												HO.put("envelope-to", U.Address);
												} else {
												HO=HeadI;
												HO.put("envelope-to",J.MailOnion2Inet(Config, U.Address, qfdn));
												}
										HO.put("Date", Mid.TimeString());
										Mid.SendRemoteSession(U.Address, lst, HO, MS);	
										}
								
								} catch(Exception E) { 
										Main.EXC(E, "ML "+lst+" U "+U.Address+"\n");
									}
						}
						
			MS.Destroy(true);
		
			}
	
	}

protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify	
}
