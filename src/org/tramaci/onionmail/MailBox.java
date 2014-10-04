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

import java.io.File;
import java.io.RandomAccessFile;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

public class MailBox {
	
	public PublicKey KP=null;
	private PrivateKey KS=null;
	public String LocalPart=null;
	public String MailDir=null;

	private byte[] Sale = null;

	public DBCrypt Index=null;
	
	private int[] List = null;
	
	private String UserIndex=null;

	public Config Config=null;
	public  Spam Spam;
	public SrvIdentity SID = null; 
	public HashMap <String,String> UserProp = new HashMap <String,String>();
	
	MailBox(SrvIdentity SE,String lp,String uindexf, PublicKey p, boolean create) throws Exception { 
		SID=SE;
		Config=SE.Config;
		MailDir = SE.Maildir+"/inbox";
		LocalPart = lp;
		UserIndex =uindexf;
		KP=p;
		Sale=SE.Sale;
		
		if (create) 
				Index = DBCrypt.Create(UserIndex,Sale, p,SE.MaxMsgXuser,256); 
				else	
				Index = DBCrypt.OpenW(UserIndex,Sale, p); 
		
		Spam = SE.Spam;
		if (Spam!=null && !Spam.exists(lp)) try { Spam.UsrCreateList(lp); } catch(Exception E) {Main.EXC(E,"Spam.Create"); }
		
	}
	
	MailBox(SrvIdentity SE, String lp,String uindexf, PublicKey p,PrivateKey h) throws Exception {
		SID=SE;
		Config=SE.Config;
		MailDir =SE.Maildir+"/inbox";
		LocalPart = lp;
		UserIndex =uindexf;
		KP=p;
		KS=h;
		Sale=SE.Sale;
		Index = DBCrypt.OpenRW(UserIndex, Sale, new KeyPair(p,h));
		UpdateIndex();
		try {
			Spam = SE.Spam;
			if (!Spam.exists(lp)) Spam.UsrCreateList(lp);
			} catch(Exception E) {Main.EXC(E,"Spam.Create"); }

		}
		
	public int Length() { return List.length; }
	
	public void UpdateIndex() { List = Index.GetIndex(); }
	
	public String ProcSpam(int delf) throws Exception { return Spam.UsrProcList( LocalPart, delf); }
	
	public void SpamAdd(String spam) throws Exception { Spam.ProcList(LocalPart, new String[] { spam }, null); }
	public void SpamClear() throws Exception { Spam.UsrCreateList(LocalPart); }
	public boolean SpamLookup(String query) throws Exception { return Spam.isSpam(LocalPart, query); }
	
	public class Message extends MailBoxFile {
		public long Time = 0;
		public long Size = 0;
		public String MailFrom = null;
		public String RcptTo = null;
		public String Subject = null;
		public byte[] ID=new byte[16];
		public int DbId = -1;
		public int Mode=0;
		public String FileName=null;
		public boolean deleted=false;
		
		protected byte[] Pack() throws Exception {
	
			if (MailFrom.length()>50) MailFrom=MailFrom.substring(0,47)+"...";
			if (RcptTo.length()>50) RcptTo=RcptTo.substring(0,47)+"...";
			if (Subject.length()>90) Subject=Subject.substring(0,87)+"...";
						
			return Stdio.MXImplode(new byte[][] {
					Stdio.Stosx(new long[] { Time, Size },4) ,
					MailFrom.getBytes(), 
					RcptTo.getBytes(),
					Subject.getBytes() ,	
					ID}
					, Const.MX_Message)
					;
			}	 
		
		public void SetHeaders(HashMap<String,String> H) throws Exception {
			if (H.containsKey("from")) MailFrom = H.get("from"); else MailFrom="";
			if (H.containsKey("to")) RcptTo = H.get("to"); else RcptTo="";
			if (H.containsKey("subject")) Subject = H.get("subject"); else Subject="";
			String S = J.CreateHeaders(H)+"\r\n"; 
			WriteLn(S);
			Size = S.length();
			}
		
		public void WriteA(String[] st) throws Exception {
			int cx = st.length;
			for (int ax=0;ax<cx;ax++) WriteLn(st[ax].trim());
		}
		
		public void WriteLn(String St) throws Exception {
			if (!St.contains("\n")) St+="\r\n";
			Size+=St.length();
			super.WriteLn(St);
		}
			
		public void End() throws Exception {
			
			byte[]  bd = Pack();
			int fr = Index.GetFree();
			if (fr==-1) throw new Exception("@500 Mailbox full (id-1)");
			Index.BlockWrite(fr, bd);
			Index.Update();
			DbId = fr;
			Close();
			}
		}
			
	private String ID2Name(byte[] i) {
		long[] H = Stdio.Lodsx(i, 8);
		int sign=0;
		int cx = H.length;
		String q="";
		for (int ax=0;ax<cx;ax++) {
				String a = Long.toString(H[ax] &0x7FFFFFFFFFFFFFFFL,36);
				if ((H[ax]&0x8000000000000000L)!=0) sign|=1;
				sign<<=1;
				q+=a+ " ";
				}
		
		q+=Integer.toString(sign,36);
		
		return q.trim().replace(' ','-')+".esf";
	}
	
	public Message MsgCreate() throws Exception {
		int i = Index.GetFree();
		if (i ==-1) throw new Exception("@500 Mailbox full!");
		Message M = new Message();
		String t0 = Long.toString(System.currentTimeMillis(),36)+"-"+Long.toString(i,36)+"-"+LocalPart;
		M.ID = Stdio.md5(t0.getBytes());
		M.Time = System.currentTimeMillis()/1000;
		M.OpenW(MailDir+"/"+ID2Name(M.ID), KP,SID);
		M.Mode=1;
		return M;
	}
	
	public Message MsgInfo(int id) throws Exception {
		int ix = List[id];
		Message M = new Message();
		byte[][] H =new byte[1][];
		try { H[0] =Index.BlockRead(ix); } catch(Exception E) {
			Config.EXC(E, "BadBlock in `"+M.FileName+"` id "+M.DbId+" mb `"+LocalPart+"`");
			M.DbId=ix;
			M.deleted=true;
			M.Subject="Bad Block "+M.DbId;
			M.Time = 0;
			M.RcptTo="YOU";
			M.MailFrom="SERVER FILESYSTEM";
			M.FileName="X";
			return M;
			}
		if (H[0]==null) return null;
		M.DbId=ix;
		H = Stdio.MXExplode(H[0], Const.MX_Message);
		long h[] = Stdio.Lodsx(H[0], 4);
		M.Time = h[0];
		M.Size = h[1];
		M.MailFrom = new String(H[1]);
		M.RcptTo = new String(H[2]);
		M.Subject = new String(H[3]);
		M.ID = H[4];
		M.FileName =MailDir+"/"+ID2Name(M.ID); 
		M.deleted = new File(M.FileName).exists() ? false: true;
		
		return M;
	}
	
	public void RemoveFromIndex(int id) throws Exception {
		int ix = List[id];
		Index.BlockDel(ix);
		Index.Update();
	}
	
	public void RemoveMsg(int id) throws Exception {
		int ix = List[id];
		try {
			
		Message M = new Message();
		byte[][] H =new byte[1][];
		H[0] =Index.BlockRead(ix);
		M.DbId=ix;
		H = Stdio.MXExplode(H[0], Const.MX_Message);
		long h[] = Stdio.Lodsx(H[0], 4);
		M.Time = h[0];
		M.Size = h[1];
		M.MailFrom = new String(H[1]);
		M.RcptTo = new String(H[2]);
		M.Subject = new String(H[3]);
		M.ID = H[4];
		M.FileName =MailDir+"/"+ID2Name(M.ID); 
		Index.BlockDel(ix);
		
		if (new File(M.FileName).exists()) {
			byte[] b = new byte[1024];
			RandomAccessFile F = new RandomAccessFile(M.FileName,"rw");
			F.seek(0);
			F.write(b);
			try { F.setLength(0); } catch(Exception I) {}
			F.close();
			File Fo =new  File(M.FileName);
			Fo.renameTo(new File(J.RandomString(8)+".old"));
			if (!Fo.delete()) Log("Can't delete `"+Fo.toString()+"`\n");
		}
		
		} catch(Exception E) { Index.BlockDel(ix); }
	}
	
	public Message MsgOpen(int id) throws Exception {
		int ix = List[id];
		Message M = new Message();
		byte[][] H =new byte[1][];
		try  { H[0] =Index.BlockRead(ix); } catch(Exception E) {
			Config.EXC(E, "MsgOpen `"+M.FileName+"` id "+M.DbId+ " mb `"+LocalPart+"`");
			M.deleted=true;
			M.MailFrom="???";
			M.RcptTo="???";
			M.Subject="BAD BLOCK TYPE 1"+M.FileName;
			return M;
			}
		
		if (H[0]==null) {
			M.deleted=true;
			M.MailFrom="???";
			M.RcptTo="???";
			M.Subject="BAD BLOCK TYPE 2"+M.FileName;
			return M;
			}
		
		M.DbId=ix;
		H = Stdio.MXExplode(H[0], Const.MX_Message);
		long h[] = Stdio.Lodsx(H[0], 4);
		M.Time = h[0];
		M.Size = h[1];
		M.MailFrom = new String(H[1]);
		M.RcptTo = new String(H[2]);
		M.Subject = new String(H[3]);
		M.ID = H[4];
		M.FileName =MailDir+"/"+ID2Name(M.ID); 
		M.deleted = new File(M.FileName).exists() ? false: true;
		
		if (!M.deleted) {
			M.OpenR(M.FileName, KS,SID);
			M.Mode=0;
			}
		return M;
	}
	
	public void MsgDestroy(int id, boolean fast) throws Exception {
		Message M=null;
		try {
			M = MsgOpen(id);
			MsgDestroy(M,fast);
			} catch(Exception E) {
				if (M==null || M.FileName==null) throw E;
				File RC = new File(M.FileName);
				if (!RC.exists()) return;
				if (!RC.delete()) throw new Exception("@Cant remove message, CAUSE= "+E.toString());
			}
	}
	
	public void MsgDestroy(Message M,boolean fast) throws Exception {
		int id = M.DbId;
		Exception rr=null;
		try { M.Destroy(fast); } catch(Exception E) { rr=E; }
		if (id!=-1) {
				Index.BlockDel(id);
				Index.Update();
				}
		if (rr!=null) throw rr;
		}	 
	
	public void Close() throws Exception {
		KP=null;
		KS=null;
		MailDir=null;
		Sale=null;
		LocalPart=null;
		if (Index!=null) try { Index.Close(); } catch(Exception II) {}
		Index=null;
		UserIndex=null;
		List=null;
		}
	
	public void Log(String st) { Config.GlobalLog(Config.GLOG_Server+Config.GLOG_Event, "MailBox `"+LocalPart+"`", st); 	}

protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
