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
import java.util.zip.CRC32;

public class Spam {

	private Config Config = null;
	private String BaseDir;

	private byte[] Sale;
	private long MaigcField=		0xFECAF000F6C7006EL;
	private long MagicCode=		0xFECA006F5AF05AFEL;
	private int MaxSpamEntryXUser=0;	
	private String NickSrv=null;
	
	private long MyHash(String st,long Sale) {
		CRC32 C = new CRC32();
		
		st=st.toLowerCase();
		st=st.trim();
		C.update(st.getBytes());
		long a = C.getValue();
		st = st.toUpperCase();
		C.update(st.getBytes());
		long b = C.getValue();
		C=null;
		a^=b<<32;
		a^=Sale;
		return a;
	}
	
	Spam(Config C,SrvIdentity S) {
		Config=C;
		NickSrv=S.Nick;
		BaseDir = (S.Maildir +"/log/").replace("//", "/");
		MaigcField ^=MyHash(S.Onion,MaigcField);
		try {
		Sale = Stdio.sha512a(new byte[][] { S.Sale,S.Subs[1] } ); //2 Cicli 1 + Pad
		} catch(Exception I) { Sale=S.Sale.clone(); C.EXC(I, "Spam()"); }
		
		MagicCode^=MaigcField&0x7FFFFFFFL;
		MaigcField^=MaigcField<<1;
		MagicCode^=(MaigcField>>32)&0x7FFFFFFFL;
		MagicCode^=MagicCode>>1;
		MagicCode^=MaigcField;
		MagicCode^=MagicCode<<1;
		MaxSpamEntryXUser= S.MaxSpamEntryXUser;		
		}
	
	public boolean exists(String local) throws Exception {
		String fs = GetFile(local);
		return new File(fs+".key").exists() && new File(fs+".lst").exists();
		}
	
	public String GetFile(String local) throws Exception {
		local=local+"@local";
		CRC32 C = new CRC32();
		C.update(Sale);
		C.update(local.toLowerCase().getBytes());
		long a = C.getValue();
		C.update(local.toUpperCase().getBytes());
		long b = C.getValue();
		a^=a<<1;
		b^=b<<1;
		String c = Long.toString(a^MagicCode,36)+"/"+Long.toString(b^MaigcField,36);
		c=c.replace('-', 'A');
		c=c.replace('/', '-');
		String s=BaseDir+c;
		return s;
	}
	
	public boolean isSpam(String local,String query)  {
		try {
			String fs = GetFile(local);
			if (!new File(fs+".key").exists()) return false;
			
			long bl =MyHash(query, MagicCode);
			long bg =MyHash("*@"+J.getDomain(query), MagicCode); 
			long H[] = Stdio.Lodsx(Stdio.file_get_bytes(fs+".key"), 8);
			int cx=H.length;
			for (int ax=0;ax<cx;ax++) if (H[ax]==bl || H[ax]==bg) return true;
			H=null;
		} catch(Exception E) {
			Config.EXC(E, "isSpam");
			return false;
		}
		return false;
	}
	
	public void UsrCreateList(String local) throws Exception {
				String fs = GetFile(local);
				Stdio.file_put_bytes(fs+".key",new byte[0]);
				String lst="SPAM\n";
				byte[] db = lst.getBytes();
				db = Stdio.AESEncMulP(Sale, db);
				Stdio.file_put_bytes(fs+".lst", db);
			}
	
	public void SetList(String local,String[] list) throws Exception {
		int cx = list.length;
		String fs = GetFile(local);
		long H[] = new long[cx];
		String st="SPAM\n";
		for (int ax=0;ax<cx;ax++) {
			String ma = list[ax].toLowerCase().trim();
			if (!isValid(ma)) continue; //Lascia un campo H a 0 non problematico.
			long bl =MyHash(ma, MagicCode);
			H[ax]=bl;
			st+=ma+"\n";
			}
		byte[] db = st.getBytes();
		
		st=null;
		db = Stdio.AESEncMulP(Sale, db);
		byte[] ke = Stdio.Stosx(H, 8);
		
		Stdio.file_put_bytes(fs+".key", ke);
		Stdio.file_put_bytes(fs+".lst",db);
		}

	public String[] GetList(String local) throws Exception { 
		String fs = GetFile(local);
		if ( !new File(fs+".key").exists() || !new File(fs+".lst").exists()) return new String[0];
		
		byte[] db = Stdio.file_get_bytes(fs+".lst");
		db = Stdio.AESDecMulP(Sale, db);
		String st = new String(db);
		
		if (!st.startsWith("SPAM\n")) {
			Config.GlobalLog(Config.GLOG_Spam, NickSrv, "InvalidSpamList for `"+J.UserLog(null,local)+"`");
			return new String[0];
			}
		String[] lst=st.split("\\n",2);
		if (lst.length==1) return new String[0];
		if (lst[1].length()==0) return new String[0];
		
		lst=lst[1].split("\\n+");
		return lst;
	}
	
	public String UsrProcList(String local,int num) throws Exception {
		String[] lst = GetList(local);
		if (lst.length==0) return "\nEMPTY SPAM LIST\n";
		int cx=lst.length;
		num--;
		if (num>-1 && num<cx) {
			String st="";
			for (int ax=0;ax<cx;ax++) if (ax!=num) st+=lst[ax]+"\n";
			st=st.trim();
			lst=st.split("\\n+");
			cx=lst.length;
			SetList(local,lst);
			}
		
		String q="Current SPAM list:\n";
		
		for (int ax=0;ax<cx;ax++) q+=Integer.toString(ax+1)+"\t = "+lst[ax]+"\n";
		return q;		
	}
	
	public String[] ProcList(String local,String[] spamu, String[] nospamu) throws Exception {
		String[] lst = GetList(local);
		String db="\n";
		int cx = lst.length;
		for (int ax=0;ax<cx;ax++) db+=lst[ax]+"\n";
		
		if (spamu!=null) {
			cx = spamu.length;
			for (int ax=0;ax<cx;ax++) {
				String s = spamu[ax].toLowerCase().trim();
				if (!db.contains("\n"+s+"\n")) db+=s+"\n";
				}
			}
		
		if (nospamu!=null) {
			cx = nospamu.length;
			for (int ax=0;ax<cx;ax++) {
				String s = nospamu[ax].toLowerCase().trim();
				s=s.replace("\n", "");
				db=db.replace("\n"+s+"\n", "\n");
				}
		}
		db=db.trim();
		lst=db.split("\\n+");
		SetList(local,lst);
		return lst;
	}
	
	public static boolean  isValid(String ad) {
		String[] tok = ad.split("@");
		if (tok.length!=2) return false;
		if (tok[0].compareTo("*")==0) return true;
		if (!tok[1].matches("[0-9a-z\\.\\-\\_]{2,60}\\.[a-z]{2,6}")) return false;
		if (!tok[1].matches("[0-9a-z\\.\\-\\_]{2,50}")) return false;
		return true;
	}
}
