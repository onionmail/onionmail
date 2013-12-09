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

import org.tramaci.onionmail.DBCrypt.DBCryptIterator;


public class Spam {

	private Config Config = null;
	private String BaseDir;

	private byte[] Sale;
	private long MaigcField=		0xFECAF000F6C7006EL;
	private long MagicCode=		0xFECA006F5AF05AFEL;
	private int MaxSpamEntryXUser=0;	
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
		BaseDir = (S.Maildir +"/log/").replace("//", "/");
		MaigcField ^=MyHash(S.Onion,MaigcField);
		Sale = Stdio.md5a( new byte[][] { S.Sale , S.Onion.getBytes() });
		
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
		return new File(fs+".key").exists() && new File(fs+".rsa").exists();
		}
	
	private String GetFile(String local) throws Exception {
		local=local+"@local";
		byte[] b = Stdio.md5a(new byte[][] { Sale , local.getBytes()  });
		String s=BaseDir+Stdio.Dump(b).toUpperCase();
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
				DBCrypt db = DBCrypt.Create(fs+".rsa", Sale, MaxSpamEntryXUser, 64);
				db.Close();
		}
	
	public void UsrAddList(String local,String spam) throws Exception {
		long bl = MyHash(spam, MagicCode);
		long bg =MyHash("*@"+J.getDomain(spam), MagicCode);
		String fs = GetFile(local);
		long H[] = Stdio.Lodsx( Stdio.file_get_bytes(fs+".key"), 8);
		int cx = H.length;
		for (int ax=0;ax<cx;ax++) if (H[ax]==bl || H[ax]==bg) return;	
		
		long I[] = new long[ cx+1];
		System.arraycopy(H, 0, I, 0, cx);
		I[cx] = bl;
		Stdio.file_put_bytes(fs+".key", Stdio.Stosx(I, 8));
		DBCrypt Db = DBCrypt.Open(fs+".rsa", Sale);
		int fr = Db.GetFree();
		spam+="\0";
		if (fr!=-1) Db.BlockWrite(fr,spam.getBytes());
		Db.Close();
	}
	
	public String UsrProcList(String local,int del) throws Exception {
		String fs = GetFile(local);
		String ls = "";
		String out="";
		del--;
		
		int trued=-1;
		DBCrypt db = DBCrypt.Open(fs+".rsa", Sale);
		DBCryptIterator I = db.GetIterator();
		int cx = I.Length();
		boolean dele=false;
		for (int ax=0;ax<cx;ax++) {
			int cur=I.CurrentIndex();
			byte[] dt = I.Next();
			if (dt==null) break;
			String re = new String(dt);
			int i = re.indexOf('\0');
			if (i!=-1) re=re.substring(0,i);
			re=re.trim();
			
			if (ax==del) {
					dele=true;
					out+=Integer.toString(ax+1)+" DELETED <"+re+">\n";
					trued=cur;
					} else {
					ls+=re+"\n";
					out+=Integer.toString(ax+1)+" = <"+re+">\n";
					}
			}
		
		if (dele) {
				out+="\n1 Entry deleted\n";
				ls=ls.trim();
				String[] Ls = ls.split("\\n+");
				int dx = Ls.length;
				if (ls.length()==0) dx=0;
				db.BlockDel(trued);
				db.Update();
				long[] H = new long[dx];
				for (int ax=0;ax<dx;ax++) {
					H[ax] = MyHash(Ls[ax], MagicCode);
					}
				db.Close();
				Stdio.file_put_bytes(fs+".key", Stdio.Stosx(H, 4));
				} else {
				db.Close();				
				}
		return out;		
	}
	
	
	
}
