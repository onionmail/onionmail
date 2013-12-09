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
import java.util.Arrays;
import java.util.zip.CRC32;

public class RemoteDerK {
	private String fileName=null;
	private int credits=3;
	private int maxcredit=3;
	public int used=0;
	private int status=0;
	private byte[] InternalData = null;
	private  boolean access=false;
	private byte[] Md5Passw = null;
	public String onion=null;
	private SrvIdentity Srv=null;
	public String Password=null;
	public byte[] LocalKey=null;
	private byte[] RawData = null;
	
	public static final int ST_Disabled = 0;
	public static final int ST_Enabled = 1;
	public static final int ST_NoCredit = 2;
	public static final int ST_TestMode = 3;
	public static final int ST_Sfiduciato = 5;
	
	public String getDesConf() throws Exception {
		CRC32 C = new CRC32();
		C.update(LocalKey);
		C.update(Md5Passw);
		long x = C.getValue() &0x7FFFFFFFFFL;
		x^=x<<1;
		x^=Stdio.Peek(0, Md5Passw);
		x^=x>>2;
		x^=0xff5a5a5a5a5aL;
		x^=x<<1;
		x&=0x7FFFFFFFFFL;
		return Long.toString(x,36);
	}
	
	public void setCredit(int c) throws Exception {
		if (!access) throw new PException("@550 Access Denied");
		credits=c;
		if (c>maxcredit) maxcredit=c;
		}
	
	public void setMaxCredit(int c) throws Exception {
		if (!access) throw new PException("@550 Access Denied");
		maxcredit=c;
		if (credits>maxcredit) credits=maxcredit; 
		}
	
	public int getCredit() { return credits; }
	public int getMaxCredit() { return maxcredit; }
	
	public void Restart() throws Exception {
		if (!access) throw new PException("@550 Access Denied");
		credits=maxcredit;
		Save();
		}
	
	public void Destroy() throws Exception {
			if (!access) throw new PException("@550 Access Denied");
			Md5Passw=new byte[32];
			Stdio.NewRnd(Md5Passw);
			LocalKey=new byte[64];
			Stdio.NewRnd(LocalKey);
			InternalData=new byte[32];
			Stdio.NewRnd(InternalData);
			credits=0;
			maxcredit=0;
			used=0;
			status=0;
			Save();
			J.Wipe(fileName,true);
			Password=null;
			Md5Passw=null;
			LocalKey=null;
			InternalData=null;
			access=false;
			System.gc();
			}
	
	RemoteDerK(SrvIdentity srv) {Srv=srv; }
	
	RemoteDerK(SrvIdentity srv,String Oni) throws Exception {
		Srv=srv;
		Oni=Oni.toLowerCase().trim();
		fileName = getFileName(srv, Oni);
		if (new File(fileName).exists()) throw new PException("@503 DERK_KEY Arleady exists");
		status=RemoteDerK.ST_Enabled;
		Password = J.GenPassword(16, 0);
		InternalData = new byte[16];
		Stdio.NewRnd(InternalData);
		LocalKey = new byte[64];
		Stdio.NewRnd(LocalKey);
		Md5Passw = Stdio.md5a(new byte[][] { InternalData,Password.getBytes() });
		access=true;
		onion=Oni;
		RawData=new byte[0];
		}
	
	public void Save() throws Exception {
		byte[][] X =  new byte[][] {
					Stdio.Stosxi(new int[] {credits,maxcredit,used,status }, 2),
					InternalData,
					Md5Passw,
					LocalKey,
					RawData}
					;
		
		byte[] raw = Stdio.MxAccuShifter(X, 0xFC4A,true);
		X=J.DerAesKey(Srv.Sale, onion);
		raw = Stdio.AES2Enc(X[0], X[1], raw);
		J.WipeRam(X);
		X=null;
		Stdio.file_put_bytes(fileName, raw);
		raw=null;
		System.gc();
		}
	
		public void setStatus(int st) throws Exception {
			if (!access) throw new PException("@550 Access Denied");
			status=st;
			}
	
		public int getStatus() { return status; }
		
		public boolean isAccess() { return access; }
		
		public boolean Logon(String pwl) throws Exception {
			byte[] raw = Stdio.md5a(new byte[][] { InternalData,pwl.getBytes() });
			access=Arrays.equals(raw,Md5Passw); 
			return access;
			}
		
		public byte[] Computa(byte[] in) throws Exception {
			if (credits==0) throw new PException("@550 No credit for this DERK");
			if (status!=ST_Enabled) throw new PException("@550 DERK Disabled, status `"+status+"`");
			byte[] a= J.Der2048(Srv.Sale, LocalKey);
			a = J.Der2048(in, a);
			credits--;
			used++;
			Save();
			return a;
		}
	
		public static RemoteDerK FastOpen(SrvIdentity srv,String Oni,String pwl) throws Exception {
			RemoteDerK DK = RemoteDerK.Load(srv, Oni);
			DK.Logon(pwl);
			return DK;
		}
		
		public static byte[] FastCompute(SrvIdentity srv,String Oni,byte[] in) throws Exception {
			RemoteDerK DK = RemoteDerK.Load(srv, Oni);
			byte[] b = DK.Computa(in);
			DK=null;
			return b;
		}
		
		public static RemoteDerK Load(SrvIdentity srv,String Oni) throws Exception {
			Oni=Oni.toLowerCase().trim();
			String fn = getFileName(srv,Oni);
			if (!new File(fn).exists()) return null;
			
			RemoteDerK DK = new RemoteDerK(srv);
			DK.fileName = fn;
			
			byte[] raw = Stdio.file_get_bytes(fn);
			DK.onion=Oni;
		
			byte[][] X=J.DerAesKey(srv.Sale, Oni);
			raw = Stdio.AES2Dec(X[0], X[1],raw);
			X = Stdio.MxDaccuShifter(raw, 0xFC4A);
			int[] dta = Stdio.Lodsxi(X[0], 2);
			DK.InternalData=X[1];
			DK.Md5Passw=X[2];
			DK.LocalKey=X[3];
			DK.RawData=X[4];
			DK.credits = dta[0];
			DK.maxcredit=dta[1];
			DK.used=dta[2];
			DK.status=dta[3];
			X=null;
			raw=null;
			return DK;
			}
	
	private static String getFileName(SrvIdentity srv, String onion) {
			onion=onion.toLowerCase().trim();
			CRC32 C = new CRC32();
			C.update(srv.Sale);
			C.update(onion.getBytes());
			String fn = Long.toString(C.getValue(),36);
			C = new CRC32();
			C.update(srv.Sale);
			onion=onion.toUpperCase();
			C.update(onion.getBytes());
			fn +="-"+ Long.toString(C.getValue(),36);
			int x = onion.hashCode();
			x^=x>>1;
			x^=Stdio.Peek(0, srv.Sale);
			x^=x<<1;
			x&=0x7FFFFFFF;
			fn+="-"+Long.toString(x,36);
			return srv.Maildir+"/keys/"+fn;
		}
	
	public static String FastCreateNew(SrvIdentity srv,String Oni,int maxcrt) throws Exception {
		RemoteDerK DK = new RemoteDerK( srv, Oni);
		DK.maxcredit=maxcrt;
		DK.credits=maxcrt;
		DK.status=RemoteDerK.ST_Enabled;
		DK.Save();
		return DK.Password;
	}
	
	public static boolean FastAdmSfiducia(SrvIdentity srv,String oni) throws Exception {
		RemoteDerK DK=RemoteDerK.Load(srv,oni);
		if (DK==null) {
			return false;
			} else {
			if (DK.status==RemoteDerK.ST_Sfiduciato) return true;
			DK.status=RemoteDerK.ST_Sfiduciato;
			DK.RawData = new byte[2];
			Stdio.Poke(0, DK.status, DK.RawData);
			DK.Save();
			return true;
			}
	}
	
	public static boolean FastAdmFiducia(SrvIdentity srv,String oni) throws Exception {
		RemoteDerK DK=RemoteDerK.Load(srv,oni);
		if (DK==null) {
			return false;
			} else {
			if (DK.status!=RemoteDerK.ST_Sfiduciato) return true;
			DK.status=Stdio.Peek(0, DK.RawData);
			DK.RawData = new byte[0];
			DK.Save();
			return true;
			}
	}
}
