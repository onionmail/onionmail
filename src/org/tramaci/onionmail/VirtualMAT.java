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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.zip.CRC32;

public class VirtualMAT {

	private SrvIdentity MY = null;

	public static final long ST_Mask  	     		= 0x7FFFFFFFFFFFFFFFL;
	
	VirtualMAT(SrvIdentity s) { MY=s; } 
	
	private long MkHash(String s0) {
		s0=s0.toLowerCase().trim();
		CRC32 C = new CRC32();
		C.update(MY.Subs[4]);
		C.update(s0.getBytes());
		long r0 = C.getValue();
		r0^=r0<<1;
		r0=r0<<32;
		C = new CRC32();
		C.update(MY.Subs[3]);
		C.update(s0.toUpperCase().getBytes());
		r0^=C.getValue();
		r0&=VirtualMAT.ST_Mask;
		return r0;
		}
	
	////////////////////// Verifica VMAT TO ////////////////////////////////////////
	
	public boolean recipientCheckRVMAT(String localpart, String mail) throws Exception { // Controlla VMAT sul server locale TORM VMAT TO
		long a = MkHash(localpart);
		String fn = MY.Maildir+"/net/x"+Long.toString(a,36)+".mat";
		if (!new File(fn).exists()) return false;
		byte[] b = Stdio.file_get_bytes(fn);
		long[] arr = Stdio.Lodsx(b, 8);
		b=null;
		int cx = arr.length;
		long t = MkHash(mail) ^ a;
		for (int ax=0;ax<cx;ax++) if (arr[ax]==t) {
			arr=null;
			return true;
			}
		return false;
		}
	
	public void recipientDeleteRVMAT(String localpart, String mail) throws Exception { // Elimina VMAT sul server locale TORM VMAT TO
		long a = MkHash(localpart);
		String fn = MY.Maildir+"/net/x"+Long.toString(a,36)+".mat";
		long t = MkHash(mail) ^ a;
		
		if (!new File(fn).exists()) return ;
		byte[] b = Stdio.file_get_bytes(fn);
		long[] arr = Stdio.Lodsx(b, 8);
		b=null;
		int cx = arr.length;
		for (int ax=0;ax<cx;ax++) {
			if (arr[ax]==t) {
				long[] n = new long[cx-1];
				System.arraycopy(arr, 0, n, 0, ax);
				if (ax!=cx-1) System.arraycopy(arr, ax+1, n, ax,cx-ax-1);
				arr=null;
				b = Stdio.Stosx(n, 8);
				n=null;
				Stdio.file_put_bytes(fn, b);
				b=null;
				}
			}
		}
	
	
	public void recipientSetRVMAT(String localpart,String mail) throws Exception { //Aggiunge VAT sul server locale TORM VMAT TO
		byte[] b;
		long[] arr;
		long[] n;
		
		long a = MkHash(localpart);
		String fn = MY.Maildir+"/net/x"+Long.toString(a,36)+".mat";
		long t = MkHash(mail) ^ a;
		boolean exi = new File(fn).exists();
		
		if (exi) {
			b= Stdio.file_get_bytes(fn);
			arr= Stdio.Lodsx(b, 8);
			b=null;
			int cx = arr.length;
			for (int ax=0;ax<cx;ax++) if (arr[ax]==t) return;
			n= new long[cx+1];
			System.arraycopy(arr, 0, n, 0, cx);
			arr=null;
			n[cx]=t;
			} else {
			n = new long[1];
			n[0]=t;
			}
		
		b = Stdio.Stosx(n, 8);
		n=null;
		Stdio.file_put_bytes(fn, b);
		}
	
	//////////////////////
	
	private String DbFile(String nome) throws Exception {
		CRC32 C = new CRC32();
		C.update(MY.Sale);
		C.update(nome.toLowerCase().getBytes());
		long t0 = C.getValue();
		C.update(MY.Subs[1]);
		C.update(nome.toUpperCase().getBytes());
		long t1 = C.getValue();
		C=null;
		String fn = Long.toHexString(t0 & 0x7FFFFFFFFL)+"-"+Long.toHexString(t1 & 0x7FFFFFFFFL)+".idx";
		return MY.Maildir+"/keys/"+fn;
		}	
	
	private String[] DbNetFile(String addr) throws Exception {
		addr=addr.toLowerCase().trim();
		CRC32 C = new CRC32();
		C.update(MY.Sale);
		C.update(addr.getBytes());
		long a = C.getValue();
		C.update(MY.Subs[2]);
		C.update(addr.toUpperCase().getBytes());
		long b = C.getValue();
		long c = 255&((a>>28) ^ ((b>>28)<<4));
		a&=0x1FFFFFFFL;
		b&=0x1FFFFFFFL;
		return new String[] { MY.Maildir+"/net/mat-"+Long.toString(c,36) , Long.toString(a,36)+Long.toString(b,36) } ;
		}
	
	/////////////////////////////// RVMAT Per l'invio ///////////////////////////////
	
	public void SenderRVMATSave(VirtualRVMATEntry M) throws Exception {	//Salva RVMAT 
		String[] fp = DbNetFile(M.mail);
						
		File F = new File(fp[0]);
		if (!F.exists()) F.mkdir();
		F=null;
		String fn = fp[0]+"/"+fp[1];
		byte[] b = PackVirtualRVMATEntry(M);
		
		byte[] k = Stdio.sha256a(new byte[][] { M.mail.getBytes() , MY.Sale} );
		byte[] i = Stdio.md5a(new byte[][] { k , MY.Subs[4]} );
		
		b= Stdio.AES2Enc(k, i, b);
		k=null;
		i=null;
		
		Stdio.file_put_bytes(fn, b);
		b=null;
		fn=null;
		}
	
	
	public VirtualRVMATEntry SenderVirtualRVMATEntryLoad(String mail) throws Exception { //Carica RVMAT
		String dom = J.getDomain(mail);
		if (dom==null) return null;
			
		String[] fp = DbNetFile(mail);
		String fn = fp[0]+"/"+fp[1];
		if (!new File(fn).exists()) return null;
		
		byte[] b = Stdio.file_get_bytes(fn);
		byte[] k = Stdio.sha256a(new byte[][] { mail.getBytes() , MY.Sale} );
		byte[] i = Stdio.md5a(new byte[][] { k , MY.Subs[4]} );
		b = Stdio.AES2Dec(k, i, b);
		k=null;
		i=null;
		VirtualRVMATEntry M = UnPackVirtualRVMATEntry(b);
		b=null;
		return M;
		}
	
	public void SenderVirtualRVMATEntryDelete(String mail) throws Exception { //Elimina RVMAT
		String[] fp = DbNetFile(mail);
		String fn = fp[0]+"/"+fp[1];
		if (!new File(fn).exists()) return;
		J.Wipe(fn, true);
		}
	
	//////////////////// altre funzioni
	
	
	public byte[] PackVirtualRVMATEntry(VirtualRVMATEntry M) throws Exception {
		return Stdio.MxAccuShifter(new byte[][]{
				M.mail.getBytes(),
				M.onionMail.getBytes(),
				M.server.getBytes()	,
				M.sign }, Const.MX_RVMAT, true) ;
		}
	
	public VirtualRVMATEntry UnPackVirtualRVMATEntry(byte[] in) throws Exception {
		byte[][] F = Stdio.MxDaccuShifter(in, Const.MX_RVMAT);
		VirtualRVMATEntry M = new VirtualRVMATEntry();
		M.mail = new String(F[0]);
		M.onionMail = new String(F[1]);
		M.server = new String(F[2]);
		M.sign = F[3];
		return M;
		}
	
	public VirtualRVMATEntry Sign(VirtualRVMATEntry M,PrivateKey P) throws Exception {
		byte[] b = (M.mail+"\n"+M.onionMail+"\n"+M.server).getBytes();
		M.sign = Stdio.RSASign(b, P);
		return M;
		}
	
	public boolean VirtualRVMATEntryVerify(VirtualRVMATEntry M,PublicKey P) throws Exception {
		if (M.sign.length==0) return false;
		byte[] b = (M.mail+"\n"+M.onionMail+"\n"+M.server).getBytes();
		return Stdio.RSAVerify(b, M.sign, P);
		}
	/////////////////////////////////
			
	//////////////////////// Funzioni VMAT come Exit //////////////////////////
	
	public void delete(VirtualMatEntry M) throws Exception {
		String fn = DbFile(M.localPart);
		if (new File(fn).exists())	J.Wipe(fn, true);
		fn = DbFile(M.onionMail)+".rev";
		if (new File(fn).exists()) J.Wipe(fn, true);
		}
	
	public void saveVMAT(VirtualMatEntry M) throws Exception {
		byte[] k = Stdio.md5a(new byte[][] { MY.Sale , MY.Subs[2],M.localPart.toLowerCase().getBytes() }) ;
		byte[] i = Stdio.md5a(new byte[][] { k , MY.Subs[3] });
		
		byte[] b = Stdio.MxAccuShifter( new byte[][] {
				new byte[] {1 , M.enabled ? (byte)1 : (byte)0},
				M.localPart.getBytes()	,
				M.onionMail.getBytes() ,
				M.passwd	}, 0x1234,true) ;
		
		byte[] cb = Stdio.AES2Enc(k, i, b);
		
		String fn = DbFile(M.localPart);
		Stdio.file_put_bytes(fn, cb);
		
		k = Stdio.md5a(new byte[][] { MY.Sale , MY.Subs[2],M.onionMail.toLowerCase().getBytes() }) ;
		i = Stdio.md5a(new byte[][] { k , MY.Subs[3] });
		
		fn = DbFile(M.onionMail)+".rev";
		cb = Stdio.AES2Enc(k, i, b);
		Stdio.file_put_bytes(fn, cb);
		}
	
	public VirtualMatEntry loadVmat(String param,boolean isOnionMail) throws Exception {
		String fn = DbFile(param);
		if (isOnionMail) fn+=".rev";
		if (!new File(fn).exists()) return null;
		byte[] k = Stdio.md5a(new byte[][] { MY.Sale , MY.Subs[2],param.toLowerCase().getBytes() }) ;
		byte[] i = Stdio.md5a(new byte[][] { k , MY.Subs[3] });
		
		byte[] b= Stdio.file_get_bytes(fn);
		b = Stdio.AES2Dec(k, i, b);
		byte[][] fi = Stdio.MxDaccuShifter(b, 0x1234);
		
		VirtualMatEntry M = new VirtualMatEntry();
		M.enabled = fi[0][1] !=0;
		M.localPart = new String(fi[1]);
		M.onionMail = new String(fi[2]);
		M.passwd = fi[3];
		return M;
	}
	
	public VirtualMatEntry subscribe(String local,String onionMail,String passwd) throws Exception {
		String loc = local;
		loc=loc.toLowerCase().trim();
		if (
					!loc.matches("[a-z0-9]{1,16}") ||
					loc.contains("sysop")	||
					loc.contains("server")	
					) throw new PException("@550 Invalid VMAT local part address") ;
					
		if (new File(DbFile(onionMail)+".rev").exists()) throw new PException("@500 Virtual Mat for `"+onionMail+"` arleady exists");
		
		long rnd = Stdio.NewRndLong() & 0x7FFFFFFFL;
		String fn;
		int ax;
		for (ax=0;ax<4;ax++) {
			fn = DbFile(loc);
			if (new File(fn).exists()) {
					if (ax==0) loc+="-";
					loc+=(char) 0x61 + (int) (rnd % 25);
					rnd<<=6;
					} else break;
			}
		
		if (ax==4) return null;
		VirtualMatEntry M = new VirtualMatEntry();
		M.onionMail = onionMail;
		M.localPart=loc;
		M.enabled=true;
		M.passwd = Stdio.md5a(new byte[][] { MY.Sale,passwd.getBytes() });
		saveVMAT(M);
		return M;
		}
	
	public boolean logon(VirtualMatEntry M,String passwd) throws Exception {
		byte[] x =  Stdio.md5a(new byte[][] { MY.Sale,passwd.getBytes() });
		return Arrays.equals(x, M.passwd);
		}
	
}
