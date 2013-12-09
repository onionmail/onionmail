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
import java.net.InetAddress;
import javax.crypto.SecretKey;

public class IPList {
	private int MinOldIP=10;
	private String fn=null;
	private SecretKey K=null;
	private byte[] IV = null;
	
	private volatile int IPS[] = null;
	private volatile short[] Point = null;
	private volatile int[] Tcr = null;
	private boolean needGarb=false;
	
	private int getipa(InetAddress I) {
		byte[] a = I.getAddress();
		int ip = (int)(a[0]&255);
		ip<<=(int)(a[1]&255);
		ip<<=(int)(a[2]&255);
		ip<<=(int)(a[3]&255);
		ip^=ip>>1;
		return ip;
		}	
	
	public int getIP(InetAddress I) {
		int ip = getipa(I);
		int cx = IPS.length;
		int t= (int) (System.currentTimeMillis()/60000);
		for (int ax=0;ax<cx;ax++) {
			if (t>Tcr[ax]) { IPS[ax]=0; needGarb=true; }
			if (IPS[ax]==ip) return Point[ax];
			}
		return 0;
	}
	
	public void setIP(InetAddress I,int poi) {
		int ip = getipa(I);
		int cx = IPS.length;
		int lastzero=-1;
		for (int ax=0;ax<cx;ax++) {
			if (IPS[ax]==ip) {
				int b = Point[ax] + poi;
				if (b<0) b=0;
				if (b>32000) b=32000;
				Point[ax]=(short)b;
				Tcr[ax] +=MinOldIP;
				return;
				}
			if (lastzero==-1 && IPS[ax]==0) lastzero=ax;
			}
		
		if (lastzero!=-1) {
			IPS[lastzero] = ip;
			Point[lastzero]=(short)poi;
			Tcr[lastzero]= (int) (System.currentTimeMillis()/60000)+MinOldIP;	
			return;
			}
		
		short[] txp = new short[cx+1];
		System.arraycopy(Point, 0, txp, 0, cx);
		Point=txp;
		txp=null;
		int[] tmp= new int[cx+1];
		System.arraycopy(Tcr, 0, tmp, 0, cx);
		Tcr=tmp;
		tmp= new int[cx+1];
		System.arraycopy(IPS, 0, tmp, 0, cx);
		IPS=tmp;
		IPS[cx] = ip;
		Point[cx]=(short)poi;
		Tcr[cx]= (int) (System.currentTimeMillis()/60000)+MinOldIP;
	}
	
	IPList(SrvIdentity S,String file) throws Exception {
		fn = J.md2st(Stdio.md5a(new byte[][] { S.Sale , file.getBytes() }));
		byte[][] b = J.DerAesKey(S.Sale, file+fn);
		fn = S.Maildir+"/log/"+fn+".lsts";
		K = Stdio.GetAESKey(b[0]);
		IV=b[1].clone();
		J.WipeRam(b);
		b=null;
		
		if (!new File(fn).exists()) {
			IPS = new int[0];
			Point= new short[0];
			Tcr = new int[0];
			return;
			}
		
		byte[] c = Stdio.file_get_bytes(fn);
		c = Stdio.AESDec(K, IV, c);
		b = Stdio.MxDaccuShifter(c, 0xfeca);
		c=null;
		IPS = Stdio.Lodsxi(b[0], 4);
		Point = Stdio.Lodsw(b[1]);
		Tcr = Stdio.Lodsxi(b[2],4);
	}
	
	public void AutoSave() throws Exception {
		Garbage();
		
		byte[] b = Stdio.MxAccuShifter(new byte[][] {
			Stdio.Stosxi(IPS, 4),
			Stdio.Stosw(Point),
			Stdio.Stosxi(Tcr, 4)		}, 0xfeca, true) ;
		
		b=Stdio.AESEnc(K, IV, b);
		Stdio.file_put_bytes(fn, b);
		
	}
	
	public void Close() { try { AutoSave(); } catch(Exception E) {} }
	
	public void Garbage() {
		if (!needGarb) return;
		int dx=0;
		int cx = IPS.length;
		for (int ax=0;ax<cx;ax++) if (IPS[ax]!=0) dx++;
		int[] i = new int[dx];
		int[] t = new int[dx];
		short[] p = new short[dx];
		int bp=0;
		for (int ax=0;ax<cx;ax++) {
			if (IPS[ax]!=0) {
				i[bp]=IPS[ax];
				t[bp]=Tcr[ax];
				p[bp]=Point[ax];
				bp++;
				if (bp>=cx) break;
				}
			}
		IPS=i;
		Tcr=t;
		Point=p;
		needGarb=false;
	}
	
	
	
}
