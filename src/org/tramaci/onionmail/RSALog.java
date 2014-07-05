/*
 * Copyright (C) 2013-2014 by Tramaci.Org
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

import java.io.RandomAccessFile;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;

public class RSALog {

	private RandomAccessFile L = null;
	private PublicKey PK = null;
	private PrivateKey RD = null;
	private int readerCursror=0;
	private volatile int currentRecord = 0;
	private volatile int currentHI = 0;
	private volatile int maxRecord = 0;
	private volatile int recordSize = 0;
	private static final int[] Fmt = new int[] { 8,3,2 };
	private static final int Magic = 0x706F; //LOGF
	private static final int initRecordSize=448;
	private static final int headerSize=1024;
	private static final int recordDataSzie=initRecordSize-2;
	
	public static final int keyBits = 512;
	public static final int keyBytes=keyBits/8;
	
	public class LogData {
		int hi=0;
		int num=0;
		long tcr = 0;
		int flags=0;
		int task = 0;
		String area=null;
		String text=null;
		
		@SuppressWarnings("deprecation")
		public String toString() {
			int type = flags;
			Date D = new Date(tcr);
			String h = (D.getYear()+1900)+"-"+
							J.Int2Str(D.getMonth()+1,2)+"-"+
							J.Int2Str(D.getDate(),2)+" "+
							J.Int2Str(D.getHours(),2)+":"+
							J.Int2Str(D.getMinutes(),2)+":"+
							J.Int2Str(D.getSeconds(),2)+"."+
							J.Int2Str((int)(tcr % 1000),4);
			
			String t;
			if ((type>>6)==0) {
				t="";
				if ((type&Config.GLOG_All)!=0) t+="A"; else t+="-";
				if ((type&Config.GLOG_Server)!=0) t+="S";  else t+="-";
				if ((type&Config.GLOG_Event)!=0) t+="E";  else t+="-";
				if ((type&Config.GLOG_Bad)!=0) t+="B";  else t+="-";
				if ((type&Config.GLOG_Spam)!=0) t+="S";  else t+="-";
				} else t = "X"+Long.toHexString(0x10000L | type).substring(1);
	
			String tid = Long.toHexString(Thread.currentThread().getId());
			return h+" "+J.Spaced(J.Limited(tid,8), 8)+" "+J.Spaced(t, 5)+" "+J.Spaced(area, 32)+" "+text;
			}
		}
	
	public void  write(long tcr,int task,int flags, String area,String text) throws Exception {
		if (L==null) throw new Exception("Log not open");
		byte[] log = pak(tcr,task,flags,area,text);
		log = Stdio.RSAEncData(log, PK,keyBytes);
		int cx = log.length;
		if (cx>recordDataSzie) throw new Exception("Record too big");
		
		currentRecord=currentRecord+1;
		if (currentRecord>=maxRecord) {
				currentRecord=0;
				currentHI=(currentHI+1) & 16383;
				}
		
		long addr = recordAddress(currentRecord);
		synchronized(L) {
			long p = L.getFilePointer();
			L.seek(addr);
			L.writeByte(0x80 | (127 & currentHI));
			L.writeShort(cx);
			L.write(log);
			L.seek(2);
			L.writeShort(currentRecord);
			L.writeShort(currentHI);
			L.seek(p);
			}
	}
	
	public void enableReader(byte[] ke) throws Exception {
		KeyPair h = decodeToRead(ke);
		RD=h.getPrivate();
		readerCursror=currentRecord+1;
		}
	
	public void disableReader() { 
			RD=null;
			System.gc();
			readerCursror=0;
			}
	
	public boolean feof() { return readerCursror==(currentRecord+1)% maxRecord; }
	
	private byte[] pak(long tcr,int task,int flags, String area,String text) throws Exception { //394 by
		byte[][] F = new byte[3][];
		if (text.length()>300) text=text.substring(0,300);
		if (area.length()>60) area=area.substring(0,60);
		F[1] = area.getBytes();
		F[2] = text.getBytes();
		F[0] = Stdio.Stosxm(new long[] {
							tcr, task,flags } , Fmt)
							;
		return Stdio.MxAccuShifter(F, Magic,true);
		}
	
	private LogData unPak(byte[] dta) throws Exception {
		byte[][] F = Stdio.MxDaccuShifter(dta, Magic);
		LogData q = new LogData();
		long[] i = Stdio.Lodsxm(F[0], Fmt);
		q.tcr = i[0];
		q.task=(int)i[1];
		q.flags=(int)i[2];
		q.area = new String(F[1]);
		q.text = new String(F[2]);
		return q;
		}
	
		public LogData read() throws Exception {
		if (L==null) throw new Exception("Log not open");
		if (RD==null) throw new Exception("Reader disabled");
		
		long addr = recordAddress(readerCursror);
		int pox=readerCursror;
		readerCursror=readerCursror+1;
		if (readerCursror>=maxRecord) readerCursror=0;

		byte[] dta;
		int hi=0;
		int sz;
		synchronized(L) {
			long p = L.getFilePointer();
			L.seek(addr);
			hi = L.readByte();
			sz = L.readShort();
			dta = new byte[sz];
			L.read(dta);
			L.seek(p);
			}
		
		if (hi==0 || sz==0) return null;
		dta = Stdio.RSADecData(dta, RD, keyBytes);
		
		LogData ld = unPak(dta);
		ld.hi=hi;
		ld.num=pox;
		return ld;
		}
	
	private static int getKeyId(PublicKey P) throws Exception {
		byte[] x  = Stdio.Public2Arr(P);
		x = Stdio.md5(x);
		int a=0;
		for (int ax=0;ax<4;ax++) {
			a<<=8;
			a^=(255&x[ax]);
			}
		return a;
	}
	
	private byte[][] decodeHeader(byte[] ke,boolean priv) throws Exception {
		if (L==null) throw new Exception("Log not open");
		byte[] in = new byte[headerSize];
		synchronized(L) {
			long p = L.getFilePointer();
			L.seek(16);
			L.read(in);
			L.seek(p);
			}
		
		byte[][] F = Stdio.MxDaccuShifter(in, Magic);
		byte[] rnd = F[0];
		byte[] tes = Stdio.md5a(new byte[][] { rnd,ke});
		if (!Arrays.equals(tes, F[ priv ? 4:3 ])) throw new Exception("Invalid Log password");
		byte[] key = J.Der2048(ke,rnd);
		in = F[ priv ? 2:1];
		in = Stdio.AESDecMul(key,in);
		return Stdio.MxDaccuShifter(in,Magic);
		}
	
	private PublicKey decodeToWrite(byte[] ke) throws Exception {
		byte[][] F = decodeHeader(ke,false);
		return Stdio.Arr2Public(F[1]);
		} 	 
	
	private KeyPair decodeToRead(byte[] ke) throws Exception {
		byte[][] F = decodeHeader(ke,true);
		PublicKey p = Stdio.Arr2Public(F[1]);
		PrivateKey h = Stdio.Arr2Private(F[2]);
		return new KeyPair(p,h);
		}
	
	public static void logFileCreate(String fileName,byte[] kp,byte[] kh,int lpsize) throws Exception {
		KeyPair LK = Stdio.RSAKeyGen(RSALog.keyBits);
		byte[] rnd = new byte[16];
		Stdio.NewRnd(rnd);
		int maxRecord=lpsize;
		byte[][] F = new byte[][] {
					rnd,
					Stdio.MxAccuShifter( new byte[][] { "KEYP".getBytes(), Stdio.Public2Arr(LK.getPublic()) }, Magic,true),
					Stdio.MxAccuShifter( new byte[][] { 
								"KEYH".getBytes(), 
								 Stdio.Public2Arr(LK.getPublic()),
								 Stdio.Private2Arr(LK.getPrivate()) 
								 }, Magic,true)
								 ,
					Stdio.md5a(new byte[][] { rnd, kp}),
					Stdio.md5a(new byte[][] { rnd, kh})}
					;
		
		F[1] = Stdio.AESEncMul(J.Der2048(kp, rnd), F[1]);
		F[2] = Stdio.AESEncMul(J.Der2048(kh, rnd), F[2]);
		rnd = Stdio.MxAccuShifter(F, Magic);
		
		RandomAccessFile O = new RandomAccessFile(fileName,"rw");
		int recordSize=initRecordSize+2;

		int magicNumber=getKeyId(LK.getPublic());
		O.seek(0);							
		O.writeShort(Magic);		//magic_fmt
		O.writeShort(-1);				//curr 
		O.writeShort(0);					//hi
		O.writeShort(0);					//0
		O.writeInt(magicNumber);	//magic
		O.writeShort(maxRecord);	//maxrec
		O.writeShort(recordSize);	//size
		byte[] b= new byte[headerSize];
		O.write(b);
		
		b= new byte[256];
		long size = recordSize*maxRecord;
		int block = (int) size>>8;
		if ((size&255)!=0) block++;
		for (int ax=0;ax<block;ax++) O.write(b);
		
		//Extended Record
		O.write(b); 
		O.writeShort(Magic);
		O.writeShort(0x0201);		
		O.writeInt(magicNumber);	//magic
		O.writeShort(maxRecord);	//maxrec
		O.writeShort(recordSize);	//size
		O.writeShort(0x5678);
		O.writeShort(12);
		O.seek(16);
		O.write(rnd);
		O.close();
		b=null;
	}
	
	private long recordAddress(int num) { return  headerSize+ 16 + (num*recordSize); }
	
	public RSALog(String fileName,byte[] ke,boolean asRead) throws Exception {
		if (L!=null) try { 
						L.close();
						L =null;
						} catch(Exception F) {}
		
		L = new RandomAccessFile(fileName,"rw");
		try {
			L.seek(0);
			int oem = L.readShort();	//oem fmt
			if (oem!=Magic) throw new Exception("LogFile: Invalid LogFile "+Integer.toHexString(oem));
			currentRecord = L.readShort();		//curr
			currentHI = L.readShort();	//hi
			L.readShort();	//0
			int mg = L.readInt();		//magic
			maxRecord = L.readShort(); //maxrec
			recordSize = L.readShort();	//size
			if (asRead) {
				KeyPair KK = decodeToRead(ke);
				PK=KK.getPublic();
				RD=KK.getPrivate();
				readerCursror=currentRecord+1;
				}else PK = decodeToWrite(ke);
			if (mg!=getKeyId(PK)) throw new Exception("@Invalid log key");			
			} catch(Exception E) {
				try { 
						L.close();
						L =null;
						} catch(Exception F) {}
				throw E;
				} 
	}
	
	public void close() {
		if (L!=null) try { 
						L.close();
						} catch(Exception F) {}
		L =null;
		PK=null;
		RD=null;
		System.gc();
		}
}
