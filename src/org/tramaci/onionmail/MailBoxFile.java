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


import java.io.EOFException;
import java.io.File;
import java.io.RandomAccessFile;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class MailBoxFile {
	private static final long MagicNumber =Long.parseLong("mailboxfile2",36);
	private static final int KBSize=256;
	
	private SecretKey[] KEY= new SecretKey[4];
	private byte[][] IV = new byte[4][16];
	
	private RandomAccessFile O =null;
	private int mode=0;
	private long StartPox=0;
	private long EndPoint = 0;
	
	private String FileName=null;
	
	private byte[] SrvK = new byte[] {1,2,4,8 };
	public boolean isTEMP = false;
	
	public boolean isOpen() { return mode!=0; }
	public boolean isRead() { return mode==2; }
	public boolean isWrite() { return mode==1; }
	
	public long getStartPox() { return StartPox; }
	public String getFileName() { return FileName; }
	
	public void SetSrvKey(byte[] b) { SrvK = b.clone(); }
	
	private void clear() {
		O=null;
		for (int ax=0;ax<3;ax++) {
					KEY[ax] = null;
				for(int bx=0;bx<16;bx++) {
					IV[ax][bx] = 0;
					}
		}
		mode=0;
		StartPox=0;
		EndPoint=0;
		FileName=null;
		O=null;
		System.gc();
	}
	
	public void OpenW(String filename,PublicKey K) throws Exception {
		if (mode!=0) throw new Exception("@500 File arleady open");
		FileName = filename;
		byte[][] Keys = new byte[6][16];
		
		for (int ax=0;ax<6;ax++) Stdio.NewRnd(Keys[ax]);
		
		byte[] bot = Stdio.RSAEncData(Stdio.MxAccuShifter(Keys, 0x4b01, true), K, KBSize);
		
		O = new RandomAccessFile(filename,"rw");
		O.seek(0);
		O.writeLong(MagicNumber);
		O.writeLong(0);
		
		O.writeShort(bot.length);
		O.write(bot);
		
		KEY = new SecretKey[3];
		byte[] tmpk = SrvK.clone();
		for (int ax=0;ax<3;ax++) {
			IV[ax] = Stdio.md5a(new byte[][] { Keys[ax+3] , tmpk });
			tmpk = IV[ax].clone();
			tmpk =Stdio.md5a(new byte[][] { Keys[ax] , tmpk , IV[ax] });
			KEY[ax] = KEY[ax] = Stdio.GetAESKey(tmpk);
			}
		
		for (int ax=0;ax<16;ax++) tmpk[ax]=0;
		tmpk=null;
		
		mode=1;
		StartPox = O.getFilePointer();
	}
	
	public void OpenTMP(String filename) throws Exception {
		FileName = filename;
		byte[][] Keys = new byte[6][16];
		
		for (int ax=0;ax<6;ax++) Stdio.NewRnd(Keys[ax]);
		
		StartPox=0;
		isTEMP=true;
				
		KEY = new SecretKey[3];
			byte[] tmpk = SrvK.clone();
			for (int ax=0;ax<3;ax++) {
				IV[ax] = Stdio.md5a(new byte[][] { Keys[ax+3] , tmpk });
				tmpk = IV[ax].clone();
				tmpk =Stdio.md5a(new byte[][] { Keys[ax] , tmpk , IV[ax] });
				KEY[ax] = KEY[ax] = Stdio.GetAESKey(tmpk);
				}
			
			for (int ax=0;ax<16;ax++) tmpk[ax]=0;
			tmpk=null;
		mode=1;
		O = new RandomAccessFile(filename,"rw");
		O.seek(0);
		
	}
	
	public void OpenAES(String filename,byte[] Salt,boolean create) throws Exception {
		FileName = filename;
		byte[][] Keys = new byte[6][16];
		
		for (int ax=0;ax<6;ax++) Keys[ax] = Stdio.md5a(new byte[][] { Keys[5-ax] , Salt }); 
		for (int ax=0;ax<6;ax++) Keys[ax] = Stdio.md5a(new byte[][] { Salt, Keys[5-ax] });
		
		StartPox=0;
		isTEMP=true;
				
		KEY = new SecretKey[3];
			byte[] tmpk = SrvK.clone();
			for (int ax=0;ax<3;ax++) {
				IV[ax] = Stdio.md5a(new byte[][] { Keys[ax+3] , tmpk });
				tmpk = IV[ax].clone();
				tmpk =Stdio.md5a(new byte[][] { Keys[ax] , tmpk , IV[ax] });
				KEY[ax] = KEY[ax] = Stdio.GetAESKey(tmpk);
				}
			
		for (int ax=0;ax<16;ax++) tmpk[ax]=0;
		
		tmpk=null;
		if (create) mode=1; else mode=2;
		O = new RandomAccessFile(filename,"rw");
		O.seek(0);
		
	}
	
	public void TMPRead() throws Exception {
		if (isTEMP) mode=2;
		O.seek(0);
	}
	
	public void OpenR(String filename,PrivateKey K) throws Exception {
		if (mode!=0) throw new Exception("@500 File arleady open");
		FileName = filename;
		byte[][] Keys = null;
		
		O = new RandomAccessFile(filename,"rw");
		try {
			O.seek(0);
			long Mag = O.readLong();
			if (Mag!=MagicNumber) throw new Exception("@500 Invalid message file");
			EndPoint = O.readLong();
			
			int eax = O.readShort();
			byte[] bot = new byte[eax];
			O.read(bot);
			
			
			try {
					bot = Stdio.RSADecData(bot, K, KBSize);
					Keys = Stdio.MxDaccuShifter(bot, 0x4b01);
				} catch(Exception E) {
					O.close();
					throw new Exception("@500 Invalid USER key");
				}
		
			KEY = new SecretKey[3];
			byte[] tmpk = SrvK.clone();
			for (int ax=0;ax<3;ax++) {
				IV[ax] = Stdio.md5a(new byte[][] { Keys[ax+3] , tmpk });
				tmpk = IV[ax].clone();
				tmpk =Stdio.md5a(new byte[][] { Keys[ax] , tmpk , IV[ax] });
				KEY[ax] = KEY[ax] = Stdio.GetAESKey(tmpk);
				}
			
			for (int ax=0;ax<16;ax++) tmpk[ax]=0;
			tmpk=null;
			
			mode=2;
			StartPox = O.getFilePointer();
		} catch(EOFException E) {
			throw new Exception("@Invalid message file `"+filename+"`");
			
		} 
	}
	
	public void WriteLn(String st) throws Exception {
		if (mode!=1) throw new Exception("@500 Bad file access mode");
		
		byte[] stv = st.getBytes();
		int cx = stv.length;
		int blo = cx>>4;
		if ((cx&15)!=0) blo++;
		int dx = blo<<4;
		byte[] out = new byte[dx];
		Stdio.NewRnd(out);
		System.arraycopy(stv, 0, out, 0, cx);
		
		long Pox = O.getFilePointer();
		byte[] Fix = Stdio.md5a(new byte[][] { IV[2] , Long.toString(Pox,36).getBytes() });
		
		O.writeShort(0x8000 | blo);
		O.writeShort(cx);
		
		if (!isTEMP) {	out = Stdio.AESEnc(KEY[0], IV[0], out);
								out = Stdio.AESDec(KEY[1], IV[1], out);
							}
		out = Stdio.AESEnc(KEY[2],Fix, out);
	
		O.write(out);
		}
	
	public String ReadLn() throws Exception {
		if (mode!=2) throw new Exception("@500 Bad file access mode");
		long Pox = O.getFilePointer();
		
		int blo = O.readShort();
		if (blo==0) return null;
		blo&=0x7FFF;
		int cx = O.readUnsignedShort();
		int dx = blo<<4;
		byte[] in = new byte[dx];
		O.read(in);
		if (cx==0) return "";
		
		byte[] Fix = Stdio.md5a(new byte[][] { IV[2] , Long.toString(Pox,36).getBytes() });
				
		byte[] out = Stdio.AESDec(KEY[2], Fix, in);
		
		if (!isTEMP) {
					out = Stdio.AESEnc(KEY[1], IV[1], out);
					out = Stdio.AESDec(KEY[0], IV[0], out);
					}

		in=new byte[cx];
		System.arraycopy(out, 0, in, 0, cx);
		return new String(in,"UTF-8");
		}
		
	
	public void Close() throws Exception {
		if (isTEMP) {
			O.writeShort(0);
			if (O!=null) O.close();
			clear();
			return;
			}
		
		if (O!=null) { 
			if (mode==1) {
					long ip = O.getFilePointer();
					O.writeShort(0);
					O.writeShort(0);
					O.seek(0);
					O.writeLong(MagicNumber);
					O.writeLong(ip);
					}
			O.close();
			}
		clear();
	}
	
	public void Destroy(boolean fast) throws Exception {
		if (mode==0) throw new Exception("@500 file not open");
		O.seek(0);
		long sz = O.length();
		long cx = sz>>10;
		if ((sz&1023)!=0) cx++;
		byte[] rnd =new byte[1024];
		Stdio.NewRnd(rnd);
		if (fast) {
				for (long ax=0;ax<4;ax++) {
						Stdio.NewRnd(rnd);
						O.write(rnd);
						}
				
				int nr = (int) cx/10;
				if (nr>0)	for (long ax=0;ax<nr;ax++) {
						long bx =(long) Math.floor(Math.random()*(cx-3));
						bx ^= System.currentTimeMillis();
						bx =4+( bx % (cx-4));
						O.seek(1024*bx);
						Stdio.NewRnd(rnd);
						O.write(rnd);
						}
				} else for (long ax=0;ax<cx;ax++) O.write(rnd);
		
		O.close();
		O=null;
		mode=0;
		Stdio.file_put_bytes(FileName, "DELETED!\0\0\0\0".getBytes());
		File F = new File(FileName);
		if (!F.delete()) {
			new File(F.getPath()).setWritable(true);
			F.setWritable(true);
			if (!F.delete()) throw new Exception("Can't delete file `"+FileName+"`");
			}
	clear();
	}
	
	public void SetAppendMode() throws Exception {
		if (mode==0) throw new Exception("@500 File not open");
		if (mode==1) throw new Exception("@500 Can't append in write mode");
		if (EndPoint==0) throw new Exception("@500 Can't append");
		O.seek(EndPoint);
		mode=1;
	}
	
	public void Rewind() throws Exception {
		if (mode==0) throw new Exception("@500 File not open");
		if (mode==1) throw new Exception("@500 Can't rewind in write mode");
		O.seek(StartPox);
		
		
	}
	

	public long GetPox() throws Exception { return O.getFilePointer(); }
}
