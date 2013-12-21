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

import java.io.RandomAccessFile;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class DBCrypt {

	private SecretKey AES = null;
	private SecretKey AESI = null;
	private byte[] IV=null;
	private byte[] IVI=null;
	private boolean isRSA=false;
	private PrivateKey SH=null;
	private PublicKey PK=null;
	private int BlockSize=0;
	private int dbSize=0;
	private String FileName=null;
	private RandomAccessFile F=null;
	private byte Index[] = null;
	private byte[] Sale=null;
	private long StartPox=0;
		
	private static long Magic1=Long.parseLong("rsadbfver20",36);
	private static long Magic2=Long.parseLong("aesdbfver15",36);
	
	public static DBCrypt Create(String fn,byte[] Srvk,PublicKey K,int maxr,int bsiz) throws Exception {
		DBCrypt D = new DBCrypt();
		D.isRSA=true;
		D.FileName=fn;
		D.PK=K;
		D.dbSize = maxr;
		D.BlockSize=bsiz;
		D.FileCreate(Srvk);
		return D;
	}
	
	public static DBCrypt Create(String fn,byte[] Srvk,int maxr,int bsiz) throws Exception {
		DBCrypt D = new DBCrypt();
		D.isRSA=false;
		D.FileName=fn;
		D.dbSize = maxr;
		D.BlockSize=bsiz;
		D.FileCreate(Srvk);
		return D;
	}
		
	public static DBCrypt Open(String fn,byte[] Srvk) throws Exception {
		DBCrypt D = new DBCrypt();
		D.isRSA=false;
		D.FileName=fn;
		D.FileOpen(Srvk);
		return D;
	}
	
	public static DBCrypt OpenW(String fn,byte[] Srvk,PublicKey k) throws Exception {
		DBCrypt D = new DBCrypt();
		D.isRSA=true;
		D.PK=k;
		D.FileName=fn;
		D.FileOpen(Srvk);
		return D;
	}
	
	public static DBCrypt OpenRW(String fn,byte[] Srvk,KeyPair k) throws Exception {
		DBCrypt D = new DBCrypt();
		D.isRSA=true;
		D.PK=k.getPublic();
		D.SH=k.getPrivate();
		D.FileName=fn;
		D.FileOpen(Srvk);
		return D;
	}
	
	public void Close() throws Exception {
		IndexSave();
		if (F!=null) {
			F.close();
			F=null;
			}
	}

	public int GetMaxSize() { return dbSize; }
	public int DBLength() { return Index.length; }

	public int[] GetIndex() {
		int cx=Index.length;
		int[] t = new int[cx];
		int bp=0;
		for (int ax=0;ax<cx;ax++) if (Index[ax]!=0) t[bp++]=ax;
		int[] rs = new int[bp];
		System.arraycopy(t, 0, rs, 0, bp);
		return rs;
	}
	
	public int GetFree() {
		int mx = Index.length;
		for (int ax=0;ax<mx;ax++) if (Index[ax]==0) return ax;
		if (dbSize==0) {
			int a = Index.length;
			byte[] b= new byte[a+1];
			System.arraycopy(Index, 0, b, 0, a);
			Index=b;
			return a; 			
		}
		return -1;
		}
	
	public int AddBlock(byte[] b) throws Exception {
		int f = GetFree();
		if (f==-1) throw new Exception("Database Full");
		BlockWrite(f, b);
		return f;
	}
	
	public int AddRecord(DbCryptRecord r) throws Exception {
		byte[] b = r.toBytesArray();
		return AddBlock(b);
	}
	
	public DbCryptRecord GetRecord(int id) throws Exception {
		byte[] b = BlockRead(id);
		if (b==null) return null;
		return new DbCryptRecord(b);		
		}
	
	public void PutRecord(int id,DbCryptRecord r) throws Exception {
		byte[] b = r.toBytesArray();
		BlockWrite(id,b);
	}
	
	DBCryptIterator GetIterator() { return new DBCryptIterator(); }
	
	public class DBCryptIterator {
		private int[] Idx=null;
		private int Last=0;

		DBCryptIterator() {
			Idx = GetIndex();
			Last=0;
		}
		
		public DbCryptRecord NextRecord() throws Exception {
		byte[] b = Next();
		if (b==null) return null;
		return new DbCryptRecord(b);		
		}
	
		public void WriteRecord(int id,DbCryptRecord r) throws Exception {
			if (id<0 || id>=Idx.length) throw new Exception("Unexistent block in `"+FileName+"` "+id);
			int bp = Idx[id];
			byte[] b = r.toBytesArray();
			BlockWrite(bp,b);
		}
		
		public DbCryptRecord ReadRecord(int id) throws Exception {
			byte[] b = ReadBlock(id);
			if (b==null) return null;
			return new DbCryptRecord(b);		
			}
		
		public byte[] Next() throws Exception {
			if (Last==Idx.length) return null;
			int bp = Idx[Last++];
			return BlockRead(bp);
			}
		
		public void WriteBlock(int id,byte[] b) throws Exception {
			if (id<0 || id>=Idx.length) throw new Exception("Unexistent block in `"+FileName+"` "+id);
			int bp = Idx[id];
			BlockWrite(bp,b);		
			}
		
		public byte[] ReadBlock(int id) throws Exception {
			if (id<0 || id>=Idx.length) throw new Exception("Unexistent block in `"+FileName+"` "+id);
			int bp = Idx[id];
			return BlockRead(bp);		
			}
		
		public void DeleteBlock(int id) throws Exception {
			if (id<0 || id>=Idx.length) throw new Exception("Unexistent block in `"+FileName+"` "+id);
			int bp = Idx[id];
			BlockDel(bp);
			Reindex();
			}
		
		public int GetThrueID(int id) {
			if (id<0 || id>=Idx.length) return -1;
			return Idx[id];
			}
		
		public void Rewind() { Last=0; }
		public int Length() { return Idx.length; }
		public int CurrentIndex() { return Last; }
		
		public void Reindex() { 
			Last=0;
			Idx = GetIndex();
			}
		
		public boolean Eof() { if (Last>=Idx.length) return true; else return false; }
	}
	
	private byte[] GenKey(byte[] Sale,byte[] Srvk) throws Exception {
		byte[] c;
		if (isRSA) c= Stdio.Public2Arr(PK); else c = "AES".getBytes();
		byte[] b = Stdio.md5a(new byte[][] {Sale, Srvk,c } );
		AES = Stdio.GetAESKey(b);
		IV = Stdio.md5a(new byte[][] {Sale, Srvk ,c, b });
		IVI = Stdio.md5a(new byte[][] { b,c,Srvk,IV,Sale });
		b= Stdio.md5a( new byte[][] { IVI, IV, Srvk,b,c,Sale });
		AESI=Stdio.GetAESKey(b);
		return Stdio.md5a(new byte[][] { IV, Srvk,b,c });
		}
	
	private void FileCreate(byte[] Srvk) throws Exception {
		F = new RandomAccessFile(FileName+".dbf","rw");
		F.setLength(0);
		F.seek(0);
		if (isRSA) F.writeLong(Magic1); else F.writeLong(Magic2);
		int isz = dbSize>>4;
		if ((dbSize&4)!=0) isz++;
		isz<<=4;
		if (isz==0) isz=256;
		Index = new byte[isz];
		F.writeShort(dbSize);
		F.writeShort(BlockSize);
		Sale=new byte[64];
		Stdio.NewRnd(Sale);
		byte[] vk = GenKey(Sale,Srvk);
		F.write(Sale);
		F.write(vk);
		StartPox=F.getFilePointer();
		IndexSave();		
		}	
	
	public void Update() { try { IndexSave(); } catch(Exception E) { Main.EXC(E, "DBCrypt.Update"); } }
	
	private void IndexSave() throws Exception {
		byte[] b = Stdio.AESEnc(AESI, IVI, Index);
		Stdio.file_put_bytes(FileName+".idx", b);
		}
	
	private void IndexLoad() throws Exception {
		byte[] b = Stdio.file_get_bytes(FileName+".idx");
		Index = Stdio.AESDec(AESI, IVI, b);
		}
	
	private void FileOpen(byte[] Srvk) throws Exception {
		F = new RandomAccessFile(FileName+".dbf","rw");
		F.seek(0);
		long t0 = F.readLong();
		long t1;
		if (isRSA) t1=Magic1; else t1=Magic2;
		if (t0!=t1) {
			F.close();
			throw new Exception("Invalid file type `"+FileName+"`");
			}
		
		dbSize = F.readUnsignedShort();
		BlockSize= F.readUnsignedShort();
		Sale=new byte[64];
		F.read(Sale);
		byte[] ak = new byte[16];
		F.read(ak);
		byte[] vk = GenKey(Sale,Srvk);
		for (int ax=0;ax<16;ax++) {
			if (vk[ax]!=ak[ax]) {
				F.close();
				throw new Exception("Invalid file KEY");
				}
			}
		StartPox=F.getFilePointer();
		IndexLoad();
	}
	
	public void BlockWrite(int id,byte[] b) throws Exception {
		int mx = BlockSize-11;
		byte[] c = b;
		
		 if (!isRSA) {	//Non RSA
			 int ex = b.length;
			 if (ex>BlockSize) {		//Block too big then truncate it
				c = new byte[BlockSize];
				System.arraycopy(b, 0, c, 0,BlockSize);
			 	} else if (ex<BlockSize) { //block too small then pad it
			 	c = new byte[BlockSize];
			 	Stdio.NewRnd(c);
			 	System.arraycopy(b, 0, c, 0,b.length);
			 	c[b.length]=0; // preserve end byte 0
			 	} 
			 } else { //RSA
				 
				if (b.length>mx) {	//Block too big then truncate it
					c=new byte[mx];
					System.arraycopy(b, 0, c, 0, mx);
					}
			}
		if (isRSA) c = Stdio.RSAEncP(c, PK);
		c = Stdio.AESEnc(AES, IV, c);
		long pox = StartPox+ (id*BlockSize);
		synchronized(F) {
				if (F.getFilePointer()!=pox) F.seek(pox);
				F.write(c);
				}
		Index[id]=1;
		}
	
	public byte[] BlockRead(int id) throws Exception {
		if (Index[id]==0) return null;
		if (isRSA && SH==null) throw new Exception("Can't read RSADBF without private key");
		long pox = StartPox+ (id*BlockSize);
		byte[] b= new byte[BlockSize];
		synchronized(F) {
			if (F.getFilePointer()!=pox) F.seek(pox);
				F.read(b);
				}
		b = Stdio.AESDec(AES,IV,b);
		if (isRSA) b = Stdio.RSADecP(b, SH);
		return b;
		}
	
	public void BlockDel(int id) throws Exception {
		byte[] c = new byte[BlockSize];
		Index[id]=0;
		long pox = StartPox+ (id*BlockSize);
		synchronized(F) {
				if (F.getFilePointer()!=pox) F.seek(pox);
				F.write(c);
				}
		}

	protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
