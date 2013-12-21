package org.tramaci.onionmail;


/*
 * Copyright (C) 2011 by Tramaci.Org
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


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class Stdio {

	private static final int[] KeyPairStruct = new int[] { 4,2,8,2 };
	public static final int PKCSPaddingSize=11;
		
	public static byte[] Stosw(short[] arr) throws Exception {
		int cx=arr.length;
		byte[] o =new byte[cx*2];
		for (int ax=0;ax<cx;ax++) Poke(ax*2,(int)arr[ax],o);
		return o;
		}
	
	public static short[] Lodsw(byte[] arr) throws Exception {
		int cx = arr.length>>1;
		short[] o = new short[cx];
		for (int ax=0;ax<cx;ax++) o[ax] =(short) Peek(ax*2,arr);
		return o;
	}
	
	
	public  static  byte[] RSAEncDataP(byte[] Data,PublicKey K,int bsize) throws Exception {
		int cx =Data.length;
		byte[] raw = new byte[cx+2];
		System.arraycopy(Data, 0, raw, 2, cx);
		Poke(0,cx,raw);
		return  RSAEncData(raw, K,bsize);
	}
	
	public  static  byte[] RSADecDataP(byte[] Data,PrivateKey K,int bsize) throws Exception {
		byte[] raw = RSADecData(Data,K, bsize);
		int cx = Peek(0,raw);
		if (cx<0 || cx> raw.length-2) throw new Exception("Invalid RSA/DATA");
		byte[] out = new byte[cx];
		System.arraycopy(raw, 2, out, 0, cx);
		return out;
		}
	
	public  static  byte[] RSAEncData(byte[] Data,PublicKey K,int bsize) throws Exception {
		byte[][] Blo = DivBlock(Data,bsize-PKCSPaddingSize,true);
		int cx = Blo.length;
		for (int ax=0;ax<cx;ax++) Blo[ax] = RSAEncP(Blo[ax],K);
		return MulBlock(Blo,bsize);
	}
	
	public  static  byte[] RSADecData(byte[] Data,PrivateKey K,int bsize) throws Exception { //Attenzione alla fine ci saranno dei dati in più
		byte[][] Blo = DivBlock(Data,bsize,false);
		int cx = Blo.length;
		for (int ax=0;ax<cx;ax++) Blo[ax] = RSADecP(Blo[ax],K);
		return MulBlock(Blo,bsize-PKCSPaddingSize);
	}
	
	protected static byte[][] AddChunk(byte[][] d, byte[] c) throws Exception {
		int cx = d.length;
		byte[][] out = new byte[cx+1][];
		for (int ax=0;ax<cx;ax++) out[ax]=d[ax];
		out[cx]=c;
		return out;
	}
	
	protected static byte[][] RemChunks(byte[][] d,int re) throws Exception {
		int dx=d.length-re;
		byte[][] out = new byte[dx][];
		for (int ax=0;ax<dx;ax++) out[ax]=d[ax];
		return out;
	}
	
	public  static  byte[] MxAccuCrypter(byte[][] in,int magic32,PublicKey K,PrivateKey S) throws Exception {
		byte[] dt = MxAccuShifter(in,0x1234,true);
		byte[] ts = md5(dt);
		byte[] ke = new byte[16];
		byte[] si  = new byte[0];
		
		NewRnd(ke);
		dt = AESEnc(GetAESKey(ke),ts,dt);
		byte[] He = MXImplode(new byte[][] { ke, ts },0x12345678);
		He = RSAEncP(He,K);
		
		if (S!=null) si = RSASign(dt,S);
		return MXImplode( new byte[][] { He, dt , si },magic32);
		
	}
	
	protected static byte[][] MxDaccuDECrypter(byte[] in,int magic32, PrivateKey K,PublicKey S) throws Exception {
		byte[][] fi = MXExplode(in,magic32);
		byte[] He = RSADecP(fi[0],K);
		byte[][] Hec = MXExplode(He,0x12345678);
		SecretKey Ke = GetAESKey(Hec[0]);
		
		if (S!=null && fi[2].length==0) throw new Exception("_MX:SIGN:N");
		if (S!=null && fi[2].length>0) {
			if (!RSAVerify(fi[1],fi[2],S)) throw new Exception("_MX:SIGN");
			}
		
		byte[] dt = AESDec(Ke,Hec[1],fi[1]);
		byte[] ts = md5(dt);
		for (int ax=0;ax<16;ax++) if (ts[ax]!=Hec[1][ax]) throw new Exception("_MX:KEY");
		return MxDaccuShifter(dt,0x1234);
		
	}
	
	
	protected static long MyUserCode(String login) {
		CRC32 C = new CRC32();
		C.update(login.getBytes());
		long d = C.getValue();
		d^=d<<1;
		d&=0xFFFFFFFFL;
		return d;
	}
	
	protected static long GetKeyId(PublicKey K) throws Exception {
		RSAPublicKey L = (RSAPublicKey) K;
		
		BigInteger a =	L.getPublicExponent();
		BigInteger b = L.getModulus();
				
		byte[] t0 =md5a( new byte[][] { a.toByteArray() , b.toByteArray() });
		long uid=0;
		for (int ax=0;ax<8;ax++) {
			uid<<=8;
			uid|=(long)(255&t0[ax]);
			}
		uid&=0x7FFFFFFFFFFFFFFFL;
		return uid;
		}
	
	protected static byte[] Public2Arr(PublicKey pub) throws Exception {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				pub.getEncoded());
				
		return x509EncodedKeySpec.getEncoded();
		
	}
	
	protected static KeyPair RSAKeyGen(int bits) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(bits);
		KeyPair me = keyGen.genKeyPair();
		return me;
	}
	
	protected static long NewRndLong() {
		try {
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");		
		return random.nextLong();
		} catch(Exception E) {
			return ((long) (Math.random()*Math.pow(2, 62)) ^ System.currentTimeMillis());
		}
		
	}
	
	protected static void NewRnd(byte[] rnd) {
		try {
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");		
		random.nextBytes(rnd);
		} catch(Exception E) {}
		
	}

	public static byte[] MxAccuShifter(byte[][] dta,int magic) throws Exception { return MxAccuShifter(dta, magic,false); 	}
	

	public static void Poke(int addr,int valu, byte[] ram) {
		ram[addr] = (byte)(255&valu);
		ram[addr+1] = (byte)(255&(valu>>8));
		
	}
	
	public static int Peek(int addr,byte[] ram) {
		int valu = (int)(255&ram[addr]);
		valu|=(int)((255&ram[addr+1])<<8);
		return valu; 
	}
	
	public static void PokeB(int addr,int valu, byte[] ram) {
		ram[addr+1] = (byte)(255&valu);
		ram[addr] = (byte)(255&(valu>>8));
		
	}
	
	public static void PokeX(int addr,long valu,int bytes, byte[] ram) {
		for (int ax=0;ax<bytes;ax++) {
			ram[addr+ax] = (byte)(255&valu);
			valu>>=8;
			}
	}

	public static long PeekX(int addr,int bytes,byte[] ram) {
		long valu=0;
		for (int ax=bytes-1;ax>-1;ax--) {
			valu<<=8;
			valu|=(long)(255&ram[addr+ax]);
			}
		return valu;
	}
	
	public static int PeekB(int addr,byte[] ram) {
		int valu = (int)(255&ram[addr+1]);
		valu|=(int)((255&ram[addr])<<8);
		return valu; 
	}
	public static int sumlen(byte[][] raw) throws Exception {
		int le=0;
		for (int ax=0;ax<raw.length;ax++) le+=raw[ax].length;
		return le;
	}
	
	public static byte[] trimarr(byte[] ar,int sz) throws Exception {
		byte[] o =new byte[sz];
		for (int ax=0;ax<sz;ax++) o[ax]=ar[ax];
				
		return o;
	}
	
	public static byte[] Naccu(int max,int sz) {
		int cx=sz>>4;
		if ((sz&3)!=0) cx++;
		cx*=16;
		if (cx==0) cx=16;
		byte[] raw=new byte[cx];
		Poke(0,0,raw);
		int bp = 6+(max*4);
		Poke(2,bp,raw);
		Poke(4,0,raw);
		return raw;
	}
	
public  static byte[] Stosxm(long[] dta,int[] sz) {
		int mx =0;
		for (int ax=0;ax<sz.length;ax++) mx+=sz[ax];
		
		int bp=0;
				
		byte[] re = new byte[mx];
			
		for (int w=0;w<dta.length;w++)	{
			long dd = dta[w];
			
			for (int al=0;al<sz[w];al++) {
				re[bp++] = (byte)(dd&255);
				dd>>=8;
			}
		}
		
		return re;
		
	}
	public static byte[] Stosxmb(long[] dta,int[] sz) {
		int mx =0;
		for (int ax=0;ax<sz.length;ax++) mx+=sz[ax];
		int bp=0;
		
		byte[] re = new byte[mx];
			
		for (int w=0;w<dta.length;w++)	{
			long dd = dta[w];
			
			for (int al=0;al<sz[w];al++) {
				re[bp++] = (byte)(dd&255);
				dd>>=8;
			}
		}
		
		return re;
		
	}
	public static long[] Lodsxm(byte[] dta,int[] sz) {
		int mx =sz.length;
		
		long[] re = new long[mx];
		int bp=0;
		long dd=0;
		int ebp=0;
		for (int ax=0;ax<mx;ax++) {
			bp=sz[ax]-1;
			dd=0;
			for (int al=0;al<sz[ax];al++) {
				dd<<=8;
				dd^=(long)(dta[ebp+(bp--)]&255);
				
			}
			ebp+=sz[ax];
			
			re[ax] = dd;
		}
		return re;		
	}
	public static byte[] StosxNP(long[] dta,int sz) {
		int mx =dta.length*sz;
		int bp=0;
		
		byte[] re = new byte[mx];
			
		for (int w=0;w<dta.length;w++)	{
			long dd = dta[w];
			
			for (int al=0;al<sz;al++) {
				re[bp++] = (byte)(dd&255);
				dd>>=8;
			}
		}
		
		return re;
		
	}
	
	public static byte[] Stosx(long[] dta,int sz) {
		int mx =dta.length*sz;
				
		int bp=0;
				
		byte[] re = new byte[mx];
			
		for (int w=0;w<dta.length;w++)	{
			long dd = dta[w];
			
			for (int al=0;al<sz;al++) {
				re[bp++] = (byte)(dd&255);
				dd>>=8;
			}
		}
		
		return re;
		
	}
	
	public static long[] Lodsx(byte[] dta,int sz) {
		int mx =(int)Math.floor(dta.length / sz);
		if ((dta.length%sz)!=0) mx++;
		
		long[] re = new long[mx];
		int bp=0;
		long dd=0;
		int ebp=0;
		for (int ax=0;ax<mx;ax++) {
			bp=sz-1;
			dd=0;
			for (int al=0;al<sz;al++) {
				dd<<=8;
				dd^=(long)(dta[ebp+(bp--)]&255);
				
			}
			ebp+=sz;
			
			re[ax] = dd;
		}
		return re;		
	}
	
	public static int[] Lodsxi(byte[] dta,int sz) {
		int mx =(int)Math.floor(dta.length / sz);
		if ((dta.length%sz)!=0) mx++;
		
		int[] re = new int[mx];
		int bp=0;
		int dd=0;
		int ebp=0;
		for (int ax=0;ax<mx;ax++) {
			bp=sz-1;
			dd=0;
			for (int al=0;al<sz;al++) {
				dd<<=8;
				dd^=(int)(dta[ebp+(bp--)]&255);
				
			}
			ebp+=sz;
			
			re[ax] = dd;
		}
		return re;		
	}
	public static byte[] Stosxi(int[] dta,int sz) {
		int mx =dta.length*sz;
				
		int bp=0;
				
		byte[] re = new byte[mx];
			
		for (int w=0;w<dta.length;w++)	{
			int dd = dta[w];
			
			for (int al=0;al<sz;al++) {
				re[bp++] = (byte)(dd&255);
				dd>>=8;
			}
		}
		
		return re;
		
	}
	public static long[] Lodsxc(byte[] dta,int sz,int mx) {
		
		long[] re = new long[mx];
		int bp=0;
		long dd=0;
		int ebp=0;
		for (int ax=0;ax<mx;ax++) {
			bp=sz-1;
			dd=0;
			for (int al=0;al<sz;al++) {
				dd<<=8;
				dd^=(long)(dta[ebp+(bp--)]&255);
				
			}
			ebp+=sz;
			
			re[ax] = dd;
		}
		return re;		
	}


	public static SecretKey GetAESKey(byte[] in) throws Exception {
		SecretKey key = new SecretKeySpec(in, "AES");
		return key;
	}
		
	public static byte[] AESEnc(SecretKey Tk,byte[] IV,byte[] data) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(IV);
		Cipher ecipher = Cipher.getInstance("AES/CBC/NoPadding");
		ecipher.init(Cipher.ENCRYPT_MODE, Tk,iv);
		byte[] enc = ecipher.doFinal(data);
		return enc;
	}
	
	public static byte[] AESDec(SecretKey Tk,byte[] IV,byte[] data) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(IV);
		Cipher ecipher = Cipher.getInstance("AES/CBC/NoPadding");
		ecipher.init(Cipher.DECRYPT_MODE, Tk,iv);
		byte[] enc = ecipher.doFinal(data);
		return enc;
	}
	
	public static SecretKey GetBlowfishKey(byte[] in) throws Exception {
		SecretKey key = new SecretKeySpec(in, "Blowfish");
		return key;
	}
		
	public static byte[] BlowfishEnc(SecretKey Tk,byte[] IV,byte[] data) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(IV);
		Cipher ecipher = Cipher.getInstance("Blowfish/CBC/NoPadding");
		ecipher.init(Cipher.ENCRYPT_MODE, Tk,iv);
		byte[] enc = ecipher.doFinal(data);
		return enc;
	}
	
	public static byte[] BlowfishDec(SecretKey Tk,byte[] IV,byte[] data) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(IV);
		Cipher ecipher = Cipher.getInstance("Blowfish/CBC/NoPadding");
		ecipher.init(Cipher.DECRYPT_MODE, Tk,iv);
		byte[] enc = ecipher.doFinal(data);
		return enc;
	}
	
	  private static byte[] AES2cipher(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        int cx = cipher.getOutputSize(data.length);
        byte[] out = new byte[cx];
        int le1 = cipher.processBytes(data, 0, data.length, out, 0);
        int le2 = cipher.doFinal(out, le1);
        int le3 = le1 + le2;
        byte[] result = new byte[le3];
        System.arraycopy(out, 0, result, 0, result.length);
        return result;
    }
	 
	public static byte[] AESEncMul(byte[] keySpec, byte[] data) throws Exception {
		   int cx = keySpec.length;
		   int round=(int) Math.floor(cx/48);
		   if (round==0) throw new Exception("AESEncMul: Ivalid KeySpec");
		   byte[][] Key = new byte[round][32];
		   byte[][] IV = new byte[round][16];
		   for (int ax=0;ax<round;ax++) {
			   int bp = 48*ax;
			   System.arraycopy(keySpec, bp, Key[ax], 0, 32);
			   System.arraycopy(keySpec, bp+16, IV[ax], 0,16);
		   	}
		   return AESEnc2m(Key,IV,data);
	   }
	
	public static byte[] AESEncMulP(byte[] keySpec, byte[] data) throws Exception {
		   int cx = keySpec.length;
		   int round=(int) Math.floor(cx/48);
		   if (round==0) throw new Exception("AESEncMul: Ivalid KeySpec");
		   byte[][] Key = new byte[round][32];
		   byte[][] IV = new byte[round][16];
		  
		   byte[] keyp = Stdio.sha256(keySpec);
		   byte[] ivp = Stdio.md5a(new byte[][] { keyp, keySpec });
		   
		   data = Stdio.AES2Enc(keyp, ivp, data);
		   
		   for (int ax=0;ax<round;ax++) {
			   int bp = 48*ax;
			   System.arraycopy(keySpec, bp, Key[ax], 0, 32);
			   System.arraycopy(keySpec, bp+16, IV[ax], 0,16);
		   	}
		   return AESEnc2m(Key,IV,data);
	   }
	
	public static byte[] AESDecMulP(byte[] keySpec, byte[] data) throws Exception {
		   int cx = keySpec.length;
		   int round=(int) Math.floor(cx/48);
		   if (round==0) throw new Exception("AESEncMul: Ivalid KeySpec");
		   byte[][] Key = new byte[round][32];
		   byte[][] IV = new byte[round][16];
		  
		   byte[] keyp = Stdio.sha256(keySpec);
		   byte[] ivp = Stdio.md5a(new byte[][] { keyp, keySpec });
		   
		   for (int ax=0;ax<round;ax++) {
			   int bp = 48*ax;
			   System.arraycopy(keySpec, bp, Key[ax], 0, 32);
			   System.arraycopy(keySpec, bp+16, IV[ax], 0,16);
		   	}
		  
		   data=AESDec2m(Key,IV,data);
		   data = Stdio.AES2Dec(keyp, ivp, data);
		   return data;
	   }
	
	public static byte[] AESDecMul(byte[] keySpec, byte[] data) throws Exception {
		   int cx = keySpec.length;
		   int round=(int) Math.floor(cx/48);
		   if (round==0) throw new Exception("AESEncMul: Ivalid KeySpec");
		   byte[][] Key = new byte[round][32];
		   byte[][] IV = new byte[round][16];
		   for (int ax=0;ax<round;ax++) {
			   int bp = 48*ax;
			   System.arraycopy(keySpec, bp, Key[ax], 0, 32);
			   System.arraycopy(keySpec, bp+16, IV[ax], 0,16);
		   	}
		   return AESDec2m(Key,IV,data);
	   }
	
	  
	  public static byte[] AESEnc2m(byte[][] key, byte[][] iv,byte[] data) throws Exception {
		
		byte[][] blo = Stdio.DivBlock(data, 16, false);
		int cx=blo.length;
		int kc = key.length;
		for (int kx=0;kx<kc;kx++) {
			CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
			CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key[kx]), iv[kx]);
			aes.init(true, ivAndKey);
			for (int ax=0;ax<cx;ax++)  aes.processBlock(blo[ax], 0, blo[ax], 0);
			}
		
		data = Stdio.MulBlock(blo, 16);
		blo=null;
        return data;
	  }
	  
	    public static byte[] AESDec2m(byte[][] key, byte[][] iv,byte[] data) throws Exception {
		
		byte[][] blo = Stdio.DivBlock(data, 16, false);
		int cx=blo.length;
		int kc = key.length-1;
		for (int kx=kc;kx>-1;kx--) {
			CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
			CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key[kx]), iv[kx]);
			aes.init(false, ivAndKey);
			for (int ax=0;ax<cx;ax++)  aes.processBlock(blo[ax], 0, blo[ax], 0);
			}
		
		data = Stdio.MulBlock(blo, 16);
		blo=null;
        return data;
	  }
	  
	  public static byte[] AESEnc2(byte[] key, byte[] iv,byte[] data) throws Exception {
       byte[][] blo = Stdio.DivBlock(data, 16, false);
		
        CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(true, ivAndKey);

        int cx=blo.length;
        for (int ax=0;ax<cx;ax++)  aes.processBlock(blo[ax], 0, blo[ax], 0);
        data = Stdio.MulBlock(blo, 16);
        blo=null;
        return data;
	  }
	    
	  public static byte[] AESDec2(byte[] key, byte[] iv,byte[] data) throws Exception {
       byte[][] blo = Stdio.DivBlock(data, 16, false);
		
        CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(false, ivAndKey);

        int cx=blo.length;
        for (int ax=0;ax<cx;ax++)  aes.processBlock(blo[ax], 0, blo[ax], 0);
        data = Stdio.MulBlock(blo, 16);
        blo=null;
        return data;
	  }
	  
	 public static byte[] AES2Enc(byte[] key, byte[] iv,byte[] data) throws Exception {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(true, ivAndKey);
        return AES2cipher(aes, data);
    }
	
	 public static byte[] AES2Dec(byte[] key, byte[] iv,byte[] data) throws Exception {
     try {
		PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(false, ivAndKey);
        return AES2cipher(aes, data);
      } catch(Exception E) {
    	   throw new Exception("!Invalid KEY for data");
       } 
    }
	 	
	public static  boolean RSAVerify(byte[] dta,byte[] sign,PublicKey K) throws Exception {
				
		Signature rsaVerifier = Signature.getInstance ("SHA1WithRSA");
		rsaVerifier.initVerify(K);
		
		rsaVerifier.update(dta);
		return rsaVerifier.verify(sign);
		
	}

	public static byte[] Private2Arr(PrivateKey privateKey) throws Exception {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		return pkcs8EncodedKeySpec.getEncoded();
	}
	
	public static PrivateKey Arr2Private(byte[] sk) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(sk);
		return keyFactory.generatePrivate(privateKeySpec);
	}
	
	public static PublicKey Arr2Public(byte[] data,String algorithm) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(data);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
		}
	
	public static PublicKey Arr2Public(byte[] data) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(data);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
		}
	
		public  static void SaveSKPR(String path,KeyPair keyPair, byte[] pax,boolean priv) throws Exception {

		FileOutputStream F = new FileOutputStream(path);
			
		byte[] sal = new byte[32];
		NewRnd(sal);
		
		F.write(sal);
		
		SecretKey KK = GetAESKey(md5a(
						new byte[][] {
								md5(pax)		,
								sal				}
								))					;
		
		byte[] IV = md5a(
					new byte[][] {
							md5(sal)			,
							md5(pax)			,
							sal					}
							)
					;
		
		PublicKey publicKey = keyPair.getPublic();
		
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		byte[] kt = x509EncodedKeySpec.getEncoded();
		byte[] kb = _ArrPad(kt,16,true);
		
		byte[] m = md5(kb);
		F.write(m);
		
		long[] h = new long[4];
		h[0] = 0x12345678;
		h[1] = kb.length;			
		h[2] = GetKeyId(publicKey);
		h[3] = (int)(65534&Calendar.getInstance().getTimeInMillis());
		h[3] ^=(int)(Math.random()*65535);
		h[3]&=65534;
		if (priv) h[3]|=1;
		
		byte[] t1 = Stosxm(h,KeyPairStruct);
		kt = AESEnc(KK,IV,t1);
		F.write(kt);
		kt = AESEnc(KK,IV,kb);
		F.write(kt);
		
		if (!priv) {
			F.close();
			return;
			}
		
		PrivateKey privateKey = keyPair.getPrivate();
		
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		kt =pkcs8EncodedKeySpec.getEncoded();
		kb = _ArrPad(kt,16,true);
		
		m = md5(kb);
		F.write(m);
		
		h = new long[4];
		h[0] = 0x12345678;
		h[1] = kb.length;			
		h[2] = GetKeyId(publicKey);
		h[3] = priv ? 0x8ec1 : 0x8cc0;
		t1 = Stosxm(h,KeyPairStruct);
		kt = AESEnc(KK,IV,t1);
		F.write(kt);
		kt = AESEnc(KK,IV,kb);
		F.write(kt);
		F.close();
		}
		
		
		public  static  KeyPair LoadSKPR(String path, byte[] pax,int skp) throws Exception {
	
		FileInputStream F = new FileInputStream(path);
		if (skp!=0) F.skip(skp);
		
		byte[] sal = new byte[32];
	
		F.read(sal);
		
		SecretKey KK = GetAESKey(md5a(
						new byte[][] {
								md5(pax)		,
								sal				}
								))					;
		
		byte[] IV = md5a(
					new byte[][] {
							md5(sal)			,
							md5(pax)			,
							sal					}
							)
					;
		
		
		byte[] m = new byte[16];
		F.read(m);
		byte[] hb=new byte[16];
		F.read(hb);
		hb = AESDec(KK,IV,hb);
		long[] h= Lodsxm(hb,KeyPairStruct);
		if (h[0]!=0x12345678) {F.close(); throw new Exception("KEY:1.1.1");}
		boolean priv=false;
		if ((h[3]&1)!=0) priv=true;
		int cx =(int) h[1];
		byte[] kb= new byte[cx];
		F.read(kb);
		byte[] k1 = AESDec(KK,IV,kb);
		byte[] v = md5(k1);
		for (int ax=0;ax<16;ax++) if (v[ax]!=m[ax]) { F.close();  throw new Exception("KEY:1.1.2");}
		byte[] pk = _ArrUPadr(k1);
		byte[] sk = null;
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		 		
		if (priv) {
			
			m = new byte[16];
			F.read(m);
			hb=new byte[16];
			F.read(hb);
			hb = AESDec(KK,IV,hb);
			h= Lodsxm(hb,KeyPairStruct);
			if (h[0]!=0x12345678) { F.close(); throw new Exception("KEY:1.2.1");}
		
		
			cx =(int) h[1];
			kb= new byte[cx];
			F.read(kb);
			byte[] k2 = AESDec(KK,IV,kb);
		    v = md5(k2);
			for (int ax=0;ax<16;ax++) if (v[ax]!=m[ax]) {F.close(); throw new Exception("KEY:1.2.2");}
			sk = _ArrUPadr(k2);		
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(sk);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			F.close();
		 return new KeyPair(publicKey, privateKey);
		}
		F.close();
		
		return new KeyPair(publicKey,null);
	
		}
		
		public  static  byte[] _ArrUPadr(byte[] I) throws Exception {
		int pad = (int) (255&I[0]);
		pad^=(int)((255&I[1])<<8);

		int cx = pad;
		byte[] re = new byte[cx];
		 for (int ax=0;ax<cx;ax++){
			 
			 re[ax]=I[ax+2];
		 }
		
		return re;
	}	
		public static  byte[] _ArrPad(byte[] I,int bsize, boolean rnd) {
			int bp=I.length+2;
			int mx = (int) Math.floor(bp/bsize);
			if ((bp%bsize)!=0) mx++;
			
			byte[] re =new byte[mx*bsize];
			if (rnd) NewRnd(re);
			bp = I.length;	

			re[0] =(byte)(bp&255);
			re[1]=(byte)((bp>>8)&255);
			bp=2;
			for (int ax=0;ax<I.length;ax++) re[bp++]=I[ax];
			return re;
		}
	
	
	public static void file_put_bytes(String name,byte[]  data) throws Exception {
			FileOutputStream fo = new FileOutputStream(name);
			fo.write(data);
			fo.close();
			
		}	
	
	public static byte[] file_get_bytes(String name) throws Exception {
		File file = new File(name);
		long length = file.length();
		if (length>512384) throw new Exception("File Too big");
		
		byte[] data=new byte[(int)length];
		FileInputStream f = new FileInputStream(name);
		
		f.read(data);
		f.close();
		return data;
	}
	
	public static byte[] HexData(String he) {
		byte[] out;
		int cx=he.length();
		int bx=0;
		int dx=0;
		out = new byte[(int)(cx/2)];
		
		for(int ax=0;ax<cx;ax+=2) {
			bx =(int) Long.parseLong(he.substring(ax, ax+2), 16);
			out[dx++]=(byte)(bx&255);
		}
		return out;
	}
	public static  byte[] RSASign(byte[] dta,PrivateKey K) throws Exception {
				
		Signature rsaSigner = Signature.getInstance ("SHA1WithRSA");
		rsaSigner.initSign(K);
		rsaSigner.update(dta);
		byte[] sign = rsaSigner.sign ();
		return sign;
				
	}
	 
    public  static String Dump(byte[] data) {
    	String o = new String();
    	int cx = data.length;
    	int bx;
    	
    	for (int ax=0;ax<cx;ax++) {
    		bx = data[ax] & 255;
    		if (bx<16) o = o + "0";
    		o = o + Integer.toHexString(bx);
    	}
    
    	return o;    	
    }
/*
public static byte[] Test(byte[][] in) {
	String s ="";
	for (int ax=0;ax<in.length;ax++) s+="\n"+Stdio.Dump(in[ax]);
	s=s.trim();
	s=s.replace("\n", "_");
	return s.getBytes();
}
   */
public static byte[] md5a(byte[][] in)  {
		MessageDigest digest;
		try {
		digest = java.security.MessageDigest.getInstance("MD5");
		for (int ax=0;ax<in.length;ax++) digest.update(in[ax]);
		return digest.digest();
		} catch (Exception E) {return new byte[16];}
	}
	
public static byte[] md5(byte[] in)  {
		MessageDigest digest;
		try {
		digest = java.security.MessageDigest.getInstance("MD5");
		digest.update(in);
		return digest.digest();
		} catch (Exception E) {return new byte[16];}
	}

public static byte[] sha1(byte[] data) throws Exception{
    MessageDigest md = MessageDigest.getInstance("SHA-1"); 
    return md.digest(data);
}

public static byte[] sha1a(byte[][] data) throws Exception{
    MessageDigest md = MessageDigest.getInstance("SHA-1"); 
    int cx=data.length;
    for (int ax=0;ax<cx;ax++) md.update(data[ax]);
    return md.digest();
}

 public static byte[] sha512(byte[] a) throws Exception {
	 Digest d = new SHA512Digest();
	 byte[] r = new byte[d.getDigestSize()];
	 d.update(a,0,a.length);
	 d.doFinal(r, 0);
	 return r;	 
 	}

 public static byte[] sha512a(byte[][] a) throws Exception {
	 Digest d = new SHA512Digest();
	 byte[] r = new byte[d.getDigestSize()];
	 int cx=a.length;
	 for (int ax=0;ax<cx;ax++)  d.update(a[ax],0,a[ax].length);
	 d.doFinal(r, 0);
	 return r;	 
 	}
 
  public static byte[] sha256(byte[] a) throws Exception {
	 Digest d = new SHA256Digest();
	 byte[] r = new byte[d.getDigestSize()];
	 d.update(a,0,a.length);
	 d.doFinal(r, 0);
	 return r;	 
 	}

 public static byte[] sha256a(byte[][] a) throws Exception {
	 Digest d = new SHA256Digest();
	 byte[] r = new byte[d.getDigestSize()];
	 int cx=a.length;
	 for (int ax=0;ax<cx;ax++)  d.update(a[ax],0,a[ax].length);
	 d.doFinal(r, 0);
	 return r;	 
 	}

	public static  byte[] RSAEnc(byte[] I,PublicKey you) throws Exception {
		 Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		 cipher.init(Cipher.ENCRYPT_MODE, you);
		 byte[] cipherData = cipher.doFinal(I);
		 return cipherData;
	}

	public  static  byte[] RSADec(byte[] I,PrivateKey my) throws Exception {
		 Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		 cipher.init(Cipher.DECRYPT_MODE, my);
		 byte[] cipherData = cipher.doFinal(I);
		 return cipherData;
	}

		public static  byte[] RSAEncP(byte[] I,PublicKey you) throws Exception {
		 Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		 cipher.init(Cipher.ENCRYPT_MODE, you);
		 byte[] cipherData = cipher.doFinal(I);
		 return cipherData;
	}

	public static  byte[] RSADecP(byte[] I,PrivateKey my) throws Exception {
		 Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		 cipher.init(Cipher.DECRYPT_MODE, my);
		 byte[] cipherData = cipher.doFinal(I);
		 return cipherData;
	}
		public static  byte[][] DivBlock(byte[] dta,int size, boolean padrand) throws Exception  {
		int blo = dta.length / size;
		if ((dta.length%size)!=0) blo++;
		byte[][] blk = new byte[blo][size];
		if (padrand)  NewRnd(blk[blo-1]);
		int cx = blo-1;
		for (int ax=0;ax<cx;ax++) System.arraycopy(dta, size*ax, blk[ax], 0, size);
		System.arraycopy(dta, cx*size, blk[blo-1], 0, dta.length - (cx*size));
		return blk;
		}
	
	public static  byte[] MulBlock(byte[][] blk,int size) throws Exception {
		int cx=blk.length;
		byte[] out = new byte[cx*size];
		for (int ax=0;ax<cx;ax++) System.arraycopy(blk[ax], 0, out, ax*size, size);
		return out;
	}
	public static  byte[] MulBlockT(byte[][] blk,int size,int trim) throws Exception {
		int cx=blk.length;
		byte[] out = new byte[cx*trim];
		for (int ax=0;ax<cx;ax++) System.arraycopy(blk[ax], 0, out, ax*size, trim);
		return out;
	}
	public static byte[] MxAccuShifter(byte[][] arr,int magic,boolean rnd) throws Exception {
		int top =0;
		int obj = arr.length;
		if (obj>255) throw new Exception("_MX:TOOBIG");
		
		for (int ax=0;ax<obj;ax++) top+=arr[ax].length;
		int bp = 5+(obj*2);
		top+=bp;
		int oldtop=top;
		top =( (top>>4) + (((top&15)!=0) ? 1:0))<<4;
		byte[] out = new byte[top];
				
		if (rnd) {
			long t0 = System.currentTimeMillis();
			for (int ax=oldtop;ax<top;ax++) out[ax]=(byte) (255&(((long)( Math.random()*256.0)) ^ (t0>>(ax&31))));
			}
		
		PokeB(0,magic,out);
		PokeB(2,top,out);
		out[4] = (byte)(255&obj);
		
		for (int ax=0;ax<obj;ax++) {
			int dx = arr[ax].length;
			PokeB(5+(ax*2),dx,out);
			System.arraycopy(arr[ax], 0, out, bp, dx);
			bp+=dx;
			}
		return out;
	}
	
	public static byte[][] MxDaccuShifter(byte[] in,int magic) throws Exception {
		int t0 =PeekB(0,in); 
		if (t0!=magic) throw new Exception("_MX:MAGIC "+Integer.toHexString(t0));
		int top = PeekB(2,in);
		if (top>in.length) throw new Exception("_MX:DIM "+top+" "+in.length);
		int obj=(int)(255&in[4]);
		byte[][] out= new byte[obj][];
		int bp = 5+(obj*2);
		for (int ax=0;ax<obj;ax++) {
			int dx = PeekB(5+(ax*2),in);
			if (dx+bp>top) throw new Exception("_MX:OVER");
			out[ax] = new byte[dx];
			System.arraycopy(in, bp,out[ax],0,dx);
			bp+=dx;
		}
		return out;
	}
	
	
	public static byte[] MXImplode(byte[][] arr,int magic32) throws Exception {
		int top =0;
		int obj = arr.length;
		if (obj>255) throw new Exception("_MX:TOOBIG");
		
		for (int ax=0;ax<obj;ax++) top+=arr[ax].length;
		int bp = 7+(obj*2);
		top+=bp;
			
		byte[] out = new byte[top];
		PokeB(2,magic32&65535,out);
		PokeB(0,magic32>>16,out);
		PokeB(4,top,out);
		out[6] = (byte)(255&obj);
		
		for (int ax=0;ax<obj;ax++) {
			int dx = arr[ax].length;
			PokeB(7+(ax*2),dx,out);
			System.arraycopy(arr[ax], 0, out, bp, dx);
			bp+=dx;
			}
		return out;
	}
	
	public static byte[][] MXExplode(byte[] in,int magic32) throws Exception {
		int t0 =PeekB(2,in); 
		t0|= PeekB(0,in)<<16;
		if (t0!=magic32) throw new Exception("_MX:MAGIC");
		int top = PeekB(4,in);

		int obj=(int)(255&in[6]);
		byte[][] out= new byte[obj][];
		int bp = 7+(obj*2);
		for (int ax=0;ax<obj;ax++) {
			int dx = PeekB(7+(ax*2),in);
			if (dx+bp>top) throw new Exception("_MX:OVER");
			out[ax] = new byte[dx];
			System.arraycopy(in, bp,out[ax],0,dx);
			bp+=dx;
		}
		return out;
	}
	
	public static InetSocketAddress Long2Sok(long ip) throws Exception {
		byte[] i = new byte[4];
		i[0] = (byte)(255&ip);
		i[1] = (byte)(255&(ip>>8));
		i[2] = (byte)(255&(ip>>16));
		i[3] = (byte)(255&(ip>>24));
		
		int port = (int)(65535&(ip>>32));
		return new InetSocketAddress(InetAddress.getByAddress(i),port);
		
	} 
	
	public static long Sok2Long(InetSocketAddress A) throws Exception {
		long port = A.getPort();
		port&=65535;
		port=port<<32;
		InetAddress I = A.getAddress();
		byte[] b = I.getAddress();
		long r =0;
		r = (long) (255&b[0]);
		r|=(long)((255&b[1])<<8);
		r|=(long)((255&b[2])<<16);
		r|=(long)((255&b[3])<<24);
		r|=port;
	
		return r;
	}
			
	
	public static void echo(String st) { System.out.print(st); }
	
	public void DBG(String M) {
		System.out.print("DBG: "+this.getClass().getSimpleName()+"\t "+M+"\n");
		}
	
	public  static void EXC(Exception E,String dove) {
		echo("\n\nException: "+dove+" = "+E.toString()+"\n"+E.getMessage()+"\n"+E.getLocalizedMessage()+"\n");
							StackTraceElement[] S = E.getStackTrace();
							for (int ax=0;ax<S.length;ax++) echo("STACK "+ax+":\t "+S[ax].toString()+"\n");
		}
	
	
	protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
