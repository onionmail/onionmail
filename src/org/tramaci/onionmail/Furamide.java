package org.tramaci.onionmail;

import java.io.RandomAccessFile;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import javax.net.ssl.SSLSocketFactory;

public class Furamide extends Thread {
	private boolean running=true;	
	private RandomAccessFile pseudoRam = null;
	private volatile int maxByteTimer= 120000;
	private volatile int noiseInterval=5;
	private volatile boolean maxTransfer=false;
	public volatile static boolean Debug=false;
	
	private volatile boolean heavyNoise = false;
	public byte[][] data=null;
	private long[] time = null;
	public static volatile String furamIDE="FURAMIDE";
	public byte[] toSwap=null;
	public	Furamide(int size,int maxBTimer,int noiseInt,boolean heavy,boolean mt,String file) throws Exception {
		super();
		maxTransfer=mt;
		heavyNoise=heavy;
		noiseInterval=noiseInt;
		maxByteTimer=1000 * maxBTimer;
		if (file!=null) pseudoRam= new RandomAccessFile(file,"r");
		data = new byte[size][];
		time=new long[size];
		for (int a=0;a<size;a++) {
			time[a]=System.currentTimeMillis() +maxByteTimer+ (Stdio.NewRndLong() % 60000);
			data[a]=addRandomNoise();
			}
		
		this.setPriority(Thread.MIN_PRIORITY);
		this.start();
		
	}
	
	public int endProc() {
		int x=0;
		for (int i=0;i<8;i++) {
			byte[] a = new byte[512384];
			a.clone();
			x^=a.length;
			a=genRSA();
			}
				
		byte[][] b = new byte[1024][];
		for (int i=0;i<1024;i++) b[i] = addRandomNoise();
		byte[][] c = new byte[128][];
		for (int i=0;i<128;i++) {
			c[i] = genRSA();
			c.clone();
			x^=c.length;
			}
		byte[][] d = new byte[1024][];
		for (int i=0;i<1024;i++) {
			d[i]=b[i].clone();
			System.gc();
		}
		
		b=c=d=null;
		System.gc();
		return x;
	}
	
	public void close() {
		running=false;
		this.interrupt();
	}
	
	public void run() {
		int c=0;
		boolean f=true;
		while(running) {
			if (f) {
				c=(c+1)%65535;
				if ((c%noiseInterval)==0) noise();
				}
			f=f^true;
			antiSwap();
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
				break;
			}
		}
		
		try { pseudoRam.close(); } catch(Exception I) {}
		pseudoRam=null;
		data=null;
		time=null;
		System.gc();
	}	
	
	private void noise() {
		int j = time.length;
		long tcr=System.currentTimeMillis();
		for (int i=0;i<j;i++) if (tcr>time[i]) {
			data[i] = addRandomNoise();
			time[i] = System.currentTimeMillis()+maxByteTimer+ (Stdio.NewRndLong() % 1000);
			
			if (Debug) Main.echo("Furamide Noise: "+data[i].length+"\n");
			
			System.gc();
			if (!maxTransfer) break;
			}
		
		System.gc();
		if (heavyNoise) {
			toSwap=addRandomNoise();
			if (data.length>0) {
				int r = (int)((0x7FFF&Stdio.NewRndLong()) % data.length);
				toSwap=data[r].clone();
				}
			toSwap=genRSA();
			if (Debug) Main.echo("Furamide HeavyNoise: "+toSwap.length+"\n");
			}
		}
		
	private byte[] addRandomNoise() {
		
		int r = Stdio.NewRndInt(16);
		
		if (pseudoRam!=null) {
			if ((r&1)!=0) try {
				long h = pseudoRam.length();
				long m = h-1024;
				byte[] data = new byte[1024];
				m = Stdio.NewRndLong() % m;
				pseudoRam.seek(m);
				pseudoRam.read(data);
				if (Debug) Main.echo("Furamide DumpFile: "+data.length+"\n");
				return data;
				} catch(Exception e) {}
			r = Stdio.NewRndInt(16);
			}
		
		switch(r) {
		
		case 1:
		case 8:
		case 9:
		case 13:
			return genBootPass();
		case 2:
			return base64();
		case 3:
		case 14:
		case 15:
			return genDump();
		case 4:
		case 6:
		case 7:
		case 12:
			return genRSA();
		case 10:
		case 11:
			return hex();
		default:
			return ramDump();
		}
		
	}
	
	private byte[] genBootPass() {
		String x = "0\r\nTor address: "+J.RandomString(16)+".a$\t\r\nKeyBlock!>\u00c0\u00c3";
		for (int i=0;i<4;i++) x+="\u001f"+J.RandomString(32);
		x+="\r\n";
		return x.getBytes();
	}

	private byte[] base64() {
		byte[] x = new byte[1024];
		String y = J.Base64Encode(x);
		x=y.getBytes();
		return x;
	}
	
	private byte[] hex() { 
		byte[] x= new byte[20];
		return Stdio.Dump(x).getBytes();
	}
	
	private byte[] genDump() {
		byte rawData[][] = {
			new byte[] {
			(byte)0x20, (byte)0x17, (byte)0x40, (byte)0x03, (byte)0x00, (byte)0x36,
			(byte)0xA0, (byte)0x17, (byte)0x00, (byte)0x09, (byte)0xA0, (byte)0x17,
			(byte)0x00, (byte)0xD1, (byte)0x20
			},
			new byte[] {
			(byte)0xE0, (byte)0xFF, (byte)0x00, (byte)0xE0, (byte)0xFF, (byte)0x00,
			(byte)0xE0, (byte)0xFF, (byte)0x00, (byte)0xE0, (byte)0xFF, (byte)0x00,
			(byte)0xE0, (byte)0xFF, (byte)0x00
			},
			new byte[] {
			(byte)0x35, (byte)0x20, (byte)0x0F, (byte)0x40, (byte)0x03, (byte)0xC0,
			(byte)0x6F, (byte)0x00, (byte)0x36, (byte)0x20, (byte)0x0F, (byte)0x40,
			(byte)0x03, (byte)0xC0, (byte)0x1F, (byte)0x00
			},
			new byte[] {
			(byte)0x2B, (byte)0x49, (byte)0xB9, (byte)0x18, (byte)0x2B, (byte)0x49,
			(byte)0xB9, (byte)0x28, (byte)0x2B, (byte)0x49, (byte)0xB9, (byte)0x38,
			(byte)0x2B, (byte)0x49, (byte)0xB9, (byte)0x48
			}
		};

		int r = (int) (Stdio.NewRndLong() &1048575);
		byte[] data = new byte[1+r&4095];
		r = r % rawData.length;
		int s = rawData[r].length;
		int j = data.length;
		for (int a=0;a<j;a++) data[a] = rawData[r][a % s];
		return data;
		} 	
	
	private byte[] genRSA() { // RSA Private KEY artifact generator.
		
		byte[][] keyFromat = new byte[][] {
				new byte[] {
					(byte)0x30, (byte)0x82, (byte)0x04, (byte)0xBC, (byte)0x02, (byte)0x01,
					(byte)0x00, (byte)0x30, (byte)0x0D, (byte)0x06, (byte)0x09, (byte)0x2A,
					(byte)0x86, (byte)0x48, (byte)0x86, (byte)0xF7, (byte)0x0D, (byte)0x01,
					(byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x82,
					(byte)0x04, (byte)0xA6, (byte)0x30, (byte)0x82, (byte)0x04, (byte)0xA2,
					(byte)0x02, (byte)0x01, (byte)0x00, (byte)0x02, (byte)0x82, (byte)0x01,
					(byte)0x01 }
				,
				new byte[] {
					(byte)0x02, (byte)0x03, (byte)0x01, (byte)0x00, (byte)0x01, (byte)0x02,
					(byte)0x82, (byte)0x01, (byte)0x00 }
				,
				new byte[] {
						(byte)0x02, (byte)0x81, (byte)0x81, (byte)0x00 }
				}
			;
		
		int[] pos = new int[] {0 , 0x126 , 0x22f };
		
		byte[] privExp = new byte[256];
		Stdio.NewRnd(privExp);
		int j=1216;
		byte[] RSAKey = new byte[j];
		for (int i=0;i<j;i++) {
			RSAKey[i]^=privExp[i&255];
			int k = 255&privExp[i&255];
			privExp[i&255]^=privExp[k];
			privExp[k]^=RSAKey[i];
			privExp[k]^=(byte)(255&(i^i<<2));
			k^=i^i>>1;
			k^=k<<1;
			k+=i;
			k&=255;
			RSAKey[i]^=k;
		}
		j = pos.length;
		for (int i=0;i<j;i++) System.arraycopy(keyFromat[i], 0, RSAKey, pos[i], keyFromat[i].length);
		return RSAKey;
	}
	
	private byte[]  ramDump() {
		int r =(int)( 1+ (Stdio.NewRndLong() & 4095));
		byte[] x = new byte[r];
		return x;
		} 
		
	private int antiSwap() {
		if (Main.SMTPS==null) return 0;
		int j = Main.SMTPS.length;
		int x=0;
		for (int i=0;i<j;i++) {
			if (Main.SMTPS[i]==null) continue;
			if (Main.SMTPS[i].Identity==null) continue;
			Object[] ob = new Object[] {
					Main.SMTPS[i].Identity.HTTPRootPass,
					Main.SMTPS[i].Identity.KBL,
					Main.SMTPS[i].Identity.PassWd,
					Main.SMTPS[i].Identity.Nick,
					Main.SMTPS[i].Identity.Onion,
					Main.SMTPS[i].Identity.ExitRouteDomain,
					Main.SMTPS[i].Identity.Sale,
					Main.SMTPS[i].Identity.SSK,
					Main.SMTPS[i].Identity.SSLServer,
					Main.SMTPS[i].Identity.Subs,
					Main.SMTPS[i].Identity.logonTempData,
					Main.SMTPS[i].Identity.logonTempString}
				;
			
			for (Object o:ob) try { x^=antiSwap(o); } catch(Exception I) {}
			x^=i;
		}
		
		return x;		
	}
	
	private int antiSwap(Object ob) {
		int x = 0;
		if (ob==null) return 0;
		
		if (ob instanceof SSLSocketFactory) {
			SSLSocketFactory s = (SSLSocketFactory) ob;
			x = s.hashCode();
			return x;
		}
		
		if (ob instanceof byte[][]) {
			byte[][] s = (byte[][]) ob;
			for (byte[] j:s) {
				for (byte i:j) x^=i;
			}
			return x;
		}
		
		if (ob instanceof byte[]) {
			byte[] s = (byte[]) ob;
			for (byte i:s) x^=i;
			return x;
		}
		
		if (ob instanceof String) {
			String s = (String) ob;
			x^=s.contains("\uffff\uffff\uffff\uffff") ? 1:2;
			return x;
			}
		
		if (ob instanceof RSAPrivateKey) {
			RSAPrivateKey s = (RSAPrivateKey) ob;
			x^=s.getPrivateExponent().hashCode();
			x^=s.getModulus().hashCode();
			return x;
		}
		
		if (ob instanceof PrivateKey) {
			PrivateKey s = (PrivateKey) ob;
			x^=s.hashCode();
			return x;
		}
		
	x^=ob.hashCode();
	return x;
	}
	
}
