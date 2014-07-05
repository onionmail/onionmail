/*
 * Copyright (C) 2013 by Tramaci.Org
 * LibSTLS V 1.0 © 2012 by EPTO (A)
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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.TreeMap;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

@SuppressWarnings("deprecation")
public class LibSTLS {

	public static final String BC = "BC";
	public static final String Version = "LibSTLS V 1.1"; 
	
	public static void AddBCProv() { Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); 	} 
	
	public static SSLSocketFactory GetSSLForServer(X509Certificate C,KeyPair KP) throws Exception { //OK
		String passwd=Long.toString(Stdio.NewRndLong(),36);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			char[] pa = passwd.toCharArray();
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            ks.load(null, pa);
            Certificate[] certChain = new Certificate[1];  
           	certChain[0] = C;
           	ks.setKeyEntry("OnionMail", (Key)KP.getPrivate(), pa, certChain);
            keyManagerFactory.init(ks, pa);
            
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(ks);
        
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
					
            SSLSocketFactory sf = ((SSLSocketFactory) sc.getSocketFactory());
            return sf;
	}
	
	public static SSLSocketFactory GetSSLForClient(X509Certificate C) throws Exception {
		SSLContext sc = SSLContext.getInstance("TLS");
		
		TrustManager[] trustAllCerts = new TrustManager[] { 
				    new X509TrustManager() {     
				        public java.security.cert.X509Certificate[] getAcceptedIssuers() { 
				            return null;
				        } 
				        public void checkClientTrusted( 
				            java.security.cert.X509Certificate[] certs, String authType) {
				            } 
				        public void checkServerTrusted( 
				            java.security.cert.X509Certificate[] certs, String authType) {
				        }
				    }
				};
		
		String passwd=Long.toString(Stdio.NewRndLong(),36);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			char[] pa = passwd.toCharArray();
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            ks.load(null, pa);
            Certificate[] certChain = new Certificate[1];  
           	certChain[0] = C;
           	ks.setCertificateEntry("OnionMail", C);
            kmf.init(ks, pa);
            
            sc.init(kmf.getKeyManagers(),trustAllCerts, new java.security.SecureRandom());
            		
            SSLSocketFactory sf = ((SSLSocketFactory) sc.getSocketFactory());
            return sf;
	}
	
	public static SSLSocketFactory GetSSLForClient() throws Exception { //OK
		SSLContext sc = SSLContext.getInstance("TLS");
		
		TrustManager[] trustAllCerts = new TrustManager[] { 
				    new X509TrustManager() {     
				        public java.security.cert.X509Certificate[] getAcceptedIssuers() { 
				            return null;
				        } 
				        public void checkClientTrusted( 
				            java.security.cert.X509Certificate[] certs, String authType) {
				            } 
				        public void checkServerTrusted( 
				            java.security.cert.X509Certificate[] certs, String authType) {
				        }
				    }
				};
		
		String passwd=Long.toString(Stdio.NewRndLong(),36);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			char[] pa = passwd.toCharArray();
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            ks.load(null, pa);
            kmf.init(ks, pa);
            sc.init(kmf.getKeyManagers(),trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory sf = ((SSLSocketFactory) sc.getSocketFactory());
            return sf;
	}
	
	public static SSLSocketFactory GetSSLForClient(X509Certificate C,KeyPair KP) throws Exception {
		SSLContext sc = SSLContext.getInstance("TLS");
		
		TrustManager[] trustAllCerts = new TrustManager[] { 
				    new X509TrustManager() {     
				        public java.security.cert.X509Certificate[] getAcceptedIssuers() { 
				            return null;
				        } 
				        public void checkClientTrusted( 
				            java.security.cert.X509Certificate[] certs, String authType) {
				            } 
				        public void checkServerTrusted( 
				            java.security.cert.X509Certificate[] certs, String authType) {
				        }
				    }
				};
		
		String passwd=Long.toString(Stdio.NewRndLong(),36);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			char[] pa = passwd.toCharArray();
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            ks.load(null, pa);
            Certificate[] certChain = new Certificate[1];  
           	certChain[0] = C;
           	ks.setKeyEntry("OnionMail",(Key) KP.getPrivate(),pa, certChain);
           	
            kmf.init(ks, pa);
            
            sc.init(kmf.getKeyManagers(),trustAllCerts, new java.security.SecureRandom());
            		
            SSLSocketFactory sf = ((SSLSocketFactory) sc.getSocketFactory());
           
            return sf;
	}

	public static SSLSocket ConnectSSL(Socket con,SSLSocketFactory sf,String Host) throws Exception { //OK
	      SSLSocket sslSocket = (SSLSocket) (sf.createSocket(con, Host, con.getPort(), true));
          sslSocket.setUseClientMode(true);
          String tmp = "";
          String[] cs = sslSocket.getSupportedCipherSuites();
          int cx = cs.length;
          for (int ax=0;ax<cx;ax++) {
        	  	if (!cs[ax].contains("_anon_")) tmp+=cs[ax]+"\n";
          		}
            tmp=tmp.trim();
            cs=tmp.split("\\n+");
            sslSocket.setEnabledCipherSuites(cs);
            try {
            	sslSocket.startHandshake();
            	} catch(Exception E) {
            		if (E.getMessage().toLowerCase().contains("could not generate dh keypair")) {
            				throw new PException("JAVA SSL BUG: JDK-7044060 Update your JDK!"); 
            		} else throw E;
            	}
            return sslSocket;
	}
	
	public static SSLSocket AcceptSSL(Socket con,SSLSocketFactory sf,String Host) throws Exception { //OK
	        SSLSocket sslSocket = (SSLSocket) (sf.createSocket(con, Host, con.getPort(), true));
            sslSocket.setUseClientMode(false);
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
            sslSocket.startHandshake();
            return sslSocket;
	}

	public static KeyPair RSAKeyGen(int bits) throws Exception { //OK
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(bits, new SecureRandom());
        return  kpGen.generateKeyPair();
        
	}
	
	public static  javax.security.cert.X509Certificate[] getCert(SSLSocket sslSocket) throws Exception { //OK
		SSLSession X = sslSocket.getSession();
		javax.security.cert.X509Certificate[] Y = X.getPeerCertificateChain();
		return Y;
	}
	/*
	public static String GetRemoteOnion(X509Certificate cert,KeyPair TK) throws Exception {
		
		BigInteger ID = cert.getSerialNumber();
		byte[] id = ID.toByteArray();
		byte[] tmp = new byte[id.length-1];
		System.arraycopy(id, 1,tmp, 0,id.length-1);
		tmp = Stdio.RSADecP(tmp,TK.getPrivate());
		String dts = new String(tmp);
		dts = dts.trim();
		if (!dts.endsWith(".onion")) return null;
		return dts.toLowerCase();
		
	}
	
	public static boolean isCertForMe(X509Certificate cert,String myonion) throws Exception {
		BigInteger ID = cert.getSerialNumber();
		byte[] id = ID.toByteArray();
		String dts = Stdio.Dump(Stdio.md5a(new byte[][] { id, myonion.getBytes() }))+".";
		String x = cert.getIssuerDN().getName();
		return x.contains(dts);
	}
	*/
	public static PublicKey getPublicKey(X509Certificate C) throws Exception { return C.getPublicKey(); } //OK
	/*
	public static X509Certificate CreateDynaCert(KeyPair KP,PublicKey TK,String OnionFrom,String OnionTo,long Dfrom, int secs) throws Exception {
		long Secs = secs*1000L;
		
		if (Dfrom==0) {
			Dfrom = Stdio.NewRndLong() & 33554432L;
			Dfrom +=2764800L;
			Dfrom *= 1000L;
			Dfrom = System.currentTimeMillis() - Dfrom;
			Secs = Stdio.NewRndLong() & 33554432L;
			Secs +=2764800L;
			Secs *= 1000L;
			Secs = System.currentTimeMillis() + Secs;
			} else Secs+=Dfrom;
		
		OnionFrom = OnionFrom.trim().toLowerCase();
		OnionTo = OnionTo.trim().toLowerCase();
		
		byte[] tmp = Stdio.RSAEncP(OnionFrom.getBytes(), TK);
		byte[] id = new byte[ tmp.length +1];
		System.arraycopy(tmp, 0, id, 1, tmp.length);
		id[0] = 0x1a;
		
		String dts = Stdio.Dump(Stdio.md5a(new byte[][] { id, OnionTo.getBytes() }));
			        
			Date startDate = new Date(Dfrom);              // time from which certificate is valid
			Date expiryDate = new Date(Secs);             // time after which certificate is not valid
			BigInteger serialNumber = new BigInteger(id);     // serial number for certificate
			KeyPair keyPair = KP;             // EC public/private key pair
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			X500Principal dnName = new X500Principal("CN="+dts+"."+Long.toString(Math.abs(Stdio.NewRndLong()),36)+".com");
			
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(dnName);                       // note: same as issuer
			certGen.setPublicKey(KP.getPublic());
			certGen.setSignatureAlgorithm("SHA1withRSA");
			
			X509Certificate cert = certGen.generate(keyPair.getPrivate());
			
			return cert;			
	}
	*/
	public static void SaveCert(String file,byte[] pass,X509Certificate cert) throws Exception {
		byte[] Sale = new byte[16];
		Stdio.NewRnd(Sale);
		SecretKey K = Stdio.GetAESKey(Stdio.md5a( new byte[][] { Sale, pass }));
		byte[] IV = Stdio.md5a( new byte[][] { Sale , pass, Sale });
		byte[] r = Stdio.MxAccuShifter(new byte[][] { cert.getEncoded() },0xf380,true);
		r = Stdio.AESEnc(K, IV, r);
		K=null;
		IV=null;
		r = Stdio.MxAccuShifter(new byte[][] {Sale, r}, 0x91ae,true);
		Stdio.file_put_bytes(file, r);
		}
	
	public static X509Certificate LoadCert(String file,byte[] pass) throws Exception {
		byte[] r = Stdio.file_get_bytes(file);
		byte[][] f = Stdio.MxDaccuShifter(r,0x91ae);
		byte[] Sale  = f[0].clone();
		SecretKey K = Stdio.GetAESKey(Stdio.md5a( new byte[][] { Sale, pass }));
		byte[] IV = Stdio.md5a( new byte[][] { Sale , pass, Sale });
		r = Stdio.AESDec(K, IV, f[1]);
		K=null;
		IV=null;
		f = Stdio.MxDaccuShifter(r, 0xf380);
		CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
		X509Certificate cert2 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(f[0]));
		return cert2;	
	} 
	
	public boolean isAnOnionMailCertificate(X509Certificate C,String onion) throws Exception {
		BigInteger ser = C.getSerialNumber();
		byte[] sr = ser.toByteArray();
		ser=null;
		if (sr[0]!=0x7C) return false;
		byte[] tx = Stdio.md5(onion.getBytes());
		for (int ax=0;ax<16;ax++) if (sr[ax+1]!=tx[ax]) return false;
		return true;
	}
	
	public static X509Certificate CreateCert(KeyPair KP,String onion,long Dfrom, long Dto, String info) throws Exception { //OK
	        
        byte[] bi  = Stdio.md5(onion.getBytes());
        byte[] bx = new byte[bi.length+9];
        System.arraycopy(bi, 0, bx, 1, bi.length);
        bx[0] =0x7C;
        byte[] tmp = Stdio.Stosx(new long[] { Dfrom/1000L , Dto/1000L },4);
        int bp=17;
        for (int ax=0;ax<8;ax++) bx[bp++] = tmp[ax];
                
			Date startDate = new Date(Dfrom);              // time from which certificate is valid
			Date expiryDate = new Date(Dto);             // time after which certificate is not valid
			BigInteger serialNumber = new BigInteger(bx);     // serial number for certificate
			KeyPair keyPair = KP;             // EC public/private key pair
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			if (info!=null && info.length()>0) info=", "+info; else info="";
			X500Principal dnName = new X500Principal("CN="+onion+info);
			
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(dnName);                       // note: same as issuer
			certGen.setPublicKey(KP.getPublic());
			certGen.setSignatureAlgorithm("SHA256WithRSAEncryption"); //SHA1withRSA");
			
			X509Certificate cert = certGen.generate(keyPair.getPrivate(),"BC");
		
			return cert;
	}

	public static String GetCertHash(X509Certificate cert) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
    	byte[] der = cert.getEncoded();
    	md.update(der);
    	byte[] digest = md.digest();
		return Stdio.Dump(digest);
	}
	
	public static byte[] CCert2Arr(javax.security.cert.X509Certificate[] C) throws Exception {
		int cx = C.length;
		byte[][] raw = new byte[cx][];
		byte[][] fmt = new byte[cx][];
		for (int ax=0;ax<cx;ax++) {
				PublicKey K = C[ax].getPublicKey();
				fmt[ax] = K.getAlgorithm().getBytes();
				raw[ax] = K.getEncoded();
				}
		
		raw = new byte[][] {
					Stdio.MxAccuShifter(raw,1)	,
					Stdio.MxAccuShifter(fmt,2)		}
					;
		
		byte[] re = Stdio.MxAccuShifter(raw, Const.MX_CertChain);
		raw = null;
		return re;
		}
	
	public static byte[][] ExtractChain(byte[] in) throws Exception {
		byte[][]	key= Stdio.MxDaccuShifter(in, Const.MX_CertChain);
		//byte[][]	fmt= Stdio.MxDaccuShifter(key[1], 2);
						key= Stdio.MxDaccuShifter(key[0],1);
		return key;
		}
	
	public static PublicKey[] ExtractChainK(byte[] in) throws Exception {
		byte[][]	key= Stdio.MxDaccuShifter(in, Const.MX_CertChain);
		byte[][]	fmt= Stdio.MxDaccuShifter(key[1], 2);
						key= Stdio.MxDaccuShifter(key[0],1);
						
		int cx= key.length;
		PublicKey[] P = new PublicKey[cx];
		for (int ax=0;ax<cx;ax++) P[ax]=Stdio.Arr2Public(key[ax], new String(fmt[ax]));
		return P;
	}
	/*
	public static void VerifyChainOld (byte[] in,javax.security.cert.X509Certificate[] C,String host) throws Exception {
		byte[][]	key= Stdio.MxDaccuShifter(in, Const.MX_CertChain);
		byte[][]	fmt= Stdio.MxDaccuShifter(key[1], 2);
						key= Stdio.MxDaccuShifter(key[0],1);
						
		int cx = key.length;
		if (cx!=C.length) throw new Exception("@500 SSL_CERT: Chain length not equal for `"+host+"`");
		for (int ax=0;ax<cx;ax++) {
			try {
				PublicKey P = Stdio.Arr2Public(key[ax], new String(fmt[ax]));
				C[ax].verify(P);
				C[ax].checkValidity();
				C[ax].verify(C[ax].getPublicKey());
				} catch(Exception E) {
					String m = E.getMessage();
					throw new Exception("@500 SSL_CERT: "+m+" for `"+host+"`");
				}
			}
		}
	*/
	public static boolean CmpsbAB(byte[][] A,byte[][] B) throws Exception {
		int cax = A.length;
		int cbx = B.length;
		if (cbx!=cax) return false;
		boolean[] cmp = new boolean[cax];
		for (int ax=0;ax<cax;ax++) {
			if (!cmp[ax]) for (int bx=0;bx<cbx;bx++) {
				cmp[ax]|= Arrays.equals(A[ax], B[bx]);
				if (cmp[ax]) break;
				}
			}
	cbx=0;
	for (int ax=0;ax<cax;ax++) if (cmp[ax]) cbx++;
	return cbx==cax;
	}
	
	public static void VerifyChain (byte[] in,javax.security.cert.X509Certificate[] C,String host) throws Exception {
		byte[][]	key= Stdio.MxDaccuShifter(in, Const.MX_CertChain);
	//	byte[][]	fmt= Stdio.MxDaccuShifter(key[1], 2);
						key= Stdio.MxDaccuShifter(key[0],1);
						
		int cx = key.length;
		if (cx!=C.length) throw new Exception("@500 SSL_CERT: Chain length not equal for `"+host+"`");
		byte[][] crt = new byte[cx][];
		int stat=0;
		for (int ax=0;ax<cx;ax++) {
			try {
				PublicKey P = C[ax].getPublicKey();
				stat=1;
				C[ax].verify(P,"BC");
				stat=2;
				C[ax].checkValidity();
				stat=3;
				crt[ax]=Stdio.Public2Arr(P);
						//Stdio.Arr2Public(key[ax], new String(fmt[ax]));				
				} catch(Exception E) {
					E.printStackTrace();
					String m = E.getMessage();
					throw new Exception("@500 SSL_CERT: "+m+" for `"+host+"` ST=`"+stat+"`");
				}
			}
		
		if (!CmpsbAB(key,crt)) throw new Exception("@500 SSL_CERT: Public Keys do not match for `"+host+"`");
		
		}
		
	
	
	public static byte[] CertHash(javax.security.cert.X509Certificate[] C,String Host) throws Exception {
		if (C.length==0) {
			return Stdio.sha1a(new byte[][] {
					Host.toLowerCase().getBytes()		,
					C[0].getEncoded()							})
					;
			
			}
		
		TreeMap<String, byte[]> XY = new TreeMap<String, byte[]>();
		int cx = C.length;
		for (int ax=0;ax<cx;ax++) {
			byte[] raw= C[ax].getEncoded();
			byte[] id = Stdio.md5(raw);
			XY.put(Stdio.Dump(id), raw);
			}
		
		byte[][] raw = new byte[cx+1][];
		raw[0] = Host.toLowerCase().getBytes();
		int ax=1;
		for (String K:XY.descendingKeySet()) raw[ax++] = XY.get(K);
		XY=null;
		byte[] rs = Stdio.sha1a(raw);
		raw = null;
		return rs;
		}

protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}