package org.tramaci.onionmail;

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

public class PGP {
   
    @SuppressWarnings({ "rawtypes", "deprecation" })
	public static byte[] decrypt(byte[] encrypted, InputStream keyIn, char[] password) throws Exception {
        InputStream inb = new ByteArrayInputStream(encrypted);
        InputStream in = PGPUtil.getDecoderStream(inb);
              
        try {
	        PGPObjectFactory pgpF = new PGPObjectFactory(in);
	        PGPEncryptedDataList enc = null;
	        Object o = pgpF.nextObject();
	        if (o==null) throw new Exception("@550 No data in message");
	        
	        if (o instanceof PGPEncryptedDataList)  enc = (PGPEncryptedDataList) o; else enc = (PGPEncryptedDataList) pgpF.nextObject();
	        
	        if (o==null) throw new Exception("@550 No dataList in message");
	        
	        Iterator it = enc.getEncryptedDataObjects();
	        PGPPrivateKey sKey = null;
	        PGPPublicKeyEncryptedData pbe = null;
	        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection( PGPUtil.getDecoderStream(keyIn));
	
	        while (sKey == null && it.hasNext()) {
	            pbe = (PGPPublicKeyEncryptedData) it.next();
	            sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
	        	}
	
	        if (sKey == null) throw new IllegalArgumentException("@550 SecretKey not found");
	        InputStream clear = pbe.getDataStream(sKey, "BC");
	        PGPObjectFactory pgpFact = new PGPObjectFactory(clear);
	        PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();
	        pgpFact = new PGPObjectFactory(cData.getDataStream());
	        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
	        InputStream unc = ld.getInputStream();
	        ByteArrayOutputStream out = new ByteArrayOutputStream();
	
	        int ch;
	        while ((ch = unc.read()) >= 0) { out.write(ch); }
	
	        byte[] rs = out.toByteArray();
	       	try { in.close(); } catch(Exception I) {}
        	try { inb.close(); } catch(Exception I) {}
	        out.close();
	        return rs;
	        
        } catch(Exception E) { 
        	try { in.close(); } catch(Exception I) {}
        	try { inb.close(); } catch(Exception I) {}
        	throw E;
        }
    }

    @SuppressWarnings({ "deprecation" })
	public static byte[] encrypt(byte[] clearData, PGPPublicKey encKey, String fileName,boolean withIntegrityCheck, boolean armor, Date At,int PGPEncryptedDataAlgo) throws Exception {
        if (fileName == null) fileName = PGPLiteralData.CONSOLE;
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        OutputStream out = encOut;
        if (armor) out = new ArmoredOutputStream(out);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut);
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, fileName, clearData.length, At);
        pOut.write(clearData);

        lData.close();
        comData.close();
        if (PGPEncryptedDataAlgo==0) PGPEncryptedDataAlgo =  PGPEncryptedData.CAST5;
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator( PGPEncryptedDataAlgo, withIntegrityCheck, new SecureRandom(), "BC");
        cPk.addMethod(encKey);

        byte[] bytes = bOut.toByteArray();
        OutputStream cOut = cPk.open(out, bytes.length);
        cOut.write(bytes); 
        cOut.close();
        out.close();
        return encOut.toByteArray();
    }

    @SuppressWarnings("rawtypes")
	public static PGPPublicKey readPublicKey(InputStream in) throws Exception {
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);
        Iterator rIt = pgpPub.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();
            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();
                if (k.isEncryptionKey()) return k;
            	}
        }
       throw new IllegalArgumentException("@550 No encryption key");
    }
    
 @SuppressWarnings("deprecation")
	public static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection keyring, long KID, char[] pwl) throws Exception {
        PGPSecretKey pgpkey = keyring.getSecretKey(KID);
        if (pgpkey == null) return null;
        return pgpkey.extractPrivateKey(pwl, "BC");
    	}
    
 public static String FilterPGPNSAsMarker(String armor,String subst) throws Exception {
    	    armor=armor.replace("\r\n", "\n");
    	    armor=armor.replace("\r", "\n");
    	    armor=armor.trim();
    	    String[] line = armor.split("\\n");
    	    String rs="";
    	    int cx = line.length;
    	    boolean asc=false;
    	    for (int ax=0;ax<cx;ax++) {
    	    	String s = line[ax].trim();
    	    	if (s.length()==0) asc=true;
    	    	
    	    	if (asc) {
    	    			rs+=s+"\r\n";
    	    			continue; 
    	    			}
    	    	
    	    	String[] tok = s.split("\\:",2);
    	    	String c = tok[0].trim().toLowerCase();
    	    	if (c.compareTo("comment")==0) continue;
    	    	if (c.compareTo("version")==0) s=tok[0]+": "+subst.trim();
    	    	rs+=s+"\r\n";
    	    	}
    	    return rs;
    } 

 protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
