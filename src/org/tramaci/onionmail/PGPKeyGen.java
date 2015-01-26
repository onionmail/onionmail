/*
 * Copyright (C) 2014 by Tramaci.Org
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

import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

public class PGPKeyGen {
	public static int DEFAULT_S2KCOUNT = 192;
	public static int DEFAULT_CERTAINTRY = 128; //80;
	public static int DEFAULT_BITS = 2048;
	public static BigInteger DEFAULT_PUBEXP= BigInteger.valueOf(0x10001);
	public static int DEFAULT_PASS_SIZE=80;
	public static int DEFAULT_PASS_STRANGE=80;
	
	public static String KeyGen(Date when, String ID,OutputStream Public, OutputStream Private) throws Exception {
		
		String pwl = J.GenPassword(DEFAULT_PASS_SIZE, DEFAULT_PASS_STRANGE);
		PGPKeyRingGenerator kg = generateKeyRingGenerator(ID, pwl.toCharArray(),when);

        PGPPublicKeyRing pkr = kg.generatePublicKeyRing();
        ArmoredOutputStream outStream = new ArmoredOutputStream(Public);
        pkr.encode(outStream);
        outStream.close();
        
        PGPSecretKeyRing skr = kg.generateSecretKeyRing();
        outStream = new ArmoredOutputStream(Private);
        skr.encode(outStream);
        outStream.close();
        
        return pwl;
	}
	
    public static PGPKeyRingGenerator generateKeyRingGenerator (String id, char[] pass, int s2kcount,int nBits,int certainty,Date when) throws Exception {
    	
        RSAKeyPairGenerator  kpg = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters kgp = new RSAKeyGenerationParameters (DEFAULT_PUBEXP,new SecureRandom(), nBits, certainty);
        kpg.init(kgp);
        PGPKeyPair rsakpSign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), when);
        PGPKeyPair rsakpEnc =  new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), when);
        PGPSignatureSubpacketGenerator signhashgen =  new PGPSignatureSubpacketGenerator();
                
        signhashgen.setKeyFlags (
        			false, 
        			KeyFlags.SIGN_DATA		|
        			KeyFlags.CERTIFY_OTHER	)
        			;
        
        signhashgen.setPreferredSymmetricAlgorithms(false, new int[] {
        		SymmetricKeyAlgorithmTags.CAST5,
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.TWOFISH,
                SymmetricKeyAlgorithmTags.AES_128	})
                ;
        
        signhashgen.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA1,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA224   })
                ;
        
        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
        enchashgen.setKeyFlags(
        			false, 
        			KeyFlags.ENCRYPT_COMMS		|
        			KeyFlags.ENCRYPT_STORAGE	)
        			;
		
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
       
        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, s2kcount)).build(pass);
               
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
        		PGPSignature.POSITIVE_CERTIFICATION, 
        		rsakpSign, 
        		id, 
        		sha1Calc, 
        		signhashgen.generate(), 
        		null,
        		new BcPGPContentSignerBuilder(
        				rsakpSign.getPublicKey().getAlgorithm(),
        				HashAlgorithmTags.SHA1),
        				pske)
        				;
        
        keyRingGen.addSubKey(rsakpEnc, enchashgen.generate(), null);
        return keyRingGen;
    }
    
    public static PGPKeyRingGenerator generateKeyRingGenerator (String id, char[] pass, Date when) throws Exception {
		return generateKeyRingGenerator(id, pass, DEFAULT_S2KCOUNT, DEFAULT_BITS, DEFAULT_CERTAINTRY,when); 
		}
}
