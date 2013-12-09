package org.tramaci.onionmail;

import java.util.HashMap;

import javax.crypto.SecretKey;

public class SrvManifest {
	public HashMap<String,String> H=new  HashMap<String,String>();
	public HashMap<String,String> I=new  HashMap<String,String>();
	public HashMap<String,String> N=new  HashMap<String,String>();
	public String Onion="";
	public boolean exit=false;
	public String ExitDomain="";
	
	SrvManifest() {}
	
	SrvManifest(byte[] b) throws Exception {
		int m = Stdio.PeekB(0, b);
		if (m!=0x0701 && m!=0x0703) throw new Exception("Invalid Manifest bytes");
		if (m==0x0703) exit=true;
		byte[][] r = Stdio.MxDaccuShifter(b, m);
		H = J.HashMapUnPack(r[0]);
		I = J.HashMapUnPack(r[1]);
		N = J.HashMapUnPack(r[2]);
		Onion = new String(r[3]);
		ExitDomain=new String(r[4]);
		}
	
		SrvManifest(SMTPReply Re,String remo) throws Exception {
			String[][] HR = J.SplitChunkLines(Re.Msg, 4,Const.Manifest_Splitter,"Too many Manifest sections for `"+remo+"`");
			if (HR.length==0) throw new PException("Invalid Manifest for `"+remo+"`");
			
			H = J.ParseHeaders(HR[0]);
			
			if (HR.length>2) {
				I = J.ParseHeaders(HR[2]);
				HashMap <String,String> net = J.ParseHeaders(HR[1]);
				for (String K:net.keySet()) {
					String v = net.get(K);
					if (!v.matches("[a-z2-7]{16}\\.onion") || !K.matches("[a-z0-9\\-\\_\\.]{2,40}\\.[a-z0-9]{2,5}") || K.endsWith(".onion")) {
						throw new PException("Invalid manifest exit/onion `"+K+"`->`"+v+"` for `"+remo+"`");
						}
					if (N.containsKey(K)) {
						String c = N.get(K);
						c="\n"+c+"\n";
						if (!c.contains("\n"+v+"\n")) {
							c = N.get(K);
							c=c.trim();
							c+="\n"+v;
							N.put(K, c);
							}
						} N.put(K, v);
					}
				}
						
			exit  =false;
			
			if (!H.containsKey("flg") || !H.containsKey("qfdn") || !H.containsKey("manifest")) throw new Exception("Invalid manifest for `"+remo+"`");
						
			String flg = H.get("flg");
			String dom = H.get("qfdn");
			dom=dom.toLowerCase().trim();
			//if (flg.contains("X") && !flg.contains("R")) exit=true;
			if (dom.endsWith(".onion")) exit=false; else if (dom.length()>4) exit=true;
			if (exit) ExitDomain = dom;
	
			Onion = remo.toLowerCase().trim();
		}
				
	public byte[] getBytes() throws Exception {
		byte[][] X = new byte[][] {
					J.HashMapPack(H),
					J.HashMapPack(I),
					J.HashMapPack(N),
					Onion.getBytes(),
					ExitDomain.getBytes() }
					;
		
		byte[] r = Stdio.MxAccuShifter(X, 0x0701, true);
		Stdio.PokeB(0, 0x0701 ^ (exit ? 2:0), r);
		return r;
	}
	
}

