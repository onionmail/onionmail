package org.tramaci.onionmail;

import java.util.HashMap;

import javax.crypto.SecretKey;

public class SrvManifest {
	public HashMap<String,String> H=new  HashMap<String,String>();
	public HashMap<String,String> I=new  HashMap<String,String>();
	private HashMap<String,String> N=new  HashMap<String,String>();
	public ExitRouterInfo[] network=null;
	public ExitRouterInfo my = new ExitRouterInfo();
	
	public HashMap <String,String> getHashMap(int mode) {
		HashMap<String,String> rs=new  HashMap<String,String>();
		ExitRouterInfo[] fl = ExitRouteList.queryFLTArray(network, mode);
		int j = fl.length;
		for (int i=0;i<j;i++) rs.put(fl[i].domain,fl[i].onion); 
		return rs;
	}
	
	SrvManifest() {
		network = new ExitRouterInfo[0];
		}
	
	SrvManifest(byte[] b) throws Exception {
		int m = Stdio.PeekB(0, b);
		if (m!=0x2701 && m!=0x2703) throw new Exception("Invalid Manifest bytes");
		if (m==0x2703) my.isExit=true;
		byte[][] r = Stdio.MxDaccuShifter(b, m);
		H = J.HashMapUnPack(r[0]);
		I = J.HashMapUnPack(r[1]);
		byte[][] net = Stdio.MxDaccuShifter(r[2], 1);
		my = ExitRouterInfo.fromBytes(r[3]);
		int cx = net.length;
		network = new ExitRouterInfo[cx];
		for (int ax=0;ax<cx;ax++) network[ax] = ExitRouterInfo.fromBytes(net[ax]);
		net=null;
		}
	
		SrvManifest(SMTPReply Re,String remo) throws Exception {
			String[][] HR = J.SplitChunkLines(Re.Msg, 4,Const.Manifest_Splitter,"Too many Manifest sections for `"+remo+"`");
			if (HR.length==0) throw new PException("Invalid Manifest for `"+remo+"`");
			
			H = J.ParseHeaders(HR[0]);
			boolean newManifest = false;
			if (!H.containsKey("flg") || !H.containsKey("qfdn") || !H.containsKey("manifest")) throw new Exception("Invalid manifest for `"+remo+"`");
			
			if ( H.get("manifest").compareTo("2.0")==0) newManifest=true;
			
			if (newManifest) {
				if (HR.length<3) throw new Exception("Invalid manifest 2.0 for `"+remo+"`");
				if (!H.containsKey("port") || !H.containsKey("ver")) throw new Exception("Invalid manifest HLDR");
				
				my.port = Config.parseInt(H.get("port"), "Invalid port in manifest", 1, 65535);
				String s = H.get("ver");
				my.canMX = SrvSMTPSession.CheckTormCapab(s, "MX");
				my.canVMAT = SrvSMTPSession.CheckTormCapab(s, "VMAT");
							
				int cx = HR[1].length;
				network = new ExitRouterInfo[cx];
				int bx=0;
				for (int ax=0;ax<cx;ax++) {
						HR[1][ax]=HR[1][ax].trim();
						if (HR[1][ax].length()==0) continue;
						network[bx++]=ExitRouterInfo.fromString(HR[1][ax]);
						if (network[ax]==null) throw new PException("Invalid manifest ExitRouterInfo `"+HR[1][ax]+"` for `"+remo+"`"); 
						}
				ExitRouterInfo[] t8 = new ExitRouterInfo[bx];
				System.arraycopy(network, 0, t8, 0, bx);
				network=null;
				network=t8;
				System.gc();
				
				I = J.ParseHeaders(HR[2]);
				
			} else {
				my.isLegacy=true;
				
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
				}
			my.knowFrom = (int)(System.currentTimeMillis()/1000);
			my.lastCHK=my.knowFrom;
			my.Goods=1;
				
			my.isExit  =false;
			String dom = H.get("qfdn");
			dom=dom.toLowerCase().trim();
			if (dom.endsWith(".onion")) my.isExit=false; else if (dom.length()>4) my.isExit=true;
			if (my.isExit) my.domain = dom; else my.domain = remo.toLowerCase().trim();
			if (!newManifest) {
					network = new ExitRouterInfo[N.size()];
					int ax=0;
					for (String K:N.keySet()) network[ax++] =ExitRouterInfo.fromLegacy(K, N.get(K));
					}
			my.onion = remo.toLowerCase().trim();
		}
				
	public byte[] getBytes() throws Exception {
		int cx=network.length;
		byte[][] net = new byte[cx][];
		for (int ax=0;ax<cx;ax++) net[ax]=network[ax].getBytes();
		
		byte[][] X = new byte[][] {
					J.HashMapPack(H),
					J.HashMapPack(I),
					Stdio.MxAccuShifter(net, 1),
					my.getBytes() }
					;
		
		byte[] r = Stdio.MxAccuShifter(X, 0x2701, true);
		Stdio.PokeB(0, 0x2701 ^ (my.isExit ? 2:0), r);
		return r;
	}
	
}

