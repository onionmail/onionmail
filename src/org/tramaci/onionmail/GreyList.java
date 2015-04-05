package org.tramaci.onionmail;

import java.util.zip.CRC32;

public class GreyList {

	public int rServer = 0;
	public int mFrom = 0;
	public int mTo = 0;
	public int time = 0;
	
	GreyList(SrvIdentity Mid,String sRServer,byte[] IP, String sMFrom, String sMTo) {
		String fDom = J.getDomain(sMFrom);
		rServer = hashString(Mid,Stdio.Dump(IP)+":"+sRServer+":"+fDom);
		mFrom = hashString(Mid,sMFrom);
		mTo = hashString(Mid,sMTo);
		time = (int) (System.currentTimeMillis()/60000L);
		}

	public boolean compare(GreyList a) { return a.rServer==rServer && a.mFrom==mFrom && a.mTo==mTo; }
	
	public String hashString() { return Long.toString(rServer,36)+"#"+Long.toString((long)mFrom * (long) mTo,36); }
	
	public static int hashString(SrvIdentity Mid,String s) {
		CRC32 C = new CRC32();
		C.update(s.getBytes());
		C.update(Mid.Subs[6]);
		long l = C.getValue();
		return (int) l &-1;
		}
	
}
