package org.tramaci.onionmail;

import java.io.File;

public class GreyListManager {
		
		public static final int GLSTATUS_OK = 0;
		public static final int GLSTATUS_GREYNEW = 1;
		public static final int GLSTATUS_EARLY = 2;
		public static final int GLSTATUS_FULL = 3;
		
		private SrvIdentity srv = null;
		public GreyList[] list = null;
		
		GreyListManager(SrvIdentity s) {
			list = new GreyList[s.Config.GreyMaxEntry];
			srv=s;
			}
			
		public int LookupServer(String sRServer,byte[] IP, String sMFrom, String sMTo) throws Exception {
			GreyList item = new GreyList(srv,sRServer,IP,sMFrom,sMTo);
			int a = item.rServer & 255;
			int b = (item.rServer>>8)&255;
			int c = item.rServer>>16;
			String fn = srv.Maildir+"/data/g"+Integer.toString(a,36)+"/"+Integer.toString(b,36);
			File F = new File(fn);
			if (F.exists()) {
				byte[] lsg = Stdio.file_get_bytes(fn);
				short[] lst = Stdio.Lodsw(lsg);
				for (short x:lst) if (x==c) {
						srv.Log("GreyList: Server Ok");
						return GLSTATUS_OK;
						}
				}
			
			System.gc();
			int free=-1;
			int j = list.length;
			int time = (int)(System.currentTimeMillis()/60000L);
			
			for (int i=0;i<j;i++) {
				if (list[i]!=null && time>(list[i].time+srv.Config.GreyListTTL)) list[i]=null; 
				
				if (list[i]==null && free==-1) free=i;
				if (list[i]==null) continue;
				if (list[i].compare(item)) {
					if (time<list[i].time+srv.Config.GreyListTime) {
						srv.Log("GrayList: Server `"+sRServer+"` early retry Hash=`"+item.hashString()+"`");
						return GLSTATUS_EARLY;
						} else {
						addOkServer(list[i]);
						list[i]=null;
						srv.Log("GrayList: Server `"+sRServer+"` Added to OK list.");
						return GLSTATUS_OK;
						}
					}				
				}
			
			if (free==-1) {
					srv.Log("GreyList: Full, can't store Server=`"+sRServer+"`, Hash=`"+item.hashString()+"`");
					return GLSTATUS_FULL;
				} else {
					list[free] = item;
					srv.Log("GreyList: Server `"+sRServer+"` in greylist Hash=`"+item.hashString()+"`");
					return GLSTATUS_GREYNEW;
				}
			
			}
	
		public synchronized void addOkServer(GreyList item) throws Exception {
			int a = item.rServer & 255;
			int b = (item.rServer>>8)&255;
			int c = item.rServer>>16;
			String path = srv.Maildir+"/data/g"+Integer.toString(a,36);
			String fn = path+"/"+Integer.toString(b,36);
			File F = new File(fn);
			if (F.exists()) {
				byte[] lsg = Stdio.file_get_bytes(fn);
				short[] lst = Stdio.Lodsw(lsg);
				for (short x:lst) if (x==c) return;
				int cx = lst.length;
				short[] lsd = new short[cx+1];
				System.arraycopy(lst, 0, lsd, 0, cx);
				lst=null;
				lsd[cx]=(short) c;
				lsg = Stdio.Stosw(lsd);
				lsd=null;
				Stdio.file_put_bytes(fn, lsg);
				lsg=null;
				System.gc();
				} else {
					F = new File(path);
					F.mkdirs();
					F.mkdir();
					byte[] lsd = Stdio.Stosw(new short[] { (short) c });
					Stdio.file_put_bytes(fn, lsd);	
				}
			} 
}
