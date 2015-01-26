package org.tramaci.onionmail;

import java.util.HashMap;

public class MsgQueueEntry {
		public String MailFrom = null;
		public String MailTo = null;
		public String VMATTo = null;
		public int NextTry = 0;
		public short NumTry = 0 ;
		public long fileId = 0;
		public short stat = 0;
		public byte[] Key = null;
		public HashMap <String,String> HLDR = new HashMap <String,String>();  
		
		public static final short ST_QUEUE=0;
		public static final short ST_SENDING=1;
		public static final short ST_SENT=2;
		public static final short ST_ERROR=3;
		
		private static final int MX_QUEUE=0xf385;
		private static final int[] QueueFMT = new int[] { 4,1,8,1 };
		
		public byte[] Pack() throws Exception {
			return Stdio.MxAccuShifter(new byte[][] {
						Stdio.Stosxm(new long[] { NextTry ,  NumTry, fileId, stat },QueueFMT ) ,
						MailFrom.getBytes() , 
						MailTo.getBytes(),
						VMATTo!=null ? VMATTo.getBytes() : new byte[0] ,
						J.HashMapPack(HLDR), Key	}
						,
						MX_QUEUE,true) 
						;
				}
		
		MsgQueueEntry() {
			long t = System.currentTimeMillis()/1000L;
			t=Long.toString(t,36).hashCode();
			long r = Stdio.NewRndLong() & 0xFFFFFFFF00000000L;
			r^=t;
			fileId=r;
			Key = new byte[128];
			Stdio.NewRnd(Key);
			}
		
		MsgQueueEntry(byte[] in) throws Exception {
			byte[][] F = Stdio.MxDaccuShifter(in, MX_QUEUE);
			long[] L = Stdio.Lodsxm(F[0], QueueFMT);
			MailFrom = new String(F[1]);
			MailTo = new String(F[2]);
			if (F[3].length>0) VMATTo=new String(F[3]);
			NextTry = (int) L[0];
			NumTry = (short) L[1];
			fileId = L[2];
			stat=(short) L[3];
			HLDR = J.HashMapUnPack(F[4]);
			Key = F[5];
			F=null;
			}
		
		public String FileName(SrvIdentity S) {
			int a =(int)(fileId&255);
			a^=S.Subs[a&7][15&S.Subs[(a&7)^7][(a>>4)&15]];
			
			return S.Maildir+"/tmp/M"+ 
					Long.toString(Long.toString(a^fileId,36).hashCode(),36)+
					Long.toString(Long.toString(fileId^fileId<<1,36).toUpperCase().hashCode(),36)+
					Long.toString(a^a<<2,36)+
					".tmp"
					;
			
			}
}
