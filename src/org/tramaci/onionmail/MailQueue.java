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

import java.io.BufferedReader;
import java.io.File;
import java.util.HashMap;

public class MailQueue {
	private SrvIdentity ParentServer= null;
	
	public String[] QueueFiles = null;
	public int[] QueueNext = null;
	public long LastSaved  = 0;
	
	private static final int MX_QUEUEFILE = 0xf380;
	private static final int MX_QUEUE = 0x8ec1;
	
	MailQueue(SrvIdentity S) throws Exception {
		ParentServer=S;
		if (S.Config.MaxQueueSize>255) throw new Exception("MailQueu too big!");
		QueueFiles=new String [S.Config.MaxQueueSize];
		QueueNext=new int [S.Config.MaxQueueSize];
		for (int ax=0;ax<S.Config.MaxQueueSize;ax++) QueueFiles[ax]="";
		}
	
	public int getNext() {
		int tcr = (int) (System.currentTimeMillis()/1000L);
		int cx = QueueNext.length;
		for (int ax=0;ax<cx;ax++) {
			if (QueueNext[ax]!=0 && tcr>QueueNext[ax]) return ax;
			}
		return -1;
	}
	
	public MsgQueueEntry UnQueue(int id) throws Exception {
		byte[] b = Stdio.file_get_bytes(QueueFiles[id]);
		J.Wipe(QueueFiles[id], ParentServer.Config.MailWipeFast);
		QueueFiles[id]="";
		QueueNext[id]=0;
		byte[][] F = Stdio.MxDaccuShifter(b, MX_QUEUEFILE);
		byte[] k = J.Der2048(F[0], ParentServer.Sale);
		b=Stdio.AESDecMulP(k,F[1]);
		try { AutoSave(); } catch(Exception E) { ParentServer.Config.EXC(E, ParentServer.Nick+".UnQueueAutoSave"); }
		return new MsgQueueEntry(b);
		}
	
	public void AutoSave() throws Exception {
		long t = System.currentTimeMillis() - LastSaved;
		if (t<2000) return;
		Save();
	}
	
	public void Save() throws Exception {
		byte[] d = Stdio.MxAccuShifter(new byte[][] {
			J.PackStringArray(QueueFiles),
			Stdio.Stosxi(QueueNext, 4)	}, MX_QUEUE, true ) 
			;
		byte[] k = J.Der2048(ParentServer.Sale,ParentServer.Subs[4]);
		d = Stdio.AESEncMulP(k, d);
		k=null;
		Stdio.file_put_bytes(ParentServer.Maildir+"/tmp/queue", d);
		d=null;
		LastSaved=System.currentTimeMillis();
		}
	
	public void Load() throws Exception {
		String sf = ParentServer.Maildir+"/tmp/queue";
		if (!new File(sf).exists()) return;
		byte[] k = J.Der2048(ParentServer.Sale,ParentServer.Subs[4]);
		byte[] b = Stdio.file_get_bytes(sf);
		b = Stdio.AESDecMulP(k, b);
		k=null;
		byte[][] F = Stdio.MxDaccuShifter(b,MX_QUEUE);
		b=null;
		QueueFiles = J.UnPackStringArray(F[0]);
		QueueNext = Stdio.Lodsxi(F[1], 4);
		}
	
	private int getNewQueue() throws Exception {
		int cx = QueueFiles.length;
		for (int ax=0;ax<cx;ax++) {
			if (QueueNext[ax]==0) return ax;
			}
		throw new Exception("@550 Queue Full");
	}
	
	public void Enqueue(String mailFrom,String mailTo ,String VMATTo, HashMap <String,String> HLDR,BufferedReader I) throws Exception { //Remember to send 220!
		int newi = getNewQueue();
		MsgQueueEntry ent = new MsgQueueEntry();
		ent.MailFrom=mailFrom;
		ent.MailTo=mailTo;
		ent.VMATTo=VMATTo;
		ent.NextTry =(int)((System.currentTimeMillis()/1000L)+(ParentServer.RetryTime*60)); 
		ent.HLDR=HLDR;
		ent.HLDR.put("x-enqueued",ParentServer.TimeString()+" by "+ ParentServer.Onion);
		MailBoxFile Ms = new MailBoxFile();
		Ms.OpenAES(ent.FileName(ParentServer),ent.Key,true);
		int MessageBytes=0;
		while(true) {
			String li = I.readLine();
		
			MessageBytes+=li.length()+2;
			if (MessageBytes>ParentServer.MaxMsgSize) {
				Ms.Close();
				Ms.Destroy(ParentServer.Config.MailWipeFast);
				throw new PException("@452 Message too big");
				}
			if (li.compareTo(".")==0) break;
			Ms.WriteLn(li);
			}
		
		Ms.Close();
		long h = Stdio.NewRndLong();
		int i =QueueFiles.hashCode();
		String fn = ParentServer.Maildir+"/tmp/Q"+Long.toString(h,36)+Long.toString(i,36)+".tmp";
		byte[] tk = new byte[64];
		Stdio.NewRnd(tk);
		byte[] k = J.Der2048(tk, ParentServer.Sale);
		byte[] b = ent.Pack();
		b = Stdio.AESEncMulP(k, b);
		b = Stdio.MxAccuShifter(new byte[][] { tk, b } ,MX_QUEUEFILE,true);
		J.WipeRam(k);
		k=null;
		Stdio.file_put_bytes(fn, b);
		b=null;
		QueueFiles[newi]=fn;
		QueueNext[newi]=ent.NextTry;
		try { AutoSave(); } catch(Exception E) { ParentServer.Config.EXC(E, ParentServer.Nick+".QueueAutoSave"); }
		}
	
}
