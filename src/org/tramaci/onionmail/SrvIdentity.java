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

package org.tramaci.onionmail;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.tramaci.onionmail.DBCrypt.DBCryptIterator;
import org.tramaci.onionmail.MailBox.Message;
import org.tramaci.onionmail.MailingList.MLUserInfo;


public class SrvIdentity {
	public String Nick = "null";
	public String Onion="null.onion";
	public InetAddress LocalIP = null;
	public boolean NewCreated = false;
	
	public boolean CanRelay=false;
	
	public int LocalPort = 25;
	public int LocalPOP3Port = 110;
	
	public String Maildir=null;
	public String Banner="${SERVER} TESMTP ${SOFTWARE} ${DATE}";
	public int MaxMsgSize=1048576;
	public boolean OnlyOnion=false;
	public boolean OnlyOnionFrom=false;
	public boolean OnlyOnionTo=false;
	
	public boolean searchexit=false;
	public String ExitRouteDomain="example.org"; 
	public boolean EnterRoute = false; 
	public int MaxMsgXuser=256;
	public String PassWd=J.GenPassword(80, 80);
		
	public boolean isSSL = false;
	public X509Certificate MyCert = null;
	public SSLSocketFactory SSLClient = null;
	public SSLSocketFactory SSLServer = null;
	public HashMap <String,String> SSlInfo = new HashMap <String,String>();
	
	public long TimerSpoof = 3600000;
	public String TimerSpoofFus="GMT";
	public long TimerSpoofDelta = 600000;
	public long TimerSpoofNextDelta  = 0;
	public long TimerSpoofVibration = 60000;
	public long TimerSpoofMaxEveryDelta = 120000;
	public long TimerSpoofMinEveryDelta = 60000;
	public long TimerSpoofMaxFuture=600000;
	public long TimerSpoofMaxPast=86400000;
	
	public PublicKey SPK = null;
	public PrivateKey SSK = null;
			
	public byte[] Sale = null;
	public byte[][] Subs = null;
	public Config Config;
	public Spam Spam;
	public static final String SpamList="_SPAM_/_LIST@Server";
	
	public int MaxSpamEntryXUser = 128; 
	public int MaxMailingListSize = 1024;
	
	private ScheduledExecutorService executor=null;
	private ScheduledExecutorService StatRun=null;
	
	public boolean FriendOk=false;
	private int LastFriend=0;
	public String DefaultLang="en-en";
	
	public String CVMF380TMP = null;
	public byte[][] CVMF3805TMP = null;
	
	public byte[] KBL = new byte[0];
	
	public int PublicControlPort=9101;
	public InetAddress PublicControlIP=null;
	
	public String ExitNotice=null;
	public boolean ExitNoticeE=true;

	public boolean NewUsersAccept=false;
	public int NewUserMax = 5;
	public int NewUserCount=0;
	public int NewUserDay=0;
	
	public IPList BlackList=null;
	
	public HashMap <String,Integer> ExitEnterPolicyBlock = null;
	public static final int EXP_NoEntry = 1;
	public static final int EXP_NoExit = 2;
		
	public volatile int StatMsgIn =0;
	public volatile int StatMsgOut=0;
	public volatile int StatMsgInet=0;
	public volatile int StatError=0;
	public volatile int StatException=0;
	public volatile int StatSpam=0;
	public volatile int StatPop3=0;
	public volatile int StatHcount=0;
	
	public volatile int StatTor2TorBy = 0;
	public volatile int StatTor2InetBy = 0;
	public volatile int StatInet2TorBy = 0;
	public volatile int StatCurrentM=0;
	public volatile int LastDoFriend = 0;
	
	public boolean NewUsrEnabled = false;
	public int NewUsrMaxXDay = 0;
	public int NewUsrMaxXHour = 0;
	public int NewUsrLastDay = 0;
	public int NewUsrLastDayCnt = 0;
	public int NewUsrLastHour = 0;
	public int NewUsrLastHourCnt = 0;
	
	public boolean NewLstEnabled = false;
	public int NewLstMaxXDay = 0;
	public int NewLstMaxXHour = 0;
	public int NewLstLastDay = 0;
	public int NewLstLastDayCnt = 0;
	public int NewLstLastHour = 0;
	public int NewLstLastHourCnt = 0;
	public long TimeSpoofSubRandom = 0;
	
//	public HashMap <String,String> NextCheck = new HashMap<String,String>();
	public HashMap <String,String> ManifestInfo = new HashMap <String,String>();
	///public HashMap <String,String>  SSLToVerify = new HashMap<String,String>();
	
	public int MaxServerDERKPoint=8;
	
	public HashMap <String,int[]> SrvDerToday= new  HashMap <String,int[]>();
	
	public String StatFile=null;
	
	public String OnTheSameMachine=null;
		
	public int Status = 0;
	public static final int ST_NotLoaded=0;		//A
	public static final int ST_Loaded=1;				//B
	public static final int ST_Running=2;				//C
	public static final int ST_Booting=4;				//D
	public static final int ST_BootOk=8;				//E
	public static final int ST_FriendRun=16;		//F
	public static final int ST_FriendOk=32;			//G
	public static final int ST_Error=64;				//H
	public static final int ST_Ok=128;					//I
	
	public String getStatus() {
		String st="";
		for (int ax=0;ax<8;ax++) if ((Status & 1<<ax)!=0) st+=Integer.toString(10+ax,36);
		return st;
	} 
	
	public void SaveStat() throws Exception {
			StatHcount++;
							
				byte[] c = Stdio.Stosxi(new int[] {
							StatMsgIn,
							StatMsgOut,
							StatError,
							StatException,
							StatMsgInet,
							StatPop3,
							StatSpam,
							StatHcount ,
							StatTor2TorBy,
							StatTor2InetBy,
							StatInet2TorBy,
							StatCurrentM,
							(int)((System.currentTimeMillis()+Config.TimeSpoof)/1000L) } , 4)
							;
		
			c=Stdio.MxAccuShifter(new byte[][] { c }, 0xf385);
			Stdio.file_put_bytes(Maildir+"/stats", c);
			c=null;
			
			if (StatFile==null) return;
			int tcr = (int)((System.currentTimeMillis()+Config.TimeSpoof)/1000L);
			PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(StatFile, true)));
			out.println(
					tcr+";"+
					StatHcount+";"+
					StatMsgIn +";"+
					StatMsgOut+";"+
					StatMsgInet+";"+
					StatError+";"+
					StatException+";"+
					StatSpam+";"+
					StatPop3+";"+
					StatTor2TorBy+";"+
					StatTor2InetBy+";"+
					StatInet2TorBy+";"+
					StatCurrentM )
					;
			out.close();
			
		GregorianCalendar  q = new GregorianCalendar();
    	int ab = q.get(Calendar.MONTH);
    	ab^= q.get(Calendar.YEAR)<<6;
		ab^= ((int)255& this.Sale[0])<<22;
		ab^=ab>>1;
		if (ab!=StatCurrentM) {
			StatCurrentM=ab;
			StatTor2TorBy=0;
			StatTor2InetBy=0;
			StatInet2TorBy=0;
			}
		}
		
	
	SrvIdentity(Config C) { 
			long a = Stdio.NewRndLong() & 0x7FFFFFFFL;
			TimeSpoofSubRandom = a % 3600000L;
			TimeSpoofSubRandom-=	1800000L;
			
			Config=C;
			Spam= null; // new Spam(C,this);
			ManifestInfo.put("info", "1.0");
			
	}
	
	private void StartProcs() throws Exception {
		if (Main.Oper!=0) return;
		if (executor!=null) {
			Log("Hops: Can't run StartProcs with executor!=null!");
			return;
			}
		
		executor= Executors.newSingleThreadScheduledExecutor();
			Runnable ServerOp = new Runnable() {
				public void run() {
					try { 
							DoGarbage();
							int t0 =(int)(System.currentTimeMillis()/1000);
							if (FriendOk && LastDoFriend!=0 && (t0-LastDoFriend)>Config.MaxDoFriendOld) {
								FriendOk=false; //DoFriens!
								LastFriend=0;
								}
							if (!FriendOk) {
									DoFriends(); 
									FriendOk=true;
									LastDoFriend=(int)(System.currentTimeMillis()/1000);
									}
							try { SearchExit(); } catch(Exception EX) { Log(Config.GLOG_Bad,"SearchExit: "+EX.getMessage()); }
							
							if (Main.Oper==0 && Config.UseBootSequence && !new File(Maildir+"/head/boot").exists() && CVMF3805TMP!=null) try {
									CreateBoot();
									} catch(Exception EX) { 
										if (CVMF3805TMP!=null) J.WipeRam(CVMF3805TMP);
										CVMF3805TMP=null;
										String ms = EX.getMessage();
										if (ms.startsWith("@")) Log(Config.GLOG_Server,ms.substring(1)); else Config.EXC(EX, "SCBF2`"+Onion+"`"); 
										}
							
							if (BlackList!=null) try { BlackList.AutoSave(); } catch(Exception EX) { Log(Config.GLOG_Bad,"BlackList AutoSave: "+EX.getMessage()); }
							} catch(Exception E) { Config.EXC(E, "ServerOp"); }
					Status |= SrvIdentity.ST_Ok;
					Log(Config.GLOG_Server,"Server Init Complete. Status `"+getStatus()+"`");
					}
				};

			executor.scheduleAtFixedRate(ServerOp,15/* 60 + (7&Stdio.NewRndLong())*/ ,Config.MessagesGarbageEvery, TimeUnit.SECONDS); //TODO Ripiazzare!
		
			StatRun = Executors.newSingleThreadScheduledExecutor();
			Runnable StatOp = new Runnable() {
				public void run() {
					try { 
							SaveStat();
							} catch(Exception E) { Config.EXC(E, "StatOp"); }
					}
				};
				
			StatRun.scheduleAtFixedRate(StatOp, 1 ,60, TimeUnit.MINUTES);
	}
	
	public static byte[][] CreateSK(String onion) throws Exception {
		byte[][] sk = new byte[][] {
					new byte[32],
					new byte[16],
					new byte[32],
					new byte[16],
					new byte[32],
					new byte[16],
					new byte[0]}
				;
		for (int ax=0;ax<6;ax++) Stdio.NewRnd(sk[ax]);
		sk[6] = onion.toLowerCase().trim().getBytes();
		return sk;
	}
	
	public void Create(byte[][] sk) throws Exception {
				
		File F = new File(Maildir);
		if (!F.exists()) F.mkdirs();
			
		for (String p : new String[] { "", "usr" , "inbox" , "keys" , "log", "feed","head" }) {
			F = new File(Maildir+"/"+p);
			F.mkdir();
			F.setExecutable(true, true);
			F.setReadable(true,true);
			F.setWritable(true, true);
			if (!F.exists()) throw new Exception("Can' create path `"+Maildir+"/"+p+"`");
			}
		
		byte[] rnd = new byte[512];
		Stdio.NewRnd(rnd);
		
		KeyPair GPG = Stdio.RSAKeyGen(2048);
		Sale=rnd.clone();
		SPK = GPG.getPublic();
		SSK = GPG.getPrivate();
		Subs = new byte[16][16];
		for (int ax=0;ax<16;ax++) Stdio.NewRnd(Subs[ax]);
		
		byte[] Head = Stdio.MxAccuShifter(new byte[][] {
					"OnionMail".getBytes(),
					Stdio.md5(Onion.getBytes()),
					rnd,
					Stdio.Public2Arr(GPG.getPublic()),
					Stdio.Private2Arr(GPG.getPrivate()) ,
					Stdio.MxAccuShifter(Subs, 1,true) }
					, Const.MS_Server, true) ;
		
		Head = Stdio.AES2Enc(sk[0], sk[1], Head);
		Head = Stdio.AES2Enc(sk[2], sk[3], Head);
		Head = Stdio.AES2Enc(sk[4], sk[5], Head);
		
		Stdio.file_put_bytes(Maildir+"/head/header", Head);
		GenCert();
	NewCreated=true;	

		byte[] sh = new byte[8];
		Stdio.NewRnd(sh);
		sh = Stdio.MXImplode(new byte[][] {
					"OnionMail".getBytes()	,
					Stdio.Stosx(new long[] { Main.VersionID , Main.getVersion().hashCode() },8) ,
					sh	,
					Stdio.md5a(new byte[][] { sh, Onion.toLowerCase().trim().getBytes() })	,
					new byte[] { 0 ,0 , 0 , 0 }}
					, 0x13c03c09) ;
	
		Stdio.file_put_bytes(Maildir+"/server.bin", sh);
		
	}
	
	public boolean CheckServerPresent() throws Exception {
		if (!new File(Maildir+"/server.bin").exists()) {
				File F = new File(Maildir);
				String[] ls = F.list();
				int cx=ls.length;
				for (int ax=0;ax<cx;ax++) {
					if (ls[ax].startsWith(".")) continue;
					if (ls[ax].endsWith(".txt")) continue;
					if (ls[ax].endsWith(".log")) continue;
					if (ls[ax].endsWith(".csv")) continue;
					if (ls[ax].startsWith("rulez.")) continue;
					if (ls[ax].compareTo("res")==0) continue;
					if (ls[ax].compareTo("!FIXME!")==0) return true;
					throw new Exception("@Server directory error: Unknown content or unsupported server type `"+Maildir+"`");
					}
				return false;
				}
		byte[] sh = Stdio.file_get_bytes(Maildir+"/server.bin");
		byte[][] F = Stdio.MXExplode(sh, 0x13c03c09);
		if (new String(F[0]).compareTo("OnionMail")!=0) throw new Exception("@Not an OnionMail server: `"+Maildir+"`");
		byte[] t = Stdio.md5a(new byte[][] { F[2] , Onion.toLowerCase().trim().getBytes() } );
		if (!Arrays.equals(t, F[3])) throw new Exception("@This is not `"+Onion+"` in path `"+Maildir+"`");
		if (F[4][0]!=0) throw new Exception("@This server is not supported by version `"+Main.getVersion()+"`");
		return true;
	}
	
	public void GenCert() throws Exception {
		
		String at = "";
		if (SSlInfo.containsKey("country")) at+="C="+SSlInfo.get("country")+"\n";
		if (SSlInfo.containsKey("organization")) at+="O="+SSlInfo.get("organization")+"\n";
		if (SSlInfo.containsKey("orgunit")) at+="OU="+SSlInfo.get("orgunit")+"\n";
		if (SSlInfo.containsKey("state")) at+="ST="+SSlInfo.get("state")+"\n";
		at=at.replace(',',' ');
		at=at.trim();
		at=at.replace("\n", ", ");
		
		long TimeFrom = 0; 
		long TimeTo = 0;
		if (SSlInfo.containsKey("from")) TimeFrom = J.parseInt(SSlInfo.get("from"));
		if (SSlInfo.containsKey("to")) TimeTo = J.parseInt(SSlInfo.get("to"));
		
		if (TimeFrom<1) TimeFrom = System.currentTimeMillis() - (86400000L * Math.abs(Stdio.NewRndLong() % 365)+86400000L);
		if (TimeTo<1) TimeTo =  System.currentTimeMillis() + (86400000L * Math.abs(Stdio.NewRndLong() % 365)+315360000000L);
		
		MyCert = LibSTLS.CreateCert(new KeyPair(SPK,SSK), Onion, TimeFrom, TimeTo, at);
		LibSTLS.SaveCert(Maildir+"/head/data", Sale, MyCert);
		
		Main.echo("\n\t"+J.Spaced("New Cert:", 16)+"`"+J.Limited(Onion, 40)+"`");
		Main.echo("\n\t"+J.Spaced("From:", 16)+"`"+J.Limited(new Date(TimeFrom).toString(),40)+"`");
		Main.echo("\n\t"+J.Spaced("To:", 16)+"`"+J.Limited(new Date(TimeTo).toString(), 40)+"`");
		
		for (String K:SSlInfo.keySet()) {
			Main.echo("\n\t"+J.Spaced(K+":", 16)+"`"+J.Limited(SSlInfo.get(K), 40)+"`");
			} 
		Main.echo("\n");
		
	}
	
		
	public void Open(byte[][] sk) throws Exception {
		
		File F = new File(Maildir);
		if (!F.exists()) throw new Exception("Maildir doesn't exist: `"+Maildir+"`");
		for (String p : new String[] {  "usr" , "inbox" , "keys" , "log", "feed","head" }) {
			F = new File(Maildir+"/"+p);
			if (!F.exists()) throw new Exception("Can' open path `"+Maildir+"/"+p+"`");
			}
		
		if (Config.UseBootSequence && !new File(Maildir+"/head/boot").exists()) CVMF3805TMP = sk.clone(); else CVMF3805TMP=null; 
		
		byte[][] Head = new byte[1][];
		Head[0] = Stdio.file_get_bytes(Maildir+"/head/header");
		
		Head[0] = Stdio.AES2Dec(sk[4], sk[5], Head[0]);
		Head[0] = Stdio.AES2Dec(sk[2], sk[3], Head[0]);
		Head[0] = Stdio.AES2Dec(sk[0], sk[1], Head[0]);
		
		try {
			Head = Stdio.MxDaccuShifter(Head[0], Const.MS_Server);
		} catch(Exception E) {
			throw new Exception("Invalid keyblock or password");
			}
		if (new String(Head[0]).compareTo("OnionMail")!=0) throw new Exception("Invalid server header");
		Sale = Head[2].clone();
		SPK = Stdio.Arr2Public(Head[3]);
		SSK = Stdio.Arr2Private(Head[4]);
		Subs = Stdio.MxDaccuShifter(Head[5], 1);
		
		MyCert = LibSTLS.LoadCert(Maildir+"/head/data", Sale);
			
		SSLClient = LibSTLS.GetSSLForClient();
		SSLServer = LibSTLS.GetSSLForServer(MyCert, new KeyPair(SPK,SSK));
		
		if (EnterRoute) try { 
				BlackList = new IPList(this,"smtp"); 
				} catch(Exception E) { 
				Config.EXC(E, "IPList: `"+Nick+"`");
				BlackList=null;
				}
		
			try {
				byte[] b = Stdio.file_get_bytes(Maildir+"/stats");
				byte[][] c = Stdio.MxDaccuShifter(b, 0xf385);
				int[] d = Stdio.Lodsxi(c[0], 4);
				StatMsgIn = d[0];
				StatMsgOut=d[1];
				StatError=d[2];
				StatException=d[3];
				StatMsgInet=d[4];
				StatPop3=d[5];
				StatSpam=d[6];
				StatHcount=-1;
				} catch(Exception I) {
				StatMsgIn = 0;
				StatMsgOut=0;
				StatError=0;
				StatException=0;
				StatMsgInet=0;
				StatPop3=0;
				StatSpam=0;
				StatHcount=-1;
				}
			
		Status |= SrvIdentity.ST_Running;
		StartProcs();
		}
	
	private String UFname(String local) throws Exception {
		CRC32 C  = new CRC32();
		String fn = Maildir+"/usr/";
		C.update(local.toLowerCase().getBytes());
		C.update(Sale);
		fn+=Long.toString(C.getValue(),36);
		C.reset();
		C.update(local.toUpperCase().getBytes());
		C.update(Sale);
		fn+="-"+Long.toString(C.getValue(),36);
		return fn;
		}
	
	public boolean UsrExists(String local) throws Exception {
		File F = new File(UFname(local)+".idx");
		return F.exists();
	}
	
	public String UsrAlias(String local) throws Exception {
		String fn = UFname(local+"@alias")+".alf";
		if (!new File(fn).exists()) return null;
		byte[] rw = Stdio.file_get_bytes(fn);
		byte[][] X = J.DerAesKey2(Sale, local);
		rw = Stdio.AES2Dec(X[0], X[1], rw);
		X = Stdio.MxDaccuShifter(rw, Const.MX_Alias);
		return new String(X[0]);
		}
	
	public boolean UsrCreateAlias(String alias,String local) throws Exception {
		alias=alias.toLowerCase().trim();
		local=local.toLowerCase().trim();
		if (	alias.compareTo(local)==0	||
				!alias.matches("[a-z0-9\\.\\_\\-]{4,32}") ||
				!local.matches("[a-z0-9\\.\\_\\-]{4,32}") ||
				alias.endsWith(".onion") ||
				alias.endsWith(".sys") ||
				alias.endsWith(".op") ||
				alias.endsWith(".list") ||
				alias.compareTo("server")==0 ||
				alias.endsWith(".onion") ||
				alias.endsWith(".sys") ||
				alias.endsWith(".list") ||
				local.compareTo("server")==0 
				) return false;
		
		if (UsrExists(alias) || !UsrExists(local)) return false;
		String fn = UFname(alias+"@alias")+".alf";
		byte[][] X = new byte[][] { local.getBytes(), alias.getBytes() };
		byte[] rw = Stdio.MxAccuShifter(X,Const.MX_Alias,true);
		X = J.DerAesKey2(Sale, alias);
		rw = Stdio.AES2Enc(X[0], X[1], rw);
		Stdio.file_put_bytes(fn, rw);
		X=null;
		return true;
		}
	
	public void UsrDelAlias(String local) throws Exception {
		String fn = UFname(local+"@alias")+".alf";
		File F=new File(fn);
		if (F.exists()) J.Wipe(fn, Config.MailWipeFast);
		}
	
	public MailBox UsrOpenW(Config C,String local) throws Exception {
		String un=UFname(local);
		byte[][] U = new byte[1][];
		U[0] = Stdio.file_get_bytes(un+".idx");
		
		byte[] Pak = Stdio.sha256a(new byte[][] { Sale, local.getBytes() });
		byte[] Iavk = Stdio.md5a(new byte[][] { Pak, Sale, local.getBytes() });
		U[0] = Stdio.AES2Dec(Pak,Iavk, U[0]);
		U = Stdio.MxDaccuShifter(U[0],Const.MX_User);
		HashMap <String,String> UP = J.HashMapUnPack(U[6]);
		MailBox M = new MailBox(this,local,un+".dbf",Stdio.Arr2Public(U[3]));
		M.UserProp =UP;
		return M;
	}
	
	public boolean UsrLogonSend(String local,String pwlwr) throws Exception {
		String un=UFname(local);
		if (!new File(un+".idx").exists()) return false;
		byte[][] U = new byte[1][];
		U[0] = Stdio.file_get_bytes(un+".idx");
		
		byte[] Pak = Stdio.sha256a(new byte[][] { Sale, local.getBytes() });
		byte[] Iavk = Stdio.md5a(new byte[][] { Pak, Sale, local.getBytes() });
		U[0] = Stdio.AES2Dec(Pak,Iavk, U[0]);
				
		U = Stdio.MxDaccuShifter(U[0],Const.MX_User);
				
		byte[] verv = Stdio.md5a( new byte[][] { pwlwr.getBytes(),U[1] } );
		for (int ax=0;ax<16;ax++) if (U[5][ax]!=verv[ax]) return false;
		return true;
	}
	
	public MailBox UsrOpenW(Config C,String local,String pws) throws Exception {
		String un=UFname(local);
		byte[][] U = new byte[1][];
		U[0] = Stdio.file_get_bytes(un+".idx");
		
		byte[] Pak = Stdio.sha256a(new byte[][] { Sale, local.getBytes() });
		byte[] Iavk = Stdio.md5a(new byte[][] { Pak, Sale, local.getBytes() });
		U[0] = Stdio.AES2Dec(Pak,Iavk, U[0]);
				
		U = Stdio.MxDaccuShifter(U[0],Const.MX_User);
		//OK			
		HashMap <String,String> UP = J.HashMapUnPack(U[6]);
		
		byte[] ver = Stdio.md5a( new byte[][] { pws.getBytes() , U[1], local.getBytes() });
		for (int ax=0;ax<16;ax++) if (U[2][ax]!=ver[ax]) return null;
		
		byte[] key = Stdio.sha256a( new byte[][] { local.getBytes(), U[1], pws.getBytes() , Sale });
		byte[] IV = Stdio.md5a( new byte[][] { key,ver, Sale });
		
		byte[] PR = U[4];
		PublicKey Pk= Stdio.Arr2Public(U[3]);
		PR = Stdio.AES2Dec(key, IV, PR);
		U = Stdio.MxDaccuShifter(PR, Const.MX_User);
		if (!new String(U[0]).contains("USER")) return null;
		PrivateKey Sk = Stdio.Arr2Private(U[1]);
		MailBox M = new MailBox(this,local,un+".dbf",Pk,Sk);
		M.UserProp = UP;
		return M;
	}
	
	public HashMap <String,String> UsrGetProp(String local) throws Exception {
		String un=UFname(local);
		byte[][] U = new byte[1][];
		U[0] = Stdio.file_get_bytes(un+".idx");
		
		byte[] Pak = Stdio.sha256a(new byte[][] { Sale, local.getBytes() });
		byte[] Iavk = Stdio.md5a(new byte[][] { Pak, Sale, local.getBytes() });
		U[0] = Stdio.AES2Dec(Pak,Iavk, U[0]);
		
		U = Stdio.MxDaccuShifter(U[0],Const.MX_User);
		
		return J.HashMapUnPack(U[6]);
		
	}
	
	public HashMap <String,String> UsrGetConfig(String local) throws Exception {
		String un=UFname(local);
		un+=".pr";
		
		if (!new File(un).exists()) return new HashMap <String,String>();
		
		byte[][] Ks = J.DerAesKey(Sale, local.toLowerCase().trim()+"#"+Onion.toLowerCase().trim());
		byte[] b= Stdio.file_get_bytes(un);
		b=Stdio.AES2Dec(Ks[0], Ks[1], b);
		Ks[0]=null;
		Ks[1]=null;
		System.gc();
		return J.HashMapUnPack(b);
	}
	
	public void UsrSetConfig(String local,HashMap <String,String> H) throws Exception {
		HashMap <String,String> O = UsrGetConfig(local);
		for(String K:H.keySet()) O.put(K, H.get(K));
		String un=UFname(local);
		un+=".pr";
		byte[][] Ks = J.DerAesKey(Sale, local.toLowerCase().trim()+"#"+Onion.toLowerCase().trim());
		byte[] b = J.HashMapPack(O);
		b = Stdio.AES2Enc(Ks[0], Ks[1], b);
		Stdio.file_put_bytes(un, b);
		Ks[0]=null;
		Ks[1]=null;
		System.gc();
	}
	
	public void UsrCreate(String local,String pws,String pwlwr,int ttl,HashMap <String,String> Prop) throws Exception {
		KeyPair GPG = Stdio.RSAKeyGen(2048);
		byte[] rnd = new byte[64];
		Stdio.NewRnd(rnd);
		byte[] key = Stdio.sha256a( new byte[][] { local.getBytes(), rnd, pws.getBytes() , Sale });
		byte[] ver = Stdio.md5a( new byte[][] { pws.getBytes() , rnd, local.getBytes() });
		byte[] IV = Stdio.md5a( new byte[][] { key,ver, Sale });
		byte[] verv = Stdio.md5a( new byte[][] { pwlwr.getBytes(),rnd } );
		
		PrivateKey Sk = GPG.getPrivate();
		PublicKey Pk = GPG.getPublic();
		byte[] EXT = J.HashMapPack(Prop);
		
		byte[] PR = Stdio.MxAccuShifter(new byte[][] {
					"USER".getBytes(),
					Stdio.Private2Arr(Sk)
					}, Const.MX_User,true); 
		
		PR = Stdio.AES2Enc(key, IV, PR);

		byte[] US = Stdio.MxAccuShifter(new byte[][] {
					Stdio.Stosx(new long[] {ttl}, 4),
					rnd,
					ver,
					Stdio.Public2Arr(Pk),
					PR,
					verv,
					EXT
					}, Const.MX_User,true);
		
		byte[] Pak = Stdio.sha256a(new byte[][] { Sale, local.getBytes() });
		byte[] Iavk = Stdio.md5a(new byte[][] { Pak, Sale, local.getBytes() });
		US = Stdio.AES2Enc(Pak,Iavk, US);
		
		String un=UFname(local);
		Stdio.file_put_bytes(un+".idx",US);

		try {
			MailBox M = UsrOpenW(Config,local);
			
			if (M.Spam !=null && !M.Spam.exists(local)) M.Spam.UsrCreateList(local);
			} catch(Exception E) { Config.EXC(E, "CreateUser.CreateUBL"); } 
		
		try {
			UsrSetConfig(local,new HashMap <String,String> ());
			} catch(Exception E) { Config.EXC(E, "CreateUser.MKConf"); }
		
		}
	
	
	public static byte[] KSEncode(byte[][] ks,byte[] p) throws Exception {
		int rs = (int)(Stdio.NewRndLong() & 255);
		if (rs<64) rs+=64;
		byte[] rnd = new byte[rs];
		Stdio.NewRnd(rnd);
		byte[] k = Stdio.MxAccuShifter(ks, 0x900E,true);
		
		byte[] l1k = Stdio.sha256a(new byte[][] { rnd,p });
		byte[] l1i = Stdio.md5a(new byte[][] {l1k,rnd,p});
		
		k = Stdio.AES2Enc(l1k, l1i, k);
		
		k = Stdio.MxAccuShifter(new byte[][] {
				Stdio.md5a(new byte[][] { rnd, p }),
				rnd	,
				k		} , 0x900E,true) ;
		
		return  k;
			
	}
	public static byte[][] KSDecode(byte[] b,byte[] p) throws Exception {
		byte[][] F = Stdio.MxDaccuShifter(b, 0x900E);
		byte[] rnd = F[1];
		byte[] vr = Stdio.md5a(new byte[][] { rnd, p });
		for (int ax=0;ax<16;ax++) if (vr[ax]!=F[0][ax]) throw new Exception("@Invalid password");
		
		byte[] l1k = Stdio.sha256a(new byte[][] { rnd,p });
		byte[] l1i = Stdio.md5a(new byte[][] {l1k,rnd,p});
		
		byte[] k = Stdio.AES2Dec(l1k, l1i, F[2]);
		
		return Stdio.MxDaccuShifter(k, 0x900E);
		}
	

	public long Time() {
		long tcr = System.currentTimeMillis();
		if (tcr>TimerSpoofNextDelta) {
			TimerSpoofNextDelta = (Stdio.NewRndLong() & 0x7FFFFFFFFFFFFFFFL) % (TimerSpoofMaxEveryDelta-TimerSpoofMinEveryDelta);
			TimerSpoofNextDelta +=TimerSpoofMinEveryDelta+tcr;
			TimerSpoofDelta = Stdio.NewRndLong() % TimerSpoofVibration;
			}
		long x = TimerSpoof+TimerSpoofDelta;
		if (x>TimerSpoofMaxFuture) x = -x;
		if (-x>TimerSpoofMaxPast) x=-TimerSpoofMaxPast;
		if (x>TimerSpoofMaxFuture) x = TimerSpoofMaxFuture;
		return tcr+TimerSpoof+x;
	}
	
	public String TimeString() {
		long tcr = Time();
		return J.TimeStandard(tcr, TimerSpoofFus);
	}
	
	public void SendMessage(String to,HashMap <String,String> Hldr,String Body) throws Exception {
		to = J.getMail(to, false);
		if (to==null) throw new PException(503,"Inalid mail address");
		String dom = J.getDomain(to);
		if (dom.compareTo(Onion)==0) SendLocalMessage(J.getLocalPart(to),Hldr,Body); else SendRemoteSession(to,Hldr.get("from"),Hldr, Body);
		}
	
	public String SrvPGPMessage(String tousr,HashMap <String,String> Hldr,String Body) throws Exception {
		try {
			String rkey = UserGetPGPKey(tousr);
			if (rkey==null) {
				Body+="\nPGP: NO PGP KEY\n";
				return Body;
				}
			
			Body=Hldr.get("subject")+":\n\n"+Body;
			
			byte[] rs = PGP.encrypt(Body.getBytes("UTF-8"), PGP.readPublicKey(new ByteArrayInputStream(rkey.getBytes())), null, true, true, new Date(Time()), Config.PGPEncryptedDataAlgo);
			Hldr.put("subject", "RE: PGP");
			Hldr.put("content-type", "text/plain; charset=UTF-8");
			Body= new String(rs);
			Body=Body.replace("\r\n", "\n"); //TODO levare!
			Body=PGPSpoofNSA(Body, false); 
			Body=Body.replace("\r\n", "\n");
			return Body;
			
		} catch(Exception E) {
			String ms= E.getMessage();
			if (ms.startsWith("@")) {
				ms=ms.substring(1);
				Body+="\n\nPGP: "+ms+"\n";
				Log("PGP: "+ms);
				} else {
				Config.EXC(E, "PGP:RE");
				Body+="\n\nPGP: Global Error\n";
				}
			return Body;
		}
			
	}
	
	public void SendLocalMessage(String LocalPart,HashMap <String,String> Hldr,String Body) throws Exception {
		StatMsgIn++;
		if (Config.Debug) Log("LocalMessage "+Nick);
				
		MailBox M = UsrOpenW(Config,LocalPart);
		int mi = M.Index.GetFree();
		if (mi==-1) {
			M.Close();
			throw new Exception("@500 Mailbox full");
			}
		long MessageBytes=0;
				
		Message MS = M.MsgCreate();
		MS.SetHeaders(Hldr);
		
		Body=Body.replace("\\r", "");
		String[] I = Body.split("\\n");
		
		for (int ax=0;ax<I.length;ax++) {
			String li = I[ax];
			if (li.compareTo(".")==0) break; 
			MessageBytes+=li.length()+2;
			if (MessageBytes>MaxMsgSize) {
				MS.Close();
				throw new Exception("@500 Message too big");
				}
			MS.WriteLn(li);
			}
		MS.End();
	}
	
	public MailingList CreateMailingList(String loc,String tit,String Owner,String Passwd,boolean isopen,boolean isgpg) throws Exception {
		MailingList M = new MailingList(this);
		M.LocalPart=loc;
		M.Title=tit;
		M.isOpen =isopen;
		M.isGPG=isgpg;
		M.Create(MaxMailingListSize);
		try {	M.Close(); } catch(Exception E) {}
		M = MailingList.Open(this, loc);
		MLUserInfo U = M.NewInfo(MailingList.TYP_Admin, Owner, Passwd);
		M.SetUsr(U);
		M.Save();
		return M;
	}
	
	public boolean CheckMailingList(String loc) throws Exception {
		MailingList M = new MailingList(this);
		M.LocalPart=loc;
		return M.Exists();
	}
	
	public MailingList OpenMailingList(String loc) throws Exception { return MailingList.Open(this, loc);	}
	
	public void SendLocalMessage(String LocalPart,HashMap <String,String> Hldr,MailBoxFile I) throws Exception {
		StatMsgIn++;
		
		MailBox M = UsrOpenW(Config,LocalPart);
		int mi = M.Index.GetFree();
		if (mi==-1) {
			M.Close();
			throw new Exception("@500 Mailbox full");
			}
		long MessageBytes=0;
		
		Message MS = M.MsgCreate();
		MS.SetHeaders(Hldr);
			
		while(true) {
			String li = I.ReadLn();
			if (li==null) break;
			if (li.compareTo(".")==0) break;
			
			MessageBytes+=li.length()+2;
			if (MessageBytes>MaxMsgSize) {
				MS.Close();
				throw new Exception("@500 Message too big");
				}
			MS.WriteLn(li);
			}
		MS.End();
	}
				
	public void SendRemoteSession(String MailTo,String MailFrom,HashMap <String,String> Hldr,MailBoxFile MBF) throws Exception { 									RawBeginRemoteSession(new SMTPOutSession(null,MailTo,MailFrom,Hldr,MBF,null,null, null));	}
	public void SendRemoteSession(String MailTo,String MailFrom,HashMap <String,String> Hldr,String Msg) throws Exception { 											RawBeginRemoteSession(new SMTPOutSession(null,MailTo,MailFrom,Hldr,null,Msg,null, null)); 	}
	public void SendRemoteSession(String MailTo,String MailFrom,HashMap <String,String> Hldr,BufferedReader I, OutputStream O) throws Exception { 	RawBeginRemoteSession(new SMTPOutSession(null,MailTo,MailFrom,Hldr,null,null,I, O)); 				}
	
	private void SetExitQFDN(String qfdn,SMTPOutSession SO) throws Exception {
		SO.QFDN = qfdn.toLowerCase().trim();
		SO.convExit=true;
		SO.OriginalFrom = SO.MailFrom;
		SO.MailFrom = J.MailOnion2Inet(Config, SO.MailFrom, SO.QFDN);
		}
	
	private void SetExitHeaders(SMTPOutSession SO) throws Exception {
		HashMap <String,String> H = new HashMap <String,String> ();
		
		for (String K:SO.Hldr.keySet()) {
			String v = SO.Hldr.get(K);
			v=v.replace(SO.OriginalFrom, SO.MailFrom);
			H.put(K, v);
			}
		
		H.put("subject", SO.Hldr.get("subject"));
		SO.Hldr = J.AddMsgID(H, SO.QFDN);
		SO.Hldr.put("x-mat-from", SO.OriginalFrom);
		
	}
	
	private void RawBeginRemoteSession(SMTPOutSession SO) throws Exception {
		StatMsgOut++;	
		
		if (ExitEnterPolicyBlock!=null && !SO.MailTo.endsWith(".onion")) {
			if (!CanEnterExit(SO.MailTo, false)) throw new PException(503,"Address rejected by the exit policy");
			StatMsgInet++;
			}
		
		String Server = J.getDomain(SO.MailTo);
		String LocalTo = J.getLocalPart(SO.MailTo);
		if (LocalTo.endsWith(".onion")) throw new PException(503,"Onion2Mail not allowed to OnionMail destination!");
		//XXX ^ Vedere!
		
		boolean ToOnion = Server.endsWith(".onion");
		if (!ToOnion) {
			if (EnterRoute) { 
				SetExitQFDN(ExitRouteDomain, SO);
				SO.HostName=Server;
				} else {
				String dou=null;
				if (J.getDomain(SO.MailFrom).compareTo(Onion)==0) {
						HashMap <String,String> Conf = UsrGetConfig(J.getLocalPart(SO.MailFrom));
						if (Conf!=null && Conf.containsKey("exitdomain")) dou=Conf.get("exitdomain");
						}
					
				ExitRouteList RL= GetExitList();
				dou = RL.SelectOnion(dou);
				if (dou==null) throw new Exception("@503 No exit/enter route available!");
				Server=RL.GetDomain(dou);
				RL=null;
				//SetExitQFDN(dou, SO);
				SO.QFDN = dou;
				if (Config.Debug) Log("Indirect `"+dou+"` > `"+Server+"`");
				ToOnion=true;
				SO.HostName=dou;
				}
		} else SO.HostName=Server;
		
		if (ToOnion) RawConnectOnion(SO); else RawConnectInet(SO);
		RawHeaders(SO);
		if (SO.DirectMode) RawOnionData(SO); else RawNormalData(SO);
		SO.Close();
	
	}
	
	private void RawConnectOnion(SMTPOutSession SO) throws Exception {
		
			Log("RemoteSendOnion  "+SO.HostName);
			
			XOnionParser tor = XOnionParser.fromString(Config,SO.HostName);
			try {
				try {
					SO.RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, tor.Onion,25);
					SO.RO = SO.RS.getOutputStream();
					SO.RI  =J.getLineReader(SO.RS.getInputStream());
					} catch(Exception E) {
								if (Config.Debug) Log("Can't connect in SMTP "+tor.Onion);
								throw new Exception("@503 Connection error `"+SO.HostName+"` "+E.getMessage());
								}

				SO.HostName = tor.Onion;
				SO.isTor=true;
				} catch(Exception E) {
					SO.Close();
					SO=null;
					throw E;
				}
	}
	
	
	
	///////////////////////// RAW SESSION /////////////////////
		
	private void RawHeaders(SMTPOutSession SO) throws Exception {
		
		SO.SupTLS=false;
		SO.SupTorm=false;
		SMTPReply Re = null;
		
		Re = new SMTPReply(SO.RI);
		if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
		
		Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"EHLO "+ (SO.isTor ? Onion : ExitRouteDomain));
		if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
			
		SO.SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");		
		if (SO.isTor) {
				SO.SupTorm = SrvSMTPSession.CheckCapab(Re,"TORM");
				SO.SupTKIM = SrvSMTPSession.CheckCapab(Re,"TKIM");
				}
				
		boolean usalo = true;
		if (Config.SSLJavaHasBug && !SO.SupTorm) {
				usalo=false;
				Log("JavaBug evasion `"+SO.HostName+"`");
				}
		
		if (SO.SupTLS && usalo) { //TODO CHECKSSLNonTorM
				if (Config.Debug) Log("SSL Connect to `"+SO.HostName+"` -> `"+SO.RS.getInetAddress().toString()+"`");
				Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"STARTTLS");
				if (Re.Code>199 || Re.Code<300) {
					SSLSocket SS = LibSTLS.ConnectSSL(SO.RS, SSLClient,SO.HostName);
					CheckSSL(SS, SO.HostName,"RH1");
					SO.RO = null;
					SO.RO = SS.getOutputStream();
					SO.RI=null;
					SO.RI=J.getLineReader(SS.getInputStream());
					SO.RS=SS;					
					
					Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"EHLO "+ (SO.isTor ? Onion : ExitRouteDomain));
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					
					} else SO.SupTLS=false;
				}
		
		SO.Hldr.put("x-ssl-transaction", SO.SupTLS ? "YES":"NO");
		
		if (SO.SupTorm && !HaveManifest(SO.HostName)) {
						Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"TORM IAM iam.onion");
						if (Re.Code>199 && Re.Code<300) ReceiveManifest(Re, SO.HostName);
						}
				
		Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"MAIL FROM: <"+SO.MailFrom+">");
		if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
		
		Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"RCPT TO: <"+SO.MailTo+">");
		if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
		
		if (SO.SupTKIM) try {
			Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"TKIM");
			if (Re.Code<299 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (remote)"); //chkkk
			byte[] rnd = Re.getData();
			try { rnd = Stdio.RSASign(rnd, SSK); } catch(Exception E) { 
					Config.EXC(E, "TKIM.RSASign(`"+SO.HostName+"`)");
					rnd = new byte[0];
					}
			SMTPReply.Send(SO.RO,220,J.Data2Lines(rnd, "TKIM/1.0 REPLY"));
			Re = new SMTPReply(SO.RI);
			if (Re.Code<200 || Re.Code>299) Log(Config.GLOG_Event,"TKIM: `"+SO.HostName+"` Error: "+Re.toString().trim());
			} catch (Exception EK) {
				Config.EXC(EK, "TKIM `"+SO.HostName+"`");
			}
	
		}
	
	
	
	private void RawNormalData(SMTPOutSession SO) throws Exception {
		SMTPReply Re = null;
		Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"DATA");
		if (Re.Code<300 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (remote)");
		RawSMTPDATA (SO);
	}
	
	private HashMap<String,String> ParseHeaders(BufferedReader I) throws Exception {
		String in="";
		for (int ax=0;ax<SrvSMTPSession.MaxHeaderLine;ax++) {
			String li = I.readLine();
			if (li==null) throw new PException(500,"Connection lost");
			if (li.compareTo(".")==0) throw new PException(500,"Invalid headers");
			li=li.replace("\r", "");
			li=li.replace("\n", "");
			in+=li+"\n";
			if (li.length()==0) return J.ParseHeaders(in.split("\\n"));
		}
		throw new PException("@500 Too many mail headers");
	} 	
	
	private void RawOnionData(SMTPOutSession SO) throws Exception {
		SMTPReply Re = null;
		Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"DATA");
		if (Re.Code<300 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (remote)");
		
		//X\XX FATTO Aggiungere controllo invio dati su DATA
				
		SO.Send("354 Enter message, ending with \".\" on a line by itself");
		SO.Hldr = ParseHeaders(SO.I);
		RawSMTPDATA (SO);
	}
	
	
	private void RawSMTPDATA (SMTPOutSession SO) throws Exception {
	
		int Modo=0;
		if (SO.MBF!=null) Modo=0;
		if (SO.Msg!=null) Modo=1;
		if (SO.I!=null) Modo=2;
		SMTPReply Re = null;
		
		SO.Hldr = J.FilterHeader(SO.Hldr);
		if (SO.HelloData!=null) {
				SO.Hldr.put("received", "from "+J.IPFilter(SO.HelloData)+" by "+Onion+" ("+Nick+") [0.0.0.0] "+TimeString());
				SO.Hldr.put("x-hellotype", SO.HelloMode==1 ? "HELO" : "EHLO");
				}
		SO.Hldr.put("sender", SO.MailFrom);
		SO.Hldr.put("envelope-to", SO.MailTo);
		SO.Hldr.put("delivery-date", TimeString());
		if (!SO.Hldr.containsKey("date")) SO.Hldr.put("date", TimeString());
		if (!SO.Hldr.containsKey("delivery-date")) SO.Hldr.put("delivery-date", TimeString());
		SO.Hldr.put("x-ssl-transaction", SO.SupTLS ? "YES" : "NO" );
		String ST;
				
		if (SO.convExit) { SetExitHeaders(SO); ST=SO.QFDN; } else ST=Onion;
		if (SO.isInternet && ExitNoticeE) { 
					String sr;
					sr = "server."+Onion+"@"+SO.QFDN;
					String st=sr;
					if (ExitNotice==null) {
					st = "This is an OnionMail message. See http://onionmail.info and <mailto:${SERVER}?subject=RULEZ> for details";
					st=st.replace("${SERVER}", sr);
					} else {
					st = ExitNotice.replace("${SERVER}", sr);
					}
					
			SO.Hldr.put("x-notice", st);
			}
		
		SO.Hldr=J.AddMsgID(SO.Hldr, ST);
			
		String t0 = J.CreateHeaders(SO.Hldr);
			t0=t0.trim();
			t0+="\r\n\r\n";
			SO.RO.write(t0.getBytes());
			t0=null;
			long MessageBytes=0;
			long TimeOut = System.currentTimeMillis()+Config.MaxSMTPSessionTTL;
			int ecx = 0;
			String[] Arr=null;
			
			if (Modo==1) {
				Arr = SO.Msg.split("\\n");
				ecx=Arr.length;
				}
			
			int eax=0;
						
			while(true) {
				if ( System.currentTimeMillis()>TimeOut) throw new Exception("@500 Timeout");
				if (Modo==1) {
					if (eax==ecx) break;
					t0 = Arr[eax++].replace("\r", "");
					}
				
				if (Modo==2) t0 = SO.I.readLine();
				if (Modo==0) t0 = SO.MBF.ReadLn().replace("\r\n", "");
				
				MessageBytes+=t0.length()+2;
				if (MessageBytes>=MaxMsgSize) throw new PException("@500 Message too big");
							
				t0+="\r\n";
				if (t0.compareTo(".\r\n")==0) break;
				SO.RO.write(t0.getBytes());
				}
			SO.RO.write(".\r\n".getBytes());
			Re = new SMTPReply(SO.RI);
			if (Modo==2) Re.Send(SO.O);
			
			try {
				Re = SrvSMTPSession.RemoteCmd(SO.RO,SO.RI,"QUIT");
				SO.Close();
				} catch(Exception Ii) {}
		
			if (Modo!=2 && (Re.Code<200 || Re.Code>299)) throw new Exception("@"+Re.Code+" "+Re.Msg[0]);
			
			///if (SO.DirectMode) SO.Send("250 Id="+J.getLocalPart(SO.Hldr.get("message-id")));
			
	}
		
	private void RawConnectInet(SMTPOutSession SO) throws Exception {
			StatMsgInet++;
			String Server = J.getDomain(SO.MailTo).toLowerCase();
			String MXServer=Server;
			if (Config.Debug) Log("RemoteSendInet `"+Server+"`");
			
			MXRecord[] MX = Main.DNSCheck.getMX(Server);
			if (MX==null) throw new Exception("@500 SMTP Server not found `"+Server+"` (No MX record)");
			SO.isInternet=true;
			
			int cx = MX.length-1;
				for (int ax=0;ax<=cx;ax++) {
						try {
							SO.RS =  new Socket(MX[ax].getAddress(),25); 
							MXServer=MX[ax].Host;
							break;
							} catch(Exception II) {
								Log(Config.GLOG_Event,"Can't connect to "+J.IP2String(MX[ax].getAddress()));
								try { SO.RS.close(); } catch(Exception III) {}
								SO.RS=null;
							}
					}
			if (SO.RS==null) throw new Exception("@500 Can't connect to "+MXServer);
			
			SO.RO = SO.RS.getOutputStream();
			SO.RI  =J.getLineReader(SO.RS.getInputStream());
			
			try {
				if (SO.MailFrom.endsWith(".onion")) {
					String OriginalFrom = SO.MailFrom;
					SO.MailFrom = J.MailOnion2Inet(Config, SO.MailFrom, ExitRouteDomain);
					HashMap <String,String> Oh = new HashMap <String,String> ();
					for (String k:SO.Hldr.keySet()) Oh.put(k, SO.Hldr.get(k).replace(OriginalFrom, SO.MailFrom));
					Oh.put("subject", SO.Hldr.get("subject"));
					Oh = J.AddMsgID(Oh, ExitRouteDomain);
					SO.Hldr=Oh;
					}
				
				SO.isTor=false;
				SO.HostName = MXServer;
				} catch(Exception E) {
					SO.Close();
					throw E;	
				}
	}

	private String GetFNName(String O) {
		try {
			return Maildir+"/feed/"+ J.md2st(Stdio.md5a(new byte[][] { Sale, O.toLowerCase().getBytes(),"Manifest2".getBytes() }));
		} catch(Exception E) {
				Config.EXC(E, "GetFNName `"+O+"`");
				return Maildir+"/feed/"+ Long.toHexString(O.hashCode())+"-fail"; 
				}
	}
	
	public String CreateManifest() throws Exception {
		HashMap <String,String> H = new HashMap <String,String>();
		H.put("manifest", "1.1");
		H.put("ver",Main.getVersion());
		String a="";
		if (OnlyOnionFrom || OnlyOnion || OnlyOnionTo || !CanRelay) a+="R";
		if (EnterRoute) a+="X";
		if (ExitNoticeE) a+="N";
		if (ExitEnterPolicyBlock!=null) a+="P";
		
		H.put("flg",a);
		H.put("qfdn",EnterRoute ? ExitRouteDomain : Onion );
		H.put("onion", Onion);
		H.put("nick", Nick);
		H.put("date", (int)(Time()/1000L)+"");
		H.put("lang", DefaultLang);
		H.put("exit",EnterRoute ? "1":"0");
		
		if (ExitEnterPolicyBlock!=null) {
			String s="";
			for (String k:ExitEnterPolicyBlock.keySet()) {
				int b =ExitEnterPolicyBlock.get(k);
				String[] d = k.split("\\@");
				if (d.length!=2) continue;
				if (b!=0) s+=d[1]+"\n";
				}
			s=s.trim();
			s=s.replace('\n',',');
			H.put("locks", s);
			}
		
		String s= J.CreateHeaders(H);
		try {
			s+="\r\n"; 
			ExitRouteList RL = GetExitList();
			for (String k:RL.keySet()) s+=k+": "+RL.get(k)+"\r\n";
			
			s+="\r\n";
			for (String k:ManifestInfo.keySet()) s+=k.toLowerCase()+": "+ManifestInfo.get(k)+"\r\n";
			
			String t = s.trim();
			t=J.Base64Encode(Stdio.RSASign(t.getBytes(), SSK));
			s+="\r\nSign: "+t;
			t=null;
			} catch(Exception E) { Config.EXC(E, "SrvID_Manifest"); }
		
		return s.trim();
		
	}
		
	public void CheckSSL(SSLSocket S,String O,String cod) throws Exception {
		try {
			javax.security.cert.X509Certificate[] C = LibSTLS.getCert(S);
			if (C==null || C.length==0 ) throw new Exception("@500 NO SSL CERT FOR `"+O+"`");
			
			SSLVerify(C,O);
		} catch(Exception E) {
			if (Config.Debug) Config.EXC(E, "CheckSSL "+cod);
			String msg=E.getMessage();
			throw new Exception(E+" COD="+cod);
		}
	}
		
	public void CreateSpam() throws Exception {
		Spam = new Spam(Config,this);
		Spam.UsrCreateList(SrvIdentity.SpamList);
	}

	public Spam GetSpamHinstance() { return Spam; } 
	public boolean isSpam(String addr) { return Spam.isSpam(SrvIdentity.SpamList, addr); }
	public void AddSpam(String addr) throws Exception { Spam.ProcList(SrvIdentity.SpamList, new String[] { addr } , null); }
	public String SpamProc(int id) throws Exception { return Spam.UsrProcList(SrvIdentity.SpamList, id); }
		
	public void DoGarbage() throws Exception {
		String inb = Maildir+"/inbox/";
		File ib = new File(inb);
		
		FilenameFilter esf = new FilenameFilter() {
			public boolean accept(File dir, String name) { return name.toLowerCase().endsWith(".esf"); }
			} ;
		
		long Old = (Config.MailRetentionDays*86400000L)+86400001L;
		String[] lst = ib.list(esf);
		int cx= lst.length;
		long Tcr=System.currentTimeMillis();
		long free=0;
		
		Log("Begin Garbage "+new Date(Tcr-Old)+"\n");
		
		for (int ax=0;ax<cx;ax++) try {
			if (lst[ax].contains(".ml.") || lst[ax].contains(".ng.")) continue;
			String fn = inb+lst[ax];
			File M = new File(fn);
			long Delta = Tcr-M.lastModified();
			if (Delta>Old) try {
				free+=M.length();
				J.Wipe(fn, Config.MailWipeFast);
				Log("Garbage message `"+lst[ax]+"`\n");
				} catch(Exception E) {
				Log("Garbage Error `"+lst[ax]+"` "+E.toString()+"\n");	
				}
			} catch(Exception F) {
				Log("Garbage Index Error `"+lst[ax]+"`\n");
			}
		if (free>0) Log("Garbage completed, "+Integer.toString((int)(free/1024))+"Kb free\n");	
		CleanDer();	
		}		
	
		public void TORM_IAM(String remo) throws Exception {
			Log("Begin IAM "+new Date(Time())+" `"+remo+"`\n");
			
			if (remo.compareToIgnoreCase(Onion)==0) throw new Exception("@503 I know me!");
				String fn = GetFNName(remo);
				if (new File(fn).exists()) {
						Log("End IAM "+new Date(Time())+" `"+remo+"` is a friend\n");
						return;  
						} 
				
				Socket	RS=null;
				OutputStream RO=null;
				BufferedReader RI=null;
				SMTPReply Re=null;
				boolean SupTLS=false;
				boolean SupTORM=false;
				
			
			try {
					
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, remo,25);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote)"); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
					SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
					if (!SupTLS) throw new Exception("Doesn't support STARTTLS");
					if (!SupTORM) throw new Exception("Doesn't support TORM");
					
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"STARTTLS");
					if (Re.Code>199 || Re.Code<300) {
					SSLSocket SS = LibSTLS.ConnectSSL(RS, SSLClient,remo);
						CheckSSL(SS, remo,"IAM");
						
						RO = null;
						RO = SS.getOutputStream();
						RI=null;
						RI=J.getLineReader(SS.getInputStream());
						RS=SS;	
												 
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
						if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote)");
						
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM IAM iam.onion");
						if (Re.Code>199 &&  Re.Code<300) ReceiveManifest(Re,remo);
						
						try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception Ii) {}
						} else  throw new Exception("@"+Re.toString().trim()+ " (remote)");
					
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
				} catch(Exception E) {
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
					Log("Friend `"+remo+"` Error: "+E.toString().replace("@", ""));
					return;
				}
			
			Log("New friend "+new Date(Time())+" `"+remo+"`\n");
						
		}
	
		public boolean HaveManifest(String remo) {
			
			String mf = GetFNName(remo)+".mf";
			File F = new File(mf);
			
			if (F.exists()) {
					try { 
							long T= F.lastModified();
							if (T==0 || Math.abs(System.currentTimeMillis() - T) > 86400000) return false;
							} catch(Exception I) { return false; }
					return true;
					}
			return false;
				
		}
		
		public SrvManifest  ReceiveManifest(SMTPReply Re,String remo) throws Exception {
			SrvManifest m = new SrvManifest(Re,remo);
			byte[] dta=m.getBytes();
			byte[] iv = Stdio.md5a( new byte[][] { Sale , "Manifest".getBytes() }) ; 		
			SecretKey K = Stdio.GetAESKey(iv);
			iv =Stdio.md5a(new byte[][] { "Manifest".getBytes() , Sale , iv });
			dta = Stdio.AESEnc(K, iv, dta);
			String mf = GetFNName(remo)+".mf";
			Stdio.file_put_bytes(mf, dta);
			Log("Manifest: `"+remo+"`");	
			return m;
		}

		public SrvManifest LoadManifest(String what,boolean onion) throws Exception {
			String mf = onion ? GetFNName(what)+".mf" : what;
			
			byte[] iv = Stdio.md5a( new byte[][] { Sale , "Manifest".getBytes() }) ; 		
			SecretKey K = Stdio.GetAESKey(iv);
			iv =Stdio.md5a(new byte[][] { "Manifest".getBytes() , Sale , iv });
			
			byte[] b = Stdio.file_get_bytes(mf);
			b = Stdio.AESDec(K, iv, b);
			return new SrvManifest(b);		
		}
		
		public int VerifyExit(String InedDom,String oni,int port)   {
			if (Config.Debug) Log("Verify `"+InedDom+"`");
			if (InedDom.compareTo(ExitRouteDomain)==0 && oni.compareTo(Onion)==0) return 1;
			Socket	RS=null;
			OutputStream RO=null;
			BufferedReader RI=null;
			SMTPReply Re=null;
	//		boolean SupTLS=false;
			boolean SupTORM=false;
			try {
				
				RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, InedDom,port);
				RO = RS.getOutputStream();
				RI  =J.getLineReader(RS.getInputStream());
				RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
				Re = new SMTPReply(RI);
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" `"+oni+"`"); 
						
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " `"+oni+"`");
	//			SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
				SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
				if (!SupTORM) {
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
					try { RS.close(); } catch(Exception IE) {}
					//modevd Log(Config.GLOG_Event,"Checking `"+oni+"` is  not an OnionMail compatible server!");
					return 2;
					}
				
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM K");
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " `"+oni+"`");
				
				byte[] pk = Re.getData();
				byte[][] sd =LoadCRT(oni.toLowerCase());
				if (sd==null) {
					Log(Config.GLOG_Event,"Checking `"+oni+"` exit without SSL Certificate in cache!");
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
					try { RS.close(); } catch(Exception IE) {}
					return 0;
					}
				
				if (!Arrays.equals(pk, sd[0])) {
					Log(Config.GLOG_Event,"Checking `"+oni+"` Invalid exit key!");
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
					try { RS.close(); } catch(Exception IE) {}
					return 0;
					}
				
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
				try { RS.close(); } catch(Exception IE) {}
								
				return 1;
			} catch(Exception EE) {
				if (RS!=null) try { RS.close(); } catch(Exception IE) {}
				Log(Config.GLOG_Event,"Checking `"+oni+"` Error: "+EE.getMessage());
				return 0;
			}
		} 
		
		public SrvManifest DoFriend(String FriendServer) throws Exception {
			SrvManifest M=null;
			if (FriendServer.compareToIgnoreCase(Onion)==0) return null;
			if (HaveManifest(FriendServer)) {
						Log("DoFriends Skip `"+FriendServer+"`");
						return null;
						}
			
				Socket	RS=null;
				OutputStream RO=null;
				BufferedReader RI=null;
				SMTPReply Re=null;
				boolean SupTLS=false;
				boolean SupTORM=false;
				Log("DoFriend Go to know `"+FriendServer+"`");
				try {
					
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, FriendServer,25);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote)"); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
					SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
					if (!SupTLS) throw new Exception("Doesn't support STARTTLS");
					if (!SupTORM) throw new Exception("Doesn't support TORM");
					
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"STARTTLS");
					if (Re.Code>199 || Re.Code<300) {
					SSLSocket SS = LibSTLS.ConnectSSL(RS, SSLClient,FriendServer);
						CheckSSL(SS, FriendServer,"DF1");
						
						RO = null;
						RO = SS.getOutputStream();
						RI=null;
						RI=J.getLineReader(SS.getInputStream());
						RS=SS;	
						
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
						if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM IAM "+Onion);
						if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
						M = ReceiveManifest(Re,FriendServer);
						} else  throw new Exception("@"+Re.toString().trim()+ " (remote)");
					
					try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception Ii) {}
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
				} catch(Exception E) {
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
					Log("Friend `"+FriendServer+"` Error: "+E.toString().replace("@", ""));
				}
				return M;
		}
		
		private void DoFriends() throws Exception {
		SrvManifest M=null;	
		Status |= SrvIdentity.ST_FriendRun;
		Log("Begin DoFriends\n");
		HashMap <String,String> net = new HashMap <String,String>();
		String[] FriendServer = RequildFriendsList();
		int cx=FriendServer.length;
		for (int ax=LastFriend;ax<cx;ax++) {
				LastFriend++;
				if (FriendServer[ax].compareToIgnoreCase(Onion)==0) continue;
				M = DoFriend(FriendServer[ax]);
				if (M==null) continue;
				
				if (M.N.size()!=0) {
					for (String K:M.N.keySet()) {
						if (net.containsKey(K)) {
							String c = M.N.get(K);
							if (net.get(K).compareTo(c)!=0) {
								String st = net.get(K).trim()+"\n";
								if (!("\n"+st).contains("\n"+c+"\n")) {
									st+=c;
									net.put(K, st.trim());
									}
								}
							} else net.put(K, M.N.get(K));
						}
					if (net.containsKey(FriendServer[ax])) net.remove(FriendServer[ax]);
					}
				}//for
				
		if (net.size()>0) {
		Log("DoFriends: Start Dynamic Friends scan\n");
		for (String K:net.keySet()) {
			String sl = net.get(K);
			sl=sl.trim();
			String[] srv = sl.split("\\n+");
			cx = srv.length;
			if (cx>1) {
					Log(Config.GLOG_Event,"DoFriends: Conflicts `"+K+"` to `"+sl.replace("\n", "`, `")+"`\n");
					DoFriend(K);
					} else DoFriend(srv[0]);
			}
		}///net
			
		Log("DoFriends Complete\n");
		LastFriend=0;
		Status &= -1 ^ SrvIdentity.ST_FriendRun;
		Status |= SrvIdentity.ST_FriendOk;
		}
	
		private void SearchExit() throws Exception {
			String inb = Maildir+"/feed/";
			SrvManifest M=null;	
			File ib = new File(inb);
			Log("Search Exit Scan");
			String onionlist="\n";
			FilenameFilter esf = new FilenameFilter() {
				public boolean accept(File dir, String name) { return name.toLowerCase().endsWith(".mf"); }
				} ;
			
			String[] lst = ib.list(esf);
			int cx = lst.length;
			HashMap <String,String> ExitList = new HashMap <String,String>();
			String nonlist="";
			String onioned="\n";
			for (int ax=0;ax<cx;ax++) {
				String fn = inb+lst[ax];
				
				try {
					M = LoadManifest(fn, false);
					} catch(Exception E) {
						Log(Config.GLOG_Bad,"Manifest Error: `"+lst[ax]+"` "+E.getMessage());
						continue;
					}
				
				if (!onionlist.contains("\n"+M.Onion)) onionlist+=M.Onion+"\n";
				if (!M.exit) continue;
				
				String qfdn = M.ExitDomain.toLowerCase().trim();
				String oni = M.Onion.toLowerCase().trim();
				if (qfdn.endsWith(".onion")) continue;
					
				if (ExitList.containsKey(qfdn)) {
					Log(Config.GLOG_Event,"Duplicate Manifest for D=`"+qfdn+"` O=`"+oni+"`");
					nonlist+=qfdn+"\n";
					onioned+=oni+"\n";
					continue;
					}
				
				if (onioned.contains("\n"+oni+"\n")) {
					Log(Config.GLOG_Event,"Duplicate onion for D=`"+qfdn+"` O=`"+oni+"`");
					nonlist+=qfdn+"\n";
					continue; 
					}
				
				onioned+=oni+"\n";
				ExitList.put(qfdn, oni);
			}
			
			onionlist=onionlist.trim();
			String[] tl =onionlist.split("\\n+");
			onionlist=null;
			cx = tl.length;
			byte[][] t0 = new byte[cx][];
			for (int ax=0;ax<cx;ax++) t0[ax]=tl[ax].getBytes();
			byte[] raw = Stdio.MxAccuShifter(t0,Const.MX_Friends,true);
			t0 = J.DerAesKey(Sale, "Friends");
			raw = Stdio.AES2Enc(t0[0], t0[1], raw);
			J.WipeRam(t0);
			Stdio.file_put_bytes(Maildir+"/friends",raw);
						
			t0=null;
			tl=null;
			
			onioned=null;
			nonlist=nonlist.trim();
			tl= nonlist.split("\\n+");
			for(String K:tl) ExitList.remove(K);
			
			String rme="";
			Log("Verifying Exit Scan");
			for (String K:ExitList.keySet()) {
				int rs = VerifyExit(K,ExitList.get(K),25);
				if (rs==2) {
						rs = VerifyExit(K,ExitList.get(K),10025);
						if (rs==2) Log(Config.GLOG_Event,"Checking `"+ExitList.get(K)+"` is  not an OnionMail compatible server!");
						if (rs==1) Log("Verify `"+ExitList.get(K)+"` is an Hybrid OnionMail Server");
						}
				if (rs==0||rs==2) {
						rme+=K+"\n"; 
						if (Config.Debug) Log("Verify `"+ExitList.get(K)+"`=`"+rs+"`");
						} else if (Config.Debug) Log("Verify `"+ExitList.get(K)+"` Ok");
				}
			rme=rme.trim();
				if (rme.length()>0) {
				String[] rmea=rme.split("\\n+");
				cx = rmea.length;
				for (int ax=0;ax<cx;ax++) {
					ExitList.remove(rmea[ax]);
					Log(Config.GLOG_Event,"Exit/Enter server error `"+rmea[ax]+"`");
					}
				}
			
			byte[][] Ks = J.DerAesKey(Sale, Const.KD_ExitList);
			cx = ExitList.size();
			byte[] b = J.HashMapPack(ExitList);
			b = Stdio.AESEnc(Stdio.GetAESKey(Ks[0]), Ks[1], b);
			Stdio.file_put_bytes(Maildir+"/feed/inet",b);
			b=null;
			J.WipeRam(Ks);
			Ks=null;
			System.gc();
			Log("Search Exit End, "+cx+" node found");
			
			}
		
		public ExitRouteList GetExitList() throws Exception {
			if (!new File(Maildir+"/feed/inet").exists()) return new ExitRouteList();
			byte[][] Ks = J.DerAesKey(Sale, Const.KD_ExitList);
			byte[] b = Stdio.file_get_bytes(Maildir+"/feed/inet");
			b = Stdio.AESDec(Stdio.GetAESKey(Ks[0]), Ks[1], b);
			J.WipeRam(Ks);
			Ks=null;
			ExitRouteList r = ExitRouteList.fromHashMap(J.HashMapUnPack(b));
			
			b=null;
			System.gc();
			return r;
			}		

		public boolean CanEnterExit(String addr,boolean in1) {
			if (ExitEnterPolicyBlock==null) return true;
			int a = -1;
			if (ExitEnterPolicyBlock.containsKey(addr)) {
					a = ExitEnterPolicyBlock.get(addr);
					if (a==0) return true;
					if (in1 && (a&SrvIdentity.EXP_NoEntry)!=0) return false;
					if (!in1 && (a&SrvIdentity.EXP_NoExit)!=0) return false;
					}
			
			String s= "*@"+J.getDomain(addr);
			
			if (ExitEnterPolicyBlock.containsKey(s)) {
					a = ExitEnterPolicyBlock.get(s);
					if (a==0) return true;
					if (in1 && (a&SrvIdentity.EXP_NoEntry)!=0) return false;
					if (!in1 && (a&SrvIdentity.EXP_NoExit)!=0) return false;
					}
			
			return true;
		}
		
		public String UserMSGParam(String local,String par,String val) throws Exception {
			par=par.toLowerCase().trim();
			HashMap <String,String> H = UsrGetConfig(local);
			String v=val.trim();
					
			if (par.compareTo("lang")==0) {
					v= J.GetLangSt(v);
					if (v!=null) H.put("lang", v);
					}
			
			if (par.compareTo("exitdomain")==0) {
				ExitRouteList RL = GetExitList();
				String sv = RL.SelectOnion(v);
				
				if (sv==null && EnterRoute) {
					H.put("exitdomain", ExitRouteDomain);
					H.put("exitonion", Onion);
					} else if (sv!=null) {
					v = RL.GetDomain(sv);
					H.put("exitdomain", v);
					H.put("exitonion", sv);
					} else throw new Exception("@500 Can't set exit domain `"+val+"`");
				}
			
			UsrSetConfig(local, H);
			String txt="";
			for(String K:H.keySet()) txt+=K+": "+H.get(K)+"\n";
			return txt;
		}
		
		
		//////////////
				
		public void SSLSaveNew(javax.security.cert.X509Certificate[] C, String host) throws Exception {
			host=host.toLowerCase().trim();
			byte[] hash = LibSTLS.CertHash(C, host);
			byte[] cat = LibSTLS.CCert2Arr(C);
			String fn = GetFNName(host)+".crt";
			byte[][] X = J.DerAesKey(Sale, host);
			cat = Stdio.AES2Enc(X[0], X[0], cat);
			Stdio.file_put_bytes(fn, cat);
			cat=null;
			J.WipeRam(X);
			X=null;
			Stdio.file_put_bytes(fn+"h", hash);
			System.gc();
			}
		
		public byte[] SSLReqHash(String host) throws Exception {
			String fn = GetFNName(host)+".crth";
			if (!new File(fn).exists()) return null;
			return Stdio.file_get_bytes(fn);
			}
		
		public byte[][] LoadCRT(String host) throws Exception {
			host=host.toLowerCase().trim();
			String fn = GetFNName(host)+".crt";
			if (!new File(fn).exists()) return null;
			byte[][] X = J.DerAesKey(Sale, host);
			byte[] in = Stdio.file_get_bytes(fn);
			in = Stdio.AES2Dec(X[0], X[0], in);
			return LibSTLS.ExtractChain(in);
		}
		
		public PublicKey[] LoadKeys(String host) throws Exception {
			host=host.toLowerCase().trim();
			String fn = GetFNName(host)+".crt";
			if (!new File(fn).exists()) return null;
			byte[][] X = J.DerAesKey(Sale, host);
			byte[] in = Stdio.file_get_bytes(fn);
			in = Stdio.AES2Dec(X[0], X[0], in);
			return LibSTLS.ExtractChainK(in);
		}
		
		public PublicKey LoadRSAKeys(String host) throws Exception {
			host=host.toLowerCase().trim();
			String fn = GetFNName(host)+".crt";
			if (!new File(fn).exists()) return null;
			byte[][] X = J.DerAesKey(Sale, host);
			byte[] in = Stdio.file_get_bytes(fn);
			in = Stdio.AES2Dec(X[0], X[0], in);
			PublicKey[] T= LibSTLS.ExtractChainK(in);
			int cx =T.length;
			for (int ax=0;ax<cx;ax++) if (T[ax].getAlgorithm().compareToIgnoreCase("RSA")==0) return T[ax];
			return null;
		}
		
		public void SSLVerify(javax.security.cert.X509Certificate[] C, String host) throws Exception {
			host=host.toLowerCase().trim();
			String fn = GetFNName(host)+".crt";
			byte[] hash = LibSTLS.CertHash(C, host);
			
			if (!new File(fn).exists()) {
				int cx= C.length; 
				for (int ax=0;ax<cx;ax++) C[ax].checkValidity();
				Log("New SSL CRT for `"+host+"`");
				SSLSaveNew(C,host);
				///SSLToVerify.put(host, Stdio.Dump(hash).toLowerCase());
				return;
				}
			
		byte[][] X = J.DerAesKey(Sale, host);
		String t0 = fn+"h";
		if (new File(t0).exists()) {
			byte[] h1 = Stdio.file_get_bytes(fn+"h");
			if (!Arrays.equals(h1,hash)) throw new Exception("@500 SSL Hash not match `"+host+"`");
			}
		
		byte[] in = Stdio.file_get_bytes(fn);
		in = Stdio.AES2Dec(X[0], X[0], in);
		LibSTLS.VerifyChain (in,C,host);
		if (Config.Debug) Log("SSL OK For `"+host+"` CryptHash `"+Stdio.Dump(LibSTLS.CertHash(C, host))+"`");	
		}
		
		//////////////
		
		public RemoteKSeedInfo[] RemoteDoKCTLAction(String action,String crt, String foronio,String Psw) throws Exception {
			
			RemoteKSeedInfo[] pw = CreateRemoteKCTLPasswords(crt, foronio, Psw);
			Log("Begin KCTL Actions for `"+foronio+"`");
			int cx = pw.length;
			boolean isDel = action.compareToIgnoreCase("del")==0;
			String[][] cmds;
			for (int ax=0;ax<cx;ax++) {
				if (isDel) {
					cmds = new String[][] { new String[] { "del" } } ;
					} else {
					cmds = new String[][] {
							action.split("\\s+") 		,
							new String[] { "cnf" }	}
							;}
					
				SrvPushOption(pw[ax].Onion,pw[ax].Password,cmds,false,null, null,null);
				int ix = isDel ? 0 :1;
				if (ix>cmds.length-1 || cmds[ix].length<2) {
						pw[ax].Ok=false;
						Log("Request KCTL `"+pw[ax].Onion+"` GeneralError");
						pw[ax].Confirm="";
						continue;
					}
				
				String cf = cmds[ix][1];
				pw[ax].Ok = VerifyRemoteKCTLRe(pw[ax].Confirm, cf);
				Log("Request KCTL `"+pw[ax].Onion+"` "+ (pw[ax].Ok ? "Ok" : "Error: "+cf));
				pw[ax].Confirm=cf;
				pw[ax].Password="";
				
			}
			return pw;
		}
	
		public void ChechPendingSSL(HashMap <String,String> hls,String[] SrvA) throws Exception { //TODO Da usare!
			int scx=SrvA.length;
			HashMap <String,HashMap <String,Integer>> shp = new HashMap <String,HashMap <String,Integer>>();
			HashMap <String,Integer> srverr = new HashMap <String,Integer> ();
				for (int sax = 0;sax<scx;sax++) {
					String oni = SrvA[sax].toLowerCase();
					int serr=0;
					
					try {
						if (Config.Debug) Log("VerifySSLArray to `"+oni+"`");
						serr = 	GetSSLHashToServer(hls,oni,shp);						
						srverr.put(oni, serr);
						} catch(Exception E) {
						String ms = E.getMessage();
						if (ms.startsWith("@")) {
							Log("Verify SSLArray: `"+oni+"` "+ms);
							} else {
							Config.EXC(E, "GetSSLHashToServer(`"+oni+"`)");
							continue;
							}
						}
					if (serr>0) Log("TRUST: Server `"+oni+"` has "+serr+" wrong certificates");
					}//for_srv
			
			HashMap <String,String> thb = new HashMap <String,String>();
			for (String K:shp.keySet()) {
				String[] r0 = GetRightSSLH(K,hls,shp);
				if (r0==null) continue;			
				String f0="N";
				if (hls.containsKey(K)) {
					if (hls.get(K).compareTo(r0[0])==0) f0="K";
					}
				f0+="/"+r0[1]+"/"+r0[0];
				thb.put(K, f0);
				}	
			byte[] rs = J.HashMapPack(thb);
			byte[][] X = J.DerAesKey2(Sale, "TrustDB");
			rs=Stdio.AES2Enc(X[0], X[1], rs);
			Stdio.file_put_bytes(Maildir+"/trustdb", rs);
			J.WipeRam(X);
			X=null;
			rs=null;
		}
		
		private String[] GetRightSSLH(String oni,HashMap <String,String> hls,HashMap <String,HashMap <String,Integer>> shp) throws Exception {
			
			String k=null;
			int h=0;
			if (!shp.containsKey(oni)) {
				if (!hls.containsKey(oni)) Log("TRUST: Nothing aobut `"+oni+"`");
				if (hls.containsKey(oni)) return new String[] { hls.get(oni), "0" };
				return null;
				}
			
			HashMap <String,Integer> sslint = shp.get(oni);
			for(String K:sslint.keySet()) {
				int i = sslint.get(K);
				if (i>h) {
					h=i;
					k="\n"+K+"\n";
					continue;
					}
				if (i==h) {
					if (!k.contains("\n"+K+"\n")) k+=K+"\n";
					}
				}
			
			if (!hls.containsKey(oni)) {
					Log("TRUST: Don't know `"+oni+"`");
				} else { 
					String myc = hls.get(oni);
					if (k.contains("\n"+myc+"\n")) return new String[] { myc,"1" };
				}
			k=k.trim();
			String st[] = k.split("\\n+");
			Log(Config.GLOG_Event,"TRUST: Another SSLHASH `"+k.replace("\n", "`, `")+"` for `"+oni+"`");
			if (st.length==1) return new String[] { st[0] ,h+"" };
			Log(Config.GLOG_Event,"TRUST: Too many SSLHASH for `"+oni+"`");
			return null;
		}
		
		
		public int GetSSLHashToServer(HashMap <String,String>  lst,String oni,HashMap <String,HashMap <String,Integer>> shp) throws Exception {
			int sslerr=0;
			Socket	RS=null;
			OutputStream RO=null;
			BufferedReader RI=null;
			SMTPReply Re=null;
			boolean SupTORM=false;
			
			
			try {
			
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, oni,25);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (VERFSSL)"); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (VERFSSL)");
					SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
					if (!SupTORM) throw new Exception("@500 VERFSSL: Server `"+oni+"` doesn't support TORM");
					
					for (String K:lst.keySet()) {
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM WHO "+K);
						if (Re.Code<200 || Re.Code>299) continue;
						byte[] h = Re.getData();
						String hs = Stdio.Dump(h).toLowerCase();
						
						if (shp.containsKey(K)) {
							HashMap<String, Integer> im = shp.get(K);
							int ix = 0;
							if (im.containsKey(hs)) ix = (int)  im.get(hs); 
							ix++;
							im.put(hs, ix);
							if (im.size()>1) sslerr++;
							shp.put(K, im);
							} else {
							HashMap<String, Integer> im = new HashMap <String,Integer>();
							im.put(hs, 1);
							shp.put(K, im);
							}
		
					}
					try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception I) {}
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
		
			} catch(Exception E) {
					try { RS.close(); } catch(Exception Ii) {}
					try { RO.close(); } catch(Exception Ii) {}
					try { RI.close(); } catch(Exception Ii) {}
					throw E;
					}
		
		return sslerr;
		}
		
		private void CleanDer() throws Exception {
			String rm="";
			int TCR = (int)(System.currentTimeMillis()/1000);
			for (String k:SrvDerToday.keySet()) {
				int[] d = SrvDerToday.get(k);
				if (TCR>d[0]) rm+=k+"\n";
			}
			rm=rm.trim();
			String[] rms=rm.split("\\n+");
			int cx=rms.length;
			for (int ax=0;ax<cx;ax++) SrvDerToday.remove(rms[ax]);
			if (SrvDerToday.size()==0) SrvDerToday = new HashMap <String,int[]>();
			
		}

		public String[] RequildFriendsList() {
			if (!new File(Maildir+"/friends").exists()) return Config.FriendServer;
			try {
				String oni="\n";
				int cx = Config.FriendServer.length;
				for (int ax=0;ax<cx;ax++) {
					String o =Config.FriendServer[ax].toLowerCase().trim()+"\n";
					if (!(oni+"\n").contains("\n"+o)) oni+=o;
					}
				
				byte[][] t0 = J.DerAesKey(Sale, "Friends");
				byte[] raw = Stdio.file_get_bytes(Maildir+"/friends");
				raw = Stdio.AES2Dec(t0[0], t0[1], raw);
				t0 = Stdio.MxDaccuShifter(raw,Const.MX_Friends);
				cx = t0.length;
				for (int ax=0;ax<cx;ax++) {
					String o =new String(t0[ax]);
					o=o.toLowerCase().trim()+"\n";
					if (!(oni+"\n").contains("\n"+o)) oni+=o;
					}
				
				oni=oni.trim();
				return oni.split("\\n+");
				} catch(Exception E) {
				Config.EXC(E, "ReqFriendList(`"+Onion+"`)");	
				return Config.FriendServer;
				} 
		}
			
		//////////////////////////////// KCTL Section /////////////////////////////////////////////////
				
		public String CreateRemoteKCTL(RemoteKSeedInfo[] Item,String Psw,String foronio) throws Exception {
			byte[] salt = new byte[32];
			Stdio.NewRnd(salt);
			foronio=foronio.toLowerCase().trim();
			foronio=Stdio.Dump(Stdio.md5a(new byte[][] { salt,foronio.getBytes() })).toLowerCase();
			String crt=foronio+"\n";
			int cx = Item.length;
			for (int ax=0;ax<cx;ax++) {
				if (!Item[ax].Ok) {
					Log("KCTL `"+Item[ax].Onion+"` Not Ok");
					continue;
					}
				String oni = Item[ax].Onion.toLowerCase().trim();
				String ps = Item[ax].Password.trim(); // rawpassword
				String cnf = Item[ax].Confirm.trim(); //confirmcode
				String itd = Item[ax].SecData.trim(); //internaldata

				if (oni.length()==0 || ps.length()==0 || cnf.length()==0 || itd.length()==0) {
					Log("KCTL/Content `"+Item[ax].Onion+"` Not Ok");
					continue;
					}
				
				crt+=oni+"\t"+ps+"\t"+cnf+"\t"+itd+"\n";
				}
			crt=crt.trim();
			byte[] b0 = crt.getBytes();			//Dati
			byte[] v0 = Stdio.md5(b0);			//Md5 Dati
			byte[][] X = J.DerAesKey2(salt, Psw);		
			b0=Stdio.AES2Enc(X[0], X[1], b0);	//Crittati in AES 256 con sale
			X = J.DerAesKeyB2(v0, Stdio.sha1a(new byte[][] { Psw.getBytes() , salt })); //Seconda chiave
			b0=Stdio.AES2Enc(X[0], X[1], b0);
		
			b0 = Stdio.MxAccuShifter(new byte[][] {
					salt	,
					v0	,
					b0	}, Const.MX_RKCTL);
			
			J.WipeRam(X);
			X=null;
			
			return J.ASCIISequenceCreate(b0, Const.ASC_KB_KCTL);
			
		}
		
		public RemoteKSeedInfo[] CreateRemoteKCTLPasswords(String crt, String foronio,String Psw) throws Exception {
			
			byte[] b0 = J.ASCIISequenceRead(crt, Const.ASC_KB_KCTL);
			byte[][] field =Stdio.MxDaccuShifter(b0, Const.MX_RKCTL);
			byte[] v0 = field[1];
			byte[] salt = field[0];
			b0 = field[2];
			byte[][] X = J.DerAesKeyB2(v0, Stdio.sha1a(new byte[][] { Psw.getBytes() , salt })); //Seconda chiave
			field=null;
			b0=Stdio.AES2Dec(X[0], X[1], b0);
			X = J.DerAesKey2(salt, Psw);	
			b0=Stdio.AES2Dec(X[0], X[1], b0);
			J.WipeRam(X);
			X=null;
			byte[] v1 = Stdio.md5(b0);
			if (!Arrays.equals(v0, v1)) throw new Exception("Access Deinied");
			foronio=foronio.toLowerCase().trim();
			foronio=Stdio.Dump(Stdio.md5a(new byte[][] { salt,foronio.getBytes() })).toLowerCase();
			crt = new String(b0);
			b0=null;
			
			String[] li = crt.split("\\n+");
			if (li[0].compareTo(foronio)!=0) throw new Exception("KCTL: Not for this onion!");
			
			int cx = li.length;
			RemoteKSeedInfo[] RS = new RemoteKSeedInfo[cx-1];
			for (int ax=1;ax<cx;ax++) {
				String[] tok = li[ax].split("\\t");
				if (tok.length!=4) {
					Log("CreateRemoteKCTLAction: Invalid KCTL line: `"+li[ax]+"`");
					continue;
					}
				int bx=ax-1;
				RS[bx] = new RemoteKSeedInfo();
				RS[bx].Onion = tok[0];
				String rtok = CreateRemoteKCTLToken(tok[3]);
				RS[bx].Password="#"+rtok;
				RS[bx].Confirm=tok[tok.length-1];
				RS[bx].Ok=true;
				}
				
			return RS;
		}
		
		public String CreateRemoteKCTLToken(String intData) throws Exception {
			long tcr = (int) (Math.floor(System.currentTimeMillis()/86400000));
			String[] tok = new String[] { Long.toString(tcr,36) , Long.toString( 0x7FFFFFFFFFFFFFFFL & Stdio.NewRndLong() ,36) , "" };
			byte[] b0 = Stdio.HexData(intData);
			b0 =  Stdio.md5a(new byte[][] {b0 , tok[0].getBytes(), tok[1].getBytes() });
			tok[2] = Stdio.Dump(b0).toLowerCase();
			b0=null;
			return tok[0]+"-"+tok[1]+"-"+tok[2];
			}
		
		public boolean VerifyRemoteKCTLRe(String intData,String line) throws Exception {
			String[] tok = line.split("\\s+");
			if (tok.length<3) return false;
			byte[] InternalData = Stdio.HexData(intData);
			String a0 = tok[1].trim();
			byte[] b0 = Stdio.md5a(new byte[][] { InternalData , a0.getBytes() });
			String b0s=Stdio.Dump(b0);
			return tok[2].compareToIgnoreCase(b0s)==0;
			}
		
		///////////////////////////////////// BOOT SECTION ///////////////////////////////////
		
		public void CreateBoot() throws Exception {
			if (CVMF3805TMP==null) throw new Exception("Cant create BOOT without `CVMF3805TMP`");
							
			Log("Create BOOT");
			try {
						String[] slist = RequildFriendsList();
						String s0="\n";
						int cx= slist.length;
						for (int ax=0;ax<cx;ax++) {
								String fn="\n"+slist[ax].toLowerCase().trim()+"\n";
								/*		if (!OnTheSameMachine.contains(fn) && s0.contains(fn)) */ s0+=slist[ax].toLowerCase().trim()+"\n"; //TODO RIABILITA!
								}
											
						s0=s0.trim();
						slist=s0.split("\\n+");
						if (slist.length==0 || s0.length()==0) throw new Exception("No server available to build  BootSequence file");
						RemoteKSeedInfo[] info = new RemoteKSeedInfo[slist.length];
						byte[] rky = Stdio.MXImplode(CVMF3805TMP, 0x7C01F6C7);		//Implode Server KeyBlock 0x7C01F6C7 is the magic number
						J.WipeRam(CVMF3805TMP);		//Destroy KeyBlock
						CVMF3805TMP=null;
						System.gc();  //try to garbage
						
						byte[] boot = CreateBootSequence(slist, MaxServerDERKPoint, info, rky); // Create boot sequence
						byte[] test = Stdio.sha1(rky); // Key verify
						J.WipeRam(rky); //Destroy the key
						rky=null;
						System.gc();
						
						//Create the BOOT file
						boot = Stdio.MXImplode(new byte[][] {
												"OnionBoot".getBytes(),				// 0 Magic Number
												test		,										// 1 Test sha1
												boot		}										// BOOT sequences 
													, 0x7C00004);							//Magic number
											
						Stdio.file_put_bytes(Maildir+"/head/boot", boot);	//Save the file!
						boot=null;
						System.gc();
						
						//Create the KCTL ASCII SEQUENCE
						String Pwls = J.GenPassword(16, 8);
						String KCTL = CreateRemoteKCTL(info,Pwls,Onion);
						//Try to send it to the sysop ...
						try {
								String secW = J.RandomString(8);
								
								HashMap <String,String> H = SrvSMTPSession.ClassicHeaders("server@"+Onion, "sysop@"+Onion);
								H.put("subject", "Server BOOT informations");
								String boundary="===="+J.RandomString(32)+"=";
								H.put("mime-version", "1.0");
								H.put("content-type","multipart/mixed;  boundary=\""+boundary+"\"");
								
								String msg = "This is a multi-part message in MIME format.\n\n--"+boundary+"\n";
									msg+="Content-Type: text/plain; charset=UTF-8\n";
									msg+="Content-Transfer-Encoding: 8bit\n\n";
									msg+="This is the KCTL sequence to remote control the boot sequence\n";
									msg+="of the server.\nThe password is:\n"+Pwls+"\n\n";
									msg+="Use this to destroy/lock/unlock the remote keys.\n\n";
									msg+="To avoid fake messages compares the code with the following in the logs on this server.\n";
									msg+="Server: "+Nick+"\n";
									msg+="SECRET CODE `"+secW+"`\n\n";
									msg+="--"+boundary+"\n";
									msg+="Content-Type: text/plain; name=\"KCTL_SEQUENCE.txt\"\n";
									msg+="Content-Disposition: attachment; filename=\"KCTL_SEQUENCE.txt\"\n";
									msg+="Content-Transfer-Encoding: 8bit\n\n";
									msg+=KCTL.replace("\r", "")+"\n--"+boundary+"--\n\n";
								Log(Config.GLOG_Server,"Sending KCTL to sysop user");
								SendLocalMessage("sysop",H,msg);
								Log(Config.GLOG_Server,"SECRET CODE `"+secW+"`");
							} catch(Exception E) {
								// ... or save to the sysop.txt
								Config.EXC(E, "SaveKTCL");
								Log(Config.GLOG_Server,"Saving KCTL data to sysop.txt");
								PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(Maildir+"/sysop.txt", true)));
								out.println("KCTL: Password: "+Pwls);
								out.println();
								out.println(KCTL);
								out.close();
							}
				
						//Apply keyblock delete policy
						if (Main.NoDelKeys==false &&	new File(Maildir+"/boot").exists() && new File(Maildir+"/keyblock.txt").exists()) {
								Log(Config.GLOG_Server,"KeyBlock removed after boot Save");
								try { J.Wipe(Maildir+"/keyblock.txt", false); } catch(Exception E) { Config.EXC(E, "SPRKD "+Onion); }
								}
						
				Log("BootSequence created");
						} catch(Exception EX) {
									//On error wipe the KeyBlock
									if (CVMF3805TMP!=null) J.WipeRam(CVMF3805TMP);
									CVMF3805TMP=null;
									Config.EXC(EX, "SCBF`"+Onion+"`"); 
						}		
			
		}
		
		/**
		 * Boot the server
		 *  
		 * **/
		public boolean Boot() throws Exception {
		if (!new File(Maildir+"/head/boot").exists()) return false;
		Status |= SrvIdentity.ST_Booting;
		int st=0;
		try {
			Log(Config.GLOG_Server,"Try to boot from network");
			byte[] boot = Stdio.file_get_bytes(Maildir+"/head/boot");
			st=1;
			byte[][] field = Stdio.MXExplode(boot, 0x7C00004);
			if (!new String(field[0]).contains("OnionBoot")) {
					Status = SrvIdentity.ST_Error;
					throw new Exception("RC6007: Invalid BOOT file");
					}
						
			byte[] test = field[1];
			boot = field[2];
			field=null;
			boot = RunBootSequence(boot,test);

			if (boot==null) {
					Status = SrvIdentity.ST_Error;
					throw new Exception("RC6008: No BOOT data found into the network!");
					}
			
			Log(Config.GLOG_Server,"Opening server by boot");
			byte[][] rky = Stdio.MXExplode(boot,  0x7C01F6C7);
			st=2;
			Open(rky);
		} catch(Exception E) {
			Log(Config.GLOG_Server,"ServerBoot: `"+Onion+"` ST"+st+" "+E.getMessage());
			Status = SrvIdentity.ST_Error;
			return false;
		}
		Status |= SrvIdentity.ST_BootOk;
		Log("Server BOOT complete!");
		return true;
	} 
		
		/**
		 * Do the boot sequence 
		 * **/
		private byte[] RunBootSequence(byte[] in,byte[] test) throws Exception {
			byte[][] boo = Stdio.MxDaccuShifter(in,  Const.MX_1_Boot);
			int cx=boo.length;
			Log(Config.GLOG_Server,"Running BOOT sequence");
			for (int ax=0;ax<cx;ax++) {
				byte[] bt = boo[ax];
				if (bt.length==0) continue;
				try {
					byte[] out = SrvGetRemoteKey(bt);
					if (out!=null && out.length!=0) {
							byte[] t = Stdio.sha1(out);
							if (!Arrays.equals(t, test)) throw new Exception("Wrong DERK F(x)");
							return out;
							}
				} catch(Exception E) {
					Log("Boot Sequence `"+ax+"` Error: "+E.getMessage());
				}
			}
			return null;
		}
		
		
		/** 
		 * INTERNAL
		 * Create the boot sequence
		 * SrvA	<- Array of servers hostname
		 * info <- Pointer to new RemoteKSeedInfo[SrvA.lenth]
		 * data <- Data to store.  
		 * **/
		private  byte[] CreateBootSequence(String[] SrvA,int points,RemoteKSeedInfo[] info,byte[] data) throws Exception {
			int scx = SrvA.length;
			byte[][] boot = new byte[scx][];
			int okb=0;
			for (int sax =0;sax<scx;sax++) {
				try {
					RemoteKSeedInfo r = SrvCreateRemoteKey(SrvA[sax],points,data.clone());
					boot[sax]=r.bytes;
					r.bytes=null;
					info[sax]=r;
					info[sax].Ok=true;
					okb++;
				} catch(Exception E) {
					boot[sax]=new byte[0];
					info[sax] = new RemoteKSeedInfo();
					info[sax].Onion = SrvA[sax];
					info[sax].Ok=false;
					String ms = E.getMessage();
					if (ms.startsWith("@")) Log("Server: `"+SrvA[sax]+"` "+ms.substring(1)); else Config.EXC(E, "CreateBootSeq(`"+SrvA[sax]+"`)");
				}
			if (okb<Config.MinBootDerks) throw new Exception("@Unable to create the BOOT / DERK / F(x) sequence. Participating too few servers. `"+okb+"`");
			}
			return Stdio.MxAccuShifter(boot, Const.MX_1_Boot);
		}
		
		/**
		 * Execute a single BOOT sequence
		 * 
		 * */
		public byte[] SrvGetRemoteKey(byte[] in) throws Exception {
			byte[][] Cobj = Stdio.MxDaccuShifter(in, Const.MX_E_Boot);
			if (new String(Cobj[0]).compareTo("DERK")!=0) throw new Exception("@Invalid BOOT sequence!");
			String onion = new String(Cobj[3]);
			onion=onion.toLowerCase().trim();
			
			byte[][] rs = SrvDoDer(Cobj[4], onion,Cobj[1], Cobj[2]); 
			
			byte[] verakey = J.Der2048(Cobj[5], rs[0]); //rand , REMOTE DERK F(x)
			byte[] kblo = Stdio.AESDecMulP(verakey, Cobj[6]);
			J.WipeRam(verakey);
			verakey=null;
			return kblo;
		}
		
		/*
		 * 
DERK/boot

byte[][] Cobj = new byte[][] {
						"DERK".getBytes()	,		//0 Sign
						r0[1]						,		//1 KeyHash
						r0[2]						,		//2 DataHash								
						oni.getBytes()			,		//3 Onion
						ind0							,		//4 Init_data
						locrnd						,		//5 rand
						kblo							}		//6 kblo
						;
	

		 * 
		 * */
		
		
		/////////// DERK Client /////////////// ////////////////////////////////////////// DERK SECTION ////////////////////
		/**
		 * Create a remote DERK
		 **/
		public RemoteKSeedInfo SrvCreateRemoteKey(String oni,int points,byte[] data) throws Exception {
			
			String[][] cmds = new String[][] {	// TORM PUSH script
						new String[]  {"new"}	,		// create DERK
						new String[]  {"gets"} ,		// get sec data
						new String[]  {"max" , Integer.toString(points) } ,	// set points 
						new String[]  {"start"} ,		// restart 
						new String[]  {"derk"} ,		// doDerk 
						new String[]  {"start"} }		// restart 
					;
			
			byte[] ind0 = new byte[512];		//x for remote DERK f(x)
			Stdio.NewRnd(ind0);
			byte[][] r0 = SrvPushOption(oni,"",cmds,true,ind0,null,null);
			// { dta,KeyH,DataH,pwl==null ? null : pwl.getBytes() };
			if (cmds.length==0 || cmds[0].length<2) throw new Exception("@550 No reply correctly to create new DERK via TORM PUSH");
			
			String Psw = cmds[0][1];
			String Cnf = cmds[0][2];
			
			byte[] locrnd = new byte[128];
			Stdio.NewRnd(locrnd);
			byte[] verakey = J.Der2048(locrnd, r0[0]);
			byte[] kblo = Stdio.AESEncMulP(verakey, data);
			J.WipeRam(verakey);
			verakey=null;
			
			byte[][] Cobj = new byte[][] {
						"DERK".getBytes()	,		//0 Sign
						r0[1]						,		//1 KeyHash
						r0[2]						,		//2 DataHash								
						oni.getBytes()			,		//3 Onion
						ind0							,		//4 Init_data
						locrnd						,		//5 rand
						kblo							}		//6 kblo
						;
	
			byte[] rderk = Stdio.MxAccuShifter(Cobj,Const.MX_E_Boot);
			RemoteKSeedInfo rt = new RemoteKSeedInfo();
			rt.bytes = rderk;
			rt.Onion = oni.toLowerCase().trim();
			rt.Confirm=Cnf.trim();
			rt.Password = Psw.trim();
			rt.SecData = cmds[1][1].trim();
			return rt;
		}
	
	
		/**
		 * Execute some PUSH/DERK options. 
		 * **/
		
		public String SvcDoRemotePushArray(String parin) throws Exception {
			Log("Begin user/sysop remote PUSH");
			parin=parin.trim();
			String[] par = parin.split("\\n+");
			int cx = par.length;
			String[] cmd = par[0].split("\\s+");
			cmd[0]=cmd[0].toLowerCase().trim();
			String re="";
			String[][] opt = new String[][] { null };
			try {
				if ("\nset\nmax\nsstatus\n".contains("\n"+cmd[0]+"\n") && cmd.length>0) {
						int i = Config.parseInt(cmd[1], "Value", 0, 255);
						opt[0] = new String[] { cmd[0] , Integer.toString(i) };
						}
				
				if ("\nstart\ndel\n".contains("\n"+cmd[0]+"\n") && cmd.length==1) {
						opt[0] = new String[] { cmd[0] };
						}
				
				if (opt[0]==null) throw new Exception("Error on command `"+cmd[0]+"`");
			} catch(Exception E) { throw new Exception("@550 Bad command: "+E.getMessage()); } 
			
			for (int ax=1;ax<cx;ax++) {
				String[] tok = par[ax].trim().split("\\s+");
				re+="Line: "+J.Spaced(ax+"",4);
				if (tok.length!=2) {
					re+="Error invalid line `"+par[ax]+"`";
					continue;
					}				
				
				String oni = tok[0].trim().toLowerCase();
				if (!oni.matches("[a-z0-9]{16}\\.onion"))  {
					re+="Error invalid Server `"+oni+"`";
					continue;
					}				
				
				try {
					re+="`"+oni+"` ";
					String pwl = tok[1].trim();
					SrvPushOption(oni,pwl,opt,false,null, null,null);
					try { re+=opt[0][1]; } catch(Exception E) { Config.EXC(E, "Dove"); re+="???"; }
					} catch(Exception E) {
						re+="Error: "+E.getMessage();
						}
				
				re+="\n";
				}
			
		return re;
		}
		
		/**
		 * Execute a PUSH/DERK sequence script
		 * 
		 * **/
		
		public byte[][] SrvPushOption(String oni,String pwl,String[][] cmds,boolean usessl,byte[] in, byte[] KeyH,byte[] DataH) throws Exception {
				byte[] dta=null;
				Socket	RS=null;
				OutputStream RO=null;
				BufferedReader RI=null;
				SMTPReply Re=null;
				boolean SupTLS=false;
				boolean SupTORM=false;
				
				Log("Push/DERK Options to `"+oni+"`");
				try {
					
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, oni,25);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote)"); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
					SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
					
					if (!SupTORM) throw new Exception("Doesn't support TORM");
					if (usessl) {
						if (!SupTLS) throw new Exception("Doesn't support STARTTLS");
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"STARTTLS");
						if (Re.Code<200 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+" (remote)"); 
						SSLSocket SS = LibSTLS.ConnectSSL(RS, SSLClient,oni);
						CheckSSL(SS, oni,"PUSH1");
						
						RO = null;
						RO = SS.getOutputStream();
						RI=null;
						RI=J.getLineReader(SS.getInputStream());
						RS=SS;	
						
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
						if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
						} 
					
					int cx= cmds.length;
					for (int ax=0;ax<cx;ax++) {
						String cmd = cmds[ax][0].toUpperCase().trim();
						String rcmd="";
						if (cmd.compareTo("NEW")==0) {
							if (usessl) try {
									Re = SrvSMTPSession.RemoteCmd(RO,RI,"TKIM");
									if (Re.Code<299 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (remote)"); //chkkk
									byte[] rnd = Re.getData();
									try { rnd = Stdio.RSASign(rnd, SSK); } catch(Exception E) { 
											Config.EXC(E, "Push::TKIM.RSASign(`"+oni+"`)");
											rnd = new byte[0];
											}
									SMTPReply.Send(RO,220,J.Data2Lines(rnd, "TKIM/1.0 REPLY"));
									Re = new SMTPReply(RI);
									if (Re.Code<200 || Re.Code>299) Log(Config.GLOG_Event,"PUSH::TKIM: `"+oni+"` Error: "+Re.toString().trim());
									} catch (Exception EK) {
										String ms = EK.getMessage();
										if (ms.startsWith("@")) Log ("Error: `"+oni+"` "+ms.substring(1)); else Config.EXC(EK, "PUSH::TKIM `"+oni+"`");
									}

							Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM PUSH NEW");
							if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
							pwl=Re.Msg[0].trim();
							cmds[ax] = new String[] { "new",Re.Msg[0].trim(), Re.Msg[1].trim() };
							continue;
							}
						
						if (cmd.compareTo("DERK")==0) {
							byte[][] X = DoRawDERK(RO, RI, in, KeyH, DataH, oni);
							dta = X[0];
							KeyH=X[1];
							DataH=X[2];
							continue;
							}
						
						rcmd="TORM PUSH "+cmd+" "+pwl;
						int dx=cmds[ax].length;
						for (int bx=1;bx<dx;bx++) rcmd+=" "+cmds[ax][bx];
						Re = SrvSMTPSession.RemoteCmd(RO,RI,rcmd);
					
						if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
						cmds[ax]= new String[] {cmd.toLowerCase() , Re.Msg[0].trim() };
						}
					
					try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception Ii) {}
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
				} catch(Exception E) {
					if (RS!=null && RS.isConnected()) try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception Ii) {}
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
					Log("PUSH Option `"+oni+"` Error: "+E.toString().replace("@", ""));
				}
			return new byte[][] { dta,KeyH,DataH,pwl==null ? null : pwl.getBytes() };
		}
	
		/**
		 * Execute a Single remote DERK f(x) action.
		 * 
		 * **/
		
		public byte[][] SrvDoDer(byte[] in, String oni,byte[] KeyH,byte[] DataH) throws Exception {
			byte[][] X=null;
			
			Socket	RS=null;
			OutputStream RO=null;
			BufferedReader RI=null;
			SMTPReply Re=null;
			boolean SupTORM=false;
			byte[] dta=null;
			
			try {
			
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, oni,25);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (DERK)"); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (DERK)");
					SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
					if (!SupTORM) throw new Exception("@500 DERK: Server `"+oni+"` doesn't support TORM");
					
					X = DoRawDERK(RO,RI,in,KeyH,DataH,oni);
										
					try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception I) {}
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
					
			} catch(Exception E) {
					try { RS.close(); } catch(Exception Ii) {}
					try { RO.close(); } catch(Exception Ii) {}
					try { RI.close(); } catch(Exception Ii) {}
					throw E;
					}
					
		return X;
		}
		
		/**
		 * Raw Client DERK operation into an opened SMTP session.
		 * 
		 * **/
		
		public static byte[][] DoRawDERK(OutputStream RO,BufferedReader RI,byte[] in ,byte[] KeyH,byte[] DataH,String oni) throws Exception {
				SMTPReply Re=null;
				
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM K");
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (DERK)");
				byte[] dta = Re.getData();
				byte[] test = Stdio.sha1(dta);
				if (KeyH!=null && !Arrays.equals(test, KeyH)) throw new Exception("@500 DERK: Server KEY error `"+oni+"`");
				if (KeyH==null) KeyH = test;
				
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM DERK");
				if (Re.Code!=334) throw new Exception("@"+Re.toString().trim()+ " (DERK)");
				
				PublicKey ks = Stdio.Arr2Public(dta);
				
				byte[] key = new byte[32];
				byte[] iv = new byte[16];
				Stdio.NewRnd(key);
				Stdio.NewRnd(iv);
				in = Stdio.MxAccuShifter(new byte[][] { key, iv, in},Const.MX_DERK);
				dta = Stdio.RSAEncDataP(in, ks, 256); 
					
				SMTPReply rp = new SMTPReply(334, dta,"FUFFA/1.0");
				rp.Send(RO);
					
				Re = new SMTPReply(RI);
				if (Re.Code>399) throw new Exception("@"+Re.toString().trim()+" (DERK)");
				dta=Re.getData();
				try { dta = Stdio.AES2Dec(key, iv,dta); } catch(Exception E) { throw new Exception("@550 Invalid Return AES Key"); }
				
				test = Stdio.sha1(dta);
				if (DataH!=null && !Arrays.equals(test, DataH)) throw new Exception("@500 DERK: Server DATA error `"+oni+"`");
				if (DataH==null) DataH = test;
				
			return new byte[][] { dta, KeyH,DataH,null };
			
		}
		
		/////////// DERK SERVER //////////
		
		/**
		 * Server operation DERK f(x) into an opened server SMTP session.
		 **/
		
		public SMTPReply SrvDer(SMTPReply Re,String onion) throws Exception {
			int TCR = (int)(System.currentTimeMillis()/1000);
			onion=onion.toLowerCase().trim();
			
			if (SrvDerToday.containsKey(onion)) {
				int[] inf = SrvDerToday.get(onion);
				if (TCR<inf[0] && inf[1]>3) throw new PException("@550 Too many DERK for `"+onion+"`"+" try before `"+J.TimeStandard(inf[0]+1)+"`");
				inf[1]++;
				SrvDerToday.put(onion, inf);
				} else {
				SrvDerToday.put(onion, new int[] { TCR+86400, 1 });	
				}
			byte[] in = Re.getData();
						
			RemoteDerK RK = RemoteDerK.Load(this, onion);
			if (RK==null) throw new PException("@500 No DERK for `"+onion+"`, please PUSH new!");
			int s = RK.getStatus();
			if (s!=1) {
				if (s==RemoteDerK.ST_Disabled) throw new PException("@550 DERK Disabled for `"+onion+"`");
				if (s==RemoteDerK.ST_Sfiduciato) throw new PException("@550 DERK Disabled by `ROOT` for `"+onion+"`");
				throw new PException("@550 DERK Error status `"+s+"` for `"+onion+"`");
				}
			
			s=RK.getCredit();
			if (s<1) throw new PException("@550 DERK: No credit for `"+onion+"`, please restart!");
			Log(Config.GLOG_Event,"DERK Request for `"+onion+"`");
			byte[][] F;
			byte[] key;
			byte[] iv;
					
			try { 
					in = Stdio.RSADecDataP(in, SSK, 256);
			
					if (in.length<64) throw new Exception("S");
					F = Stdio.MxDaccuShifter(in, Const.MX_DERK);
					if (F.length<3) throw new Exception("F");
					key=F[0];
					iv=F[1];
					in=F[2];
					if (in.length<1) throw new Exception("D");
					if (iv.length!=16) throw new Exception("IV");
					if (key.length!=32) throw new Exception("KEY");
					
					in =RK.Computa(in);
					in = Stdio.AES2Enc(key, iv, in);
					
				} catch(Exception E) {
					Config.EXC(E, "SrvDer(`"+onion+"`)");
					throw new PException("@500 Invalid FUFFA seqence!");
				}
			return new SMTPReply(220,in,"DERK/1.0 TCR="+J.TimeStandard(Time()));
		}		
		
		private String PGPKeyFile(String user) throws Exception {
			byte[] by = Stdio.md5a(new byte[][] { user.toLowerCase().trim().getBytes() , Sale , user.toUpperCase().trim().getBytes() });
			long rx=0;
			for (int ax=1;ax<9;ax++) {
				rx<<=8;
				rx^=(int)(255&by[ax]);
				}
			return Maildir+"/keys/P"+Long.toString(rx,36)+".dat";
			}
		
		public boolean UserHasPGP(String user) throws Exception { return new File(PGPKeyFile(user)).exists(); }
		
		public DynaRes UserSetPGPKey(String PGPKey,String user,boolean norep) throws Exception {

			String fs = PGPKeyFile(user);
			if (!norep) PGPKey=J.ParsePGPKey(PGPKey);
			byte[] K = Stdio.sha512a(new byte[][] { Sale, user.getBytes()} );
			byte[] b = PGPKey.getBytes();
			b=Stdio.AESEncMulP(K, b);
			Stdio.file_put_bytes(fs, b);
			if (norep) return null;
			DynaRes Re = DynaRes.GetHinstance(Config, "mykey", DefaultLang);
			Re.Par.put("user", user);
			return Re;
		}
		
		public String UserGetPGPKey(String user) throws Exception {
			String fs = PGPKeyFile(user);
			
			if (!new File(fs).exists()) return null;
			String PGPKey=null;
			try {
				byte[] K = Stdio.sha512a(new byte[][] { Sale, user.getBytes()} );
				byte[] b = Stdio.file_get_bytes(fs);
				b=Stdio.AESDecMulP(K, b);
				PGPKey = new String(b);
				if (!PGPKey.contains(" PGP ") && !PGPKey.contains(" KEY ")) {
					Log("UserGetPGPKey: Crypt Key Error");
					return null;
					}
			} catch(Exception E) {
				Config.EXC(E, "UserGetPGPKey");
				return null;
			}
			return PGPKey;
		}
		
		
		//////////////////// NEWUSER VIA GPG /////////////////
		
		public DynaRes CreaNewUserViaPGP(String PGPKey,String user) throws Exception {
			
			String smtpp;
			String pop3p;
			if (user==null || user.length()==0)  user=J.RandomString(8);
			user=user.toLowerCase().trim();
						
			if (
						!user.matches("[a-z0-9\\-\\_\\.]{3,16}") 	|| 
						user.compareTo("sysop")==0 					|| 
						user.compareTo("server")==0 					|| 
						user.endsWith(".onion") 								|| 
						user.endsWith(".o") 									||
						user.endsWith(".list") 									|| 
						(user.endsWith(".sys"))								||
						(user.endsWith(".app"))								||
						(user.endsWith(".sysop"))							||
						(user.endsWith(".op"))								|| 
						user.startsWith(".") 									|| 
						user.endsWith(".") 										|| 
						user.contains("..")) 									{
				
				throw new PException("@550 Invalid or reserved user name");						
				}
			
			if (UsrExists(user)) throw new PException("@550 User arleady exists");
			smtpp=J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
			pop3p=J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
			
			HashMap <String,String> P = new HashMap <String,String>();
			P.put("lang", DefaultLang);
			P.put("flag", Const.USR_FLG_TERM);
			UsrCreate(user,pop3p, smtpp, 1,P);
					
			DynaRes re = DynaRes.GetHinstance(Config, "newuser", DefaultLang);
			re.Par.put("onionmail", user+"@"+Onion);
			re.Par.put("onion", Onion);
			re.Par.put("username", user);
			re.Par.put("pop3password", pop3p);
			re.Par.put("sha1",LibSTLS.GetCertHash(MyCert)); 
			re.Par.put("smtppassword",smtpp);
			re.Par.put("nick", Nick);
			re.Par.put("MsgSize", Integer.toString(MaxMsgSize));
			re.Par.put("MaxMsgXuser",  Integer.toString(MaxMsgXuser));
			re.Par.put("MsgOld",  Integer.toString(Config.MailRetentionDays));
			re.Par.put("Scrambler", Config.PGPEncryptedDataAlgoStr);
			re = re.Get();
						
			Log(Config.GLOG_Event, "NewUser Created via PGP `"+user+"`");
			
			pop3p="X";
			smtpp="X";
			pop3p=null;
			smtpp=null;
			System.gc();

			byte[] original = re.Res.getBytes();
			ByteArrayInputStream pubKey = new ByteArrayInputStream(PGPKey.getBytes());
			byte[] encrypted = PGP.encrypt(original, PGP.readPublicKey(pubKey), null, true, true,new Date(Time()),Config.PGPEncryptedDataAlgo);
			re.Res = new String(encrypted);
			
			if (Config.PGPSpoofVer!=null) try {
				int cx = Config.PGPSpoofVer.length;
				if (cx!=0) {
					int r = 1;
					if (cx>1) r = (int) ((0x7FFFFFFFFFFFFFFFL & Stdio.NewRndLong()) % cx);
					String spoof = Config.PGPSpoofVer[r];
					re.Res = PGP.FilterPGPNSAsMarker(re.Res, spoof);
					}
				} catch(Exception E) { Config.EXC(E, "PGP:SpoofNSA"); }
			
		return re;			
		}
		
		public void CanAndCountCreateNewUser() throws Exception {
			if (!NewUsrEnabled) throw new Exception("@550 Operation not permitted");
			int tcr = (int) Math.floor((System.currentTimeMillis()+TimeSpoofSubRandom) / 1000L);
			int day =(int) Math.floor(tcr / 86400);
			int hour = (int) Math.floor(tcr / 3600);
			
			if (hour==NewUsrLastHour) {
				if (NewUsrLastHourCnt>NewUsrMaxXHour) throw new Exception("@550 To many new user for this hour. Try again in next hour.");
				} else {
				NewUsrLastHourCnt=0;
				NewUsrLastHour=hour;
				}
			NewUsrLastHourCnt++;
			
			if (day==NewUsrLastHour) {
				if (NewUsrLastDayCnt>NewUsrMaxXDay) throw new Exception("@550 To many new user for this day. Try again tomorrow.");
				} else {
				NewUsrLastDayCnt=0;
				NewUsrLastDay=hour;
				}
			NewUsrLastDayCnt++;
			}
		
		public void CanAndCountCreateNewList() throws Exception {
			if (!NewLstEnabled) throw new Exception("@550 Operation not permitted");
			int tcr = (int) Math.floor((System.currentTimeMillis()+TimeSpoofSubRandom) / 1000L);
			int day =(int) Math.floor(tcr / 86400);
			int hour = (int) Math.floor(tcr / 3600);
			
			if (hour==NewLstLastHour) {
				if (NewLstLastHourCnt>NewLstMaxXHour) throw new Exception("@550 To many new list for this hour. Try again in next hour.");
				} else {
				NewLstLastHourCnt=0;
				NewLstLastHour=hour;
				}
			NewLstLastHourCnt++;
			
			if (day==NewLstLastHour) {
				if (NewLstLastDayCnt>NewLstMaxXDay) throw new Exception("@550 To many new list for this day. Try again tomorrow.");
				} else {
				NewLstLastDayCnt=0;
				NewLstLastDay=hour;
				}
			NewLstLastDayCnt++;
			}
		
		public String GetRunString() { 
				long x = TimeSpoofSubRandom;
				x^=x<<1;
				return Long.toString(Long.toString(x,36).hashCode(),36); 
				}
		
		// Log functions

		public void SrvSetPGPKeys() {
			Main.echo("\nDo you want to insert a PGP Public & Private key for server`"+Nick+"`\n\tYes, No ?");
					boolean re=false;
					BufferedReader In = J.getLineReader(System.in);
					
					try { re = Config.parseY(In.readLine().trim().toLowerCase()); } catch(Exception I) { Main.echo("NO\n"); }
					if (re) try {
						Main.echo("Enter the ASCII file name: >");
						String Pat = In.readLine().trim();
						Pat = new String(Stdio.file_get_bytes(Pat));
						Main.echo("Enter the Passphrase: >");
						String Pass = In.readLine().trim();
						String Priv = J.ParsePGPPrivKey(Pat);
						Pat = J.ParsePGPKey(Pat);
						UserSetPGPKey(Pat, "server",true);
						UserSetPGPKey(Priv, Const.SRV_PRIV,true);
						byte[] b = Pass.getBytes("UTF-8");
						b=Stdio.AESEncMulP(Sale, b);
						Stdio.file_put_bytes(Maildir+"/head/hldr", b);
						Main.echo("PGP Keys for `"+Nick+"` is set!\n");
						} catch(Exception EX) {
							String ms = EX.getMessage();
							Main.echo("Error: "+ms+"\n");
							Log(Config.GLOG_Server, "Can't set GPG Keys: "+ms);
							if (Config.Debug) EX.printStackTrace();
						}
		}
		
		public String GetPassPhrase() throws Exception {
			byte[] b = Stdio.file_get_bytes(Maildir+"/head/hldr");
			b=Stdio.AESDecMulP(Sale, b);
			return new String(b,"UTF-8");
		}
		
		public String PGPSpoofNSA(String armor,boolean crlf)  {
			if (Config.PGPSpoofVer!=null) try {
				int cx = Config.PGPSpoofVer.length;
				if (cx!=0) {
					int r = 1;
					if (cx>1) r = (int) ((0x7FFFFFFFFFFFFFFFL & Stdio.NewRndLong()) % cx);
					String spoof = Config.PGPSpoofVer[r];
					String armor2=armor.replace("\r\n", "\n");
					armor=PGP.FilterPGPNSAsMarker(armor2, spoof);
					armor2=null;
					if (crlf) armor=armor.replace("\n", "\r\n");
					}
				} catch(Exception E) { Config.EXC(E, "PGPSpoofNSA"); }
			return armor;
		}
		
		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, Nick, st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server, Nick, st); 	}

protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
