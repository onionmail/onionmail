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
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.URLEncoder;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.tramaci.onionmail.MailBox.Message;
import org.tramaci.onionmail.MailingList.MLUserInfo;

public class SrvIdentity {
	public String Nick = "null";
	public String Onion="null.onion";
	public String MXDomain=null;
	public InetAddress LocalIP = null;
	public InetAddress ExitIP = null;
	public boolean NewCreated = false;
	public boolean POP3CanRegister=true;
	public boolean POP3CanVMAT=true;
	public boolean NoVersion = true;
	public  static boolean CheckCertValidity = false; // É shared per tutti i server. (retrocompatiblità con vecchie versioni).
	public int RetryTime=400; 
	public boolean ShowFriends = true;
	public boolean Friendly = true;
	public boolean HTTPSServer=false;
	public boolean  forceVerifySSLHash=false;
	
	public String friendsForceAdd=null;
	
	public boolean permitDERKUpdate=true;
	
	public boolean HasHTTP=false;
	public int LocalHTTPPort = 80;		
	public String HTTPServerName=null;
	public String HTTPBasePath=null;
	public String HTTPLogFile=null;
	
	public HashMap <String,Boolean> HTTPCached = new HashMap <String,Boolean>();
	public HashMap <String,Integer> HTTPAccess = new HashMap <String,Integer>();
	public HashMap <String,String> HTTPETEXVar = new HashMap <String,String>();
	public HashMap <String,String> DefaultUserConfig = null;
	
	public String HTTPRootLogin=null;
	public String HTTPRootPass= null;
	
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
	int LastFriend=0;
	public String DefaultLang="en-en";
	
	public String logonTempString = null;
	public byte[][] logonTempData = null;
	
	public byte[] KBL = new byte[0];
	
	public int PublicControlPort=9101;
	public InetAddress PublicControlIP=null;
	
	public String ExitNotice=null;
	public boolean ExitNoticeE=true;

	public boolean NewUsersAccept=false;
	public int NewUserMax = 5;
	public int NewUserCount=0;
	public int NewUserDay=0;
	public int MaxMsgXUserXHour = 0;
	public IPList BlackList=null;
	
	public VirtualMAT VMAT = null;
	public String EnabledVMAT= null;
	public String DisabledVMAT= null;
	
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
	
	public volatile long StatSendMSGBytes = 0; 
	public volatile long StatRecvMSGBytes = 0;
	public String binaryStatsFile=null; 
	public int StatCurrentHour=0;
	
	public boolean NewUsrEnabled = false;
	public int NewUsrMaxXDay = 0;
	public int NewUsrMaxXHour = 0;
	public int NewUsrLastDay = 0;
	public volatile int NewUsrLastDayCnt = 0;
	public int NewUsrLastHour = 0;
	public volatile int NewUsrLastHourCnt = 0;
	public volatile boolean EnableRulezNews = true;
	
	public boolean NewLstEnabled = false;
	public int NewLstMaxXDay = 0;
	public int NewLstMaxXHour = 0;
	public int NewLstLastDay = 0;
	public volatile int NewLstLastDayCnt = 0;
	public int NewLstLastHour = 0;
	public volatile int NewLstLastHourCnt = 0;
	public long TimeSpoofSubRandom = 0;
	
	public int LastDayPurgeTmp = 0;
	
	public String ExitGood = null;
	public String ExitBad=null;
	//public String ExitCurrent = null;
		
	public String IdentText=null;
	
	public String LogVoucherTo=null;
	public int VoucherLength=0;
	public int MultiDeliverMaxRCPTTo=10;
	public int ExitAltPort = 10025;		
	public boolean ExitNotMultipleServerDelivery = false; 
	
	public String PGPKeyServers=null;
	
	public HashMap <String,Application> Applications = null;
	
//	public HashMap <String,String> NextCheck = new HashMap<String,String>();
	public HashMap <String,String> ManifestInfo = new HashMap <String,String>();
	///public HashMap <String,String>  SSLToVerify = new HashMap<String,String>();
	
	public int MaxServerDERKPoint=8;
	
	public HashMap <String,int[]> SrvDerToday= new  HashMap <String,int[]>();
	public volatile int MaxMsgXserverXHour = 0;
	public int[] LimSrvMHash = new int[0];
	public int[] LimSrvMHour = new int[0];
	public int[] LimSrvMMsg = new int[0];
	
	public String StatFile=null;
	
	public String OnTheSameMachine=null;
	public boolean AutoDeleteReadedMessages=true;	
	
	public volatile int statsRunningSMTPSession = 0; //TODO SaveStats
	public volatile int statsMaxRunningSMTPSession = 0;
	public volatile int statsRunningPOP3Session = 0;
	public volatile int statsMaxRunningPOP3Session = 0;
	
	public volatile boolean SSLEIDSendUserMessage = false;
	
	public HashMap<String,Integer> VMATErrorPolicy = new  HashMap<String,Integer>();
	public HashMap<String,String> IAMOnion=null;
	
	public GreyListManager greyList = null;
	public boolean useGreyList=false;
	
	public int Status = 0;
	public boolean AutoPGP=true;
	public boolean AutoPGPUpdate=false;
	public String AutoPGPID = "%n OnionMail Server";
	
	public String OnUpdateUserNews = null;
	//public boolean hasServerNotice=false;
	
	private HashMap <String,String> badSrvNum = new HashMap <String,String>();
	private HashMap <String,String> badSrvLast = new HashMap <String,String>();
	
	public static final int ST_NotLoaded=0;		//A
	public static final int ST_Loaded=1;				//B
	public static final int ST_Running=2;				//C
	public static final int ST_Booting=4;				//D
	public static final int ST_BootOk=8;				//E
	public static final int ST_FriendRun=16;		//F
	public static final int ST_FriendOk=32;			//G
	public static final int ST_Error=64;				//H
	public static final int ST_Ok=128;					//I
	
	private static final int Loop_Stats = 0x2e27810; // stats by base36.


	public String getStatus() {
		String st="";
		for (int ax=0;ax<8;ax++) if ((Status & 1<<ax)!=0) st+=Integer.toString(10+ax,36);
		return st;
	}
	
	public void SaveStat(boolean resetH) throws Exception {
			StatHcount++;
			try {				
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
			} catch(Exception E) { Log(Config.GLOG_Server, "Stat: error on `/stats` "+E.getMessage()); }
			
			if (StatFile!=null) try {
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
						StatCurrentM+";"+
						StatRecvMSGBytes+";"+
						StatSendMSGBytes+";"+
						statsMaxRunningSMTPSession+";"+
						statsMaxRunningPOP3Session+";"+
						Main.statsMaxThread+";"+
						Main.statsPercThread	)
						;
				out.close();
				} catch(Exception E) { Log(Config.GLOG_Server, "Stat: error on `"+StatFile+"` "+E.getMessage()); }
		
		GregorianCalendar  q = new GregorianCalendar();
		
		if (binaryStatsFile!=null) try {
			long[] dta = new long[] {
					((System.currentTimeMillis()+Config.TimeSpoof)/1000L) ,
					StatMsgIn,
					StatMsgOut,
					StatMsgInet,
					StatError,
					StatException,
					StatSpam,
					StatPop3,
					StatTor2TorBy,
					StatTor2InetBy,
					StatInet2TorBy,
					StatRecvMSGBytes,
					StatSendMSGBytes,
					statsMaxRunningSMTPSession,
					statsMaxRunningPOP3Session,
					Main.statsMaxThread,
					Main.statsPercThread
					}
					;
			
			int[] fmt= new int[] {
					4,
					2,
					2,
					2,
					2,
					2,
					2,
					2,
					2,
					2,
					2,
					4,
					4,
					2,
					2,
					2,
					1}
					;
			
			J.LoopFileInit(binaryStatsFile, Loop_Stats, 744, 63);
			J.LoopFileWrite(binaryStatsFile, dta, fmt);
			
			} catch(Exception E) { Log(Config.GLOG_Server, "Stat: error on `"+binaryStatsFile+"` "+E.getMessage()); }		
	 	
		
		int hour = (int) Math.floor(System.currentTimeMillis()/60000);
		
		if (StatCurrentHour==0) {
				StatCurrentHour=hour;
				return;
				}
		
		if (StatCurrentHour!=hour) {
				StatMsgIn=0;
				StatMsgOut=0;
				StatMsgInet=0;
				StatError=0;
				StatException=0;
				StatSpam=0;
				StatPop3=0;
				StatTor2TorBy=0;
				StatTor2InetBy=0;
				StatInet2TorBy=0;
				StatRecvMSGBytes=0;
				StatSendMSGBytes=0;
				statsMaxRunningSMTPSession=0;
				statsMaxRunningPOP3Session=0;
				Main.statsMaxThread=0;
				Main.statsPercThread=0;
				StatCurrentHour=hour;
			}
		
		}
	
	SrvIdentity(Config C) { 
			long a = Stdio.NewRndLong() & 0x7FFFFFFFL;
			TimeSpoofSubRandom = a % 3600000L;
			TimeSpoofSubRandom-=	1800000L;
			
			Config=C;
			Spam= null; // new Spam(C,this);
			ManifestInfo.put("info", "1.0");
			VMAT = new VirtualMAT(this);
						
	}
	
	private void StartProcs() throws Exception {
			
		try { 
			RefreshRulezList();
			SaveRulezList();
			} catch(Exception E) { Config.EXC(E, "RfShRules."+Nick); }
			
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
							try { SearchExit(); } catch(Exception EX) { Log(Config.GLOG_Bad,"SearchExit: "+EX.getMessage()); EX.printStackTrace(); }
							
							if (Main.Oper==0 && Config.UseBootSequence && !new File(Maildir+"/head/boot").exists() && logonTempData!=null) try {
									if ((Main.cmdFlags& Main.CF_D_NODERK)==0) CreateBoot();
																		
									} catch(Exception EX) { 
										if (logonTempData!=null) J.WipeRam(logonTempData);
										logonTempData=null;
										String ms = EX.getMessage();
										if (ms.contains("@")) Log(Config.GLOG_Server,ms.substring(1)); else Config.EXC(EX, "SCBF2`"+Onion+"`"); 
										}
							
							if (BlackList!=null) try { BlackList.AutoSave(); } catch(Exception EX) { Log(Config.GLOG_Bad,"BlackList AutoSave: "+EX.getMessage()); }
							} catch(Exception E) { Config.EXC(E, "ServerOp"); }
					Status |= SrvIdentity.ST_Ok;
					Log(Config.GLOG_Server,"Server Init Complete. Status `"+getStatus()+"`");
					if (logonTempData!=null) J.WipeRam(logonTempData);
					logonTempData=null;
					}
				};

			executor.scheduleAtFixedRate(ServerOp,15/* 60 + (7&Stdio.NewRndLong())*/ ,Config.srvOpEvery, TimeUnit.SECONDS); //TODO Ripiazzare!
		
			StatRun = Executors.newSingleThreadScheduledExecutor();
			Runnable StatOp = new Runnable() {
				public void run() {
					try { 
							SaveStat(true);
							} catch(Exception E) { Config.EXC(E, "StatOp"); }
					
					if (BlackList!=null) try { 
							BlackList.Garbage();
							BlackList.AutoSave();
							} catch(Exception E) { Config.EXC(E, "IPGrarbage"); }
					
					int curDay = (int)Math.floor(System.currentTimeMillis()/86400000L);
					if ( curDay!=LastDayPurgeTmp ) try {
						LastDayPurgeTmp = curDay;
						String[] tmp = new File(Maildir+"/tmp/").list();
						int cx = tmp!=null ? tmp.length : 0;
						for (int ax=0;ax<cx;ax++) {
							if (!tmp[ax].endsWith(".tmp")) continue;
								String fi =Maildir+"/tmp/"+tmp[ax];
								int fDay = (int) Math.floor(new File(fi).lastModified() /86400000L);
								if (curDay-fDay > 2) try { J.Wipe(fi, Config.MailWipeFast); } catch(Exception E2) { Config.EXC(E2, Nick+".DelLTmpFile `"+fi+"`"); }
							}
						} catch(Exception E) {
							 Config.EXC(E, Nick+".PurgeTmp");
						}
				
				
					} //run
				} ;
				
			StatRun.scheduleAtFixedRate(StatOp, 1 ,60, TimeUnit.MINUTES);
			if (binaryStatsFile!=null) try { 
					J.LoopFileInit(binaryStatsFile, Loop_Stats, 744, 31);
					} catch(Exception E) { 
						Log(Config.GLOG_Server,"BinaryStat: Error on `"+binaryStatsFile+"` "+E.getMessage()); 
					} 
	
	if (EnterRoute) try { EnableQueue(); } catch(Exception E) { 
			Config.EXC(E, "EnableQueue");
			if (Config.Debug) E.printStackTrace();
			}
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
			
		for (String p : new String[] { "", "usr" , "inbox" , "keys" , "log", "feed","head","net" ,"tmp"}) {
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
		String s = "ver: OnionMail "+Main.getVersion()+
				"\nvid: "+Long.toHexString(Main.VersionID)+
				"\nextra: "+Main.VersionExtra+
				"\ncomp: "+Main.CompiledBy+
				"\ntorm: V="+Const.TormVer+
				"\nmig: 0"+
				"\nvid_b: ";
		
		long bx = Main.VersionID;
		for (int ax=0;ax<4;ax++) {
				s+=Integer.toString((int)(bx&255));
				if (ax!=3) s+=",";
				bx>>=8;
				}
		
		s+="\nhash: "+Long.toHexString(s.hashCode())+"\n";
				
		Stdio.file_put_bytes(Maildir+"/server.tex",s.getBytes() );
		setAutoConfig();
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
					throw new Exception("@Server directory error: Unknown content or unsupported legacy server type `"+Maildir+"`");
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
	
		String[] AltName = null;
		
		if (EnterRoute && Config.AddCertSAltNames) {
			String t0 = Onion + "\n" + ExitRouteDomain ;
			if ((Main.cmdFlags & Main.CF_W_SSLNOWILC)==0) t0+="\n*."+ExitRouteDomain;
			if (MXDomain!=null) t0+="\n"+MXDomain;
			t0=t0.toLowerCase().trim();
			AltName = t0.split("\\n+");
			}
		
		MyCert = LibSTLS.CreateCert(new KeyPair(SPK,SSK), Onion, TimeFrom, TimeTo, at,AltName);
		LibSTLS.SaveCert(Maildir+"/head/data", Sale, MyCert);
		
		Main.echo("\n\t"+J.Spaced("New Cert:", 16)+"`"+J.Limited(Onion, 40)+"`");
		Main.echo("\n\t"+J.Spaced("From:", 16)+"`"+J.Limited(new Date(TimeFrom).toString(),40)+"`");
		Main.echo("\n\t"+J.Spaced("To:", 16)+"`"+J.Limited(new Date(TimeTo).toString(), 40)+"`");
		
		if (AltName!=null) {
			int cx = AltName.length;
			Main.echo("\n\tAlt Names:");
			for (int ax=0;ax<cx;ax++) Main.echo("\n\t\t"+AltName[ax]);
			}
		
		for (String K:SSlInfo.keySet()) {
			Main.echo("\n\t"+J.Spaced(K+":", 16)+"`"+J.Limited(SSlInfo.get(K), 40)+"`");
			} 
		Main.echo("\n");
		
	}
			
	public void Open(byte[][] sk) throws Exception {
		
		File F = new File(Maildir);
		if (!F.exists()) throw new Exception("Maildir doesn't exist: `"+Maildir+"`");
		
		for (String p : new String[] {  "usr" , "inbox" , "keys" , "log", "feed","head","net","tmp" }) {
			F = new File(Maildir+"/"+p);
			if (!F.exists()) throw new Exception("Can't open path `"+Maildir+"/"+p+"`");
			}
		
		for (String p : new String[] {  "net" , "data" , "local","rulez" }) {
			F = new File(Maildir+"/"+p);
			 if (!F.exists()) {
				 	if (!F.mkdir()) throw new Exception("Can't create path `"+Maildir+"/net`"); else {
				 		F.setExecutable(true, true);
				 		F.setReadable(true, true);
				 		F.setReadable(true,true);
				 		}
			 		}
			}
				 		
		if (Config.UseBootSequence && !new File(Maildir+"/head/boot").exists()) logonTempData = sk.clone(); else logonTempData=null; 
		
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
		
		if (EnterRoute && useGreyList) try { 
				greyList = new GreyListManager(this);
				} catch(Exception E) { 
				Config.EXC(E, "GreyList: `"+Nick+"`");
				greyList=null;
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
		setAutoConfig();
		if (AutoPGP) {
				if (!new File(Maildir+"/head/hldr").exists()) SrvAutoPGPKeys();
				if (AutoPGPUpdate && new File(Maildir+"/head/hldr").exists()) try {
					if (Main.ConfVars==null) Main.echo("Sending Server's PGP keys to keyserver via TOR Please wait...\n");
					PGPSendKey("server", Maildir+"/IDList");
					} catch(Exception E) {
						Log("PGPSendKey Error: "+E.getMessage());
						if (Config.Debug) E.printStackTrace();
					}
				}
		
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
	
	public MailBox UsrOpenW(Config C,String local,boolean create) throws Exception {
		String un=UFname(local);
		byte[][] U = new byte[1][];
		U[0] = Stdio.file_get_bytes(un+".idx");
		
		byte[] Pak = Stdio.sha256a(new byte[][] { Sale, local.getBytes() });
		byte[] Iavk = Stdio.md5a(new byte[][] { Pak, Sale, local.getBytes() });
		U[0] = Stdio.AES2Dec(Pak,Iavk, U[0]);
		U = Stdio.MxDaccuShifter(U[0],Const.MX_User);
		HashMap <String,String> UP = J.HashMapUnPack(U[6]);
		MailBox M = new MailBox(this,local,un+".dbf",Stdio.Arr2Public(U[3]),create); 
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
		if (O==null) O =new HashMap <String,String> ();
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
	
	public void DelUserCrawler() throws Exception {
		byte[] k1 = Stdio.sha256a(new byte[][] { Subs[4], Sale ,Subs[13]});
		byte[] iv = Stdio.md5a(new byte[][] { k1, Subs[14] });
		String fil=Maildir+"/oper.idx";
		
		byte[] raw;
		byte[][] f;
		long[] tcr;
		int scx=0;
		if (new File(fil).exists()) {
				raw = Stdio.file_get_bytes(fil);
				raw = Stdio.AESDec2(k1, iv, raw);
				f= Stdio.MxDaccuShifter(raw, 0x4c01);
				tcr = Stdio.Lodsx(f[0], 4);
				f = Stdio.MxDaccuShifter(f[1], 0x4c02);
				} else {
				k1=null;
				iv=null;
				return;
				}
		
		Log("User garbage: Start crawler");
		long cur = System.currentTimeMillis()/86400000L;
		int cx = tcr.length;
		scx=cx;
		long[] ntcr=new long[tcr.length];
		byte[][] q = new byte[tcr.length][];
		int bx=0;
		for (int ax=0;ax<cx;ax++) {
			String loc=null;
			if (cur>tcr[ax]) try {
				loc = new String(f[ax]);
				if (loc.compareTo("sysop")==0) continue;
				if (loc.endsWith(".op")) continue;
				UsrDestroy(loc);
				} catch(Exception E) { 
						Log("Can't del `"+loc+"` "+E.getMessage());
						if (Config.Debug) E.printStackTrace();
						} else {
							ntcr[bx]=tcr[ax];
							q[bx]=f[ax];
							bx++;
						}
			}
		tcr=new long[bx];
		f=new byte[bx][];
		System.arraycopy(ntcr, 0, tcr, 0, bx);
		for (int ax=0;ax<bx;ax++) f[ax]=q[ax];
		ntcr=null;
		raw = Stdio.Stosx(tcr, 4);
		q = new byte[][] {
				Stdio.MxAccuShifter(f, 0x4c02),
				raw	}
				;
		f=null;
		tcr=null;
		raw = Stdio.MxAccuShifter(q, 0x4c01, true);
		Stdio.file_put_bytes(fil, raw);
		raw=null;
		q=null;
		k1=null;
		iv=null;
		Log("User garbage: "+(scx-bx)+" users deleted, "+bx+" users in garbage list");
	}
		
	public void AddDelUser(String local) throws Exception {
		byte[] k1 = Stdio.sha256a(new byte[][] { Subs[4], Sale ,Subs[13]});
		byte[] iv = Stdio.md5a(new byte[][] { k1, Subs[14] });
		String fil=Maildir+"/oper.idx";
		
		byte[] raw;
		byte[][] f;
		long[] tcr;
		
		if (new File(fil).exists()) {
				raw = Stdio.file_get_bytes(fil);
				raw = Stdio.AESDec2(k1, iv, raw);
				f= Stdio.MxDaccuShifter(raw, 0x4c01);
				tcr = Stdio.Lodsx(f[0], 4);
				f = Stdio.MxDaccuShifter(f[1], 0x4c02);
				} else {
				raw=null;
				tcr=new long[0];
				f=new byte[0][];
				}
				
		long cur = 2+(System.currentTimeMillis()/86400000L);
		int cx = tcr.length;
		long[] tcrn = new long[cx+1];
		System.arraycopy(tcr, 0, tcrn, 0, cx);
		tcrn[cx]=cur;
		tcr=null;
		cx = f.length;
		byte[][] q = new byte[cx+1][];
		for (int ax=0;ax<cx;ax++) q[ax]=f[ax];
		f=null;
		q[cx] = local.getBytes();
		raw = Stdio.Stosx(tcrn, 4);
		
		f = new byte[][] {
				Stdio.MxAccuShifter(q, 0x4c02),
				raw	}
				;
	
		raw = Stdio.MxAccuShifter(f, 0x4c01, true);
		f=null;
		q=null;
		raw = Stdio.AESEnc2(k1, iv, raw);
		Stdio.file_put_bytes(fil, raw);
		raw=null;
		k1=null;
		iv=null;		
		}
	
	public void UsrDestroy(String local) throws Exception {
		String un=UFname(local);
		
		String[] lst = new String[] {
				un	,
				un+".idx",
				un+".dbf",
				un+".pr",
				null };
		
		MailBox M=null;
		try {
			M = UsrOpenW(Config,local,false);
			if (M.Spam !=null && !M.Spam.exists(local)) lst[4] = M.Spam.GetFile(local);
			M.Close();
			} catch(Exception E) { 
					Config.EXC(E, "DestroyUser.GetUBL"); 
						MailBox.AutoClose(M); 
						} 
		
		for (String f:lst) try {
			if (f==null) continue;
			if (new File(f).exists()) J.Wipe(f, Config.MailWipeFast);
			} catch(Exception E) {
				Config.EXC(E, "Server `"+Nick+"`.UsrDestroy file `"+f+"`");
			}
		
		Log("User destroyed `"+local+"`");
	}
	
	//															pop3		smtp
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
		
		MailBox M=null;
		try {
			M = UsrOpenW(Config,local,true);
			if (M.Spam !=null && !M.Spam.exists(local)) M.Spam.UsrCreateList(local);
			M.Close();
			
			} catch(Exception E) { 
				Config.EXC(E, "CreateUser.CreateUBL");
				MailBox.AutoClose(M); 
				} 
		
		try {
			HashMap <String,String>  uc =new HashMap <String,String>();
			if (DefaultUserConfig!=null) for (String k:DefaultUserConfig.keySet()) { uc.put(k, DefaultUserConfig.get(k)); }
			if (uc.containsKey("newsrulez")) {
				HashMap <String,String> Test= GetNewsRulez();
				for (String k:Test.keySet()) {
					String t0="newsrulez-"+k;
					if (uc.containsKey(t0)) uc.put(t0, Test.get(k));
					}
				}
			UsrSetConfig(local,uc);
			uc=null;
			} catch(Exception E) { Config.EXC(E, "CreateUser.MKConf"); }
		
		GPG=null;
		Sk=null;
		Pk=null;
		System.gc();
		
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
		if (!Hldr.containsKey("date")) Hldr.put("date", TimeString());
		if (!Hldr.containsKey("delivery-date")) Hldr.put("delivery-date", TimeString());
		if (!Hldr.containsKey("message-id")) Hldr.put("message-id", "<"+J.RandomString(16)+"@"+ ((this.EnterRoute && !to.endsWith(".onion")) ? ExitRouteDomain : Onion)+">");
			
		if (dom.compareTo(Onion)==0) SendLocalMessage(J.getLocalPart(to),Hldr,Body); else SendRemoteSession(to,Hldr.get("from"),Hldr, Body,null,false);
		}
	
	public void SendClearMessage(String to,HashMap <String,String> Hldr,String Body) throws Exception {
		to = J.getMail(to, false);
		if (to==null) throw new PException(503,"Inalid mail address");
		String dom = J.getDomain(to);
		if (!Hldr.containsKey("date")) Hldr.put("date", TimeString());
		if (!Hldr.containsKey("delivery-date")) Hldr.put("delivery-date", TimeString());
		if (!Hldr.containsKey("message-id")) Hldr.put("message-id", "<"+J.RandomString(16)+"@"+ ((this.EnterRoute && !to.endsWith(".onion")) ? ExitRouteDomain : Onion)+">");
		Hldr.put("x-ssl", "no");
		if (dom.compareTo(Onion)==0) SendLocalMessage(J.getLocalPart(to),Hldr,Body); else SendRemoteSession(to,Hldr.get("from"),Hldr, Body,null,true);
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
			Body=Body.replace("\r\n", "\n"); //XXX o!
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
	
	public void SendLocalMessageStream(String MailTo,HashMap <String,String> Hldr,BufferedReader Ms,MailBoxFile Mb) throws Exception {
		String usr = J.getLocalPart(MailTo);
		MailBox M = null;
		Message MS=null;
		try {
			M= UsrOpenW(Config,usr,false);
			int mi = M.Index.GetFree();
			if (mi==-1) {
				M.Close();
				throw new PException("@452  Mailbox full!");
				}
			
			if (!Hldr.containsKey("date")) Hldr.put("date", TimeString());	
				long MessageBytes=0;
				MS = M.MsgCreate();
	
			MS.SetHeaders(Hldr);
			while(true) {
				String li;
				if (Ms!=null) li = Ms.readLine(); else li = Mb.ReadLn();
			
				MessageBytes+=li.length()+2;
				if (MessageBytes>MaxMsgSize) {
					MS.Close();
					throw new PException("@452 Message too big");
					}
				if (li.compareTo(".")==0) break;
				MS.WriteLn(li);
				}
			MS.End();
			M.Close();
		
		} catch(Exception P) {
			MailBox.AutoClose(M);
			if (MS!=null) MS.Close();
			throw P;
			}
		
	}
	
	
	public void SendLocalMessage(String LocalPart,HashMap <String,String> Hldr,String Body) throws Exception {
		StatMsgIn++;
		if (Config.Debug) Log("LocalMessage "+Nick);
		if (!Hldr.containsKey("date")) Hldr.put("date", TimeString());
		MailBox M=null;
		Message MS=null;
		try {
			M = UsrOpenW(Config,LocalPart,false);
			int mi = M.Index.GetFree();
			if (mi==-1) {
				M.Close();
				throw new Exception("@500 Mailbox full");
				}
			long MessageBytes=0;
					
			MS = M.MsgCreate();
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
			M.Close();
		} catch(Exception E) {
			MailBox.AutoClose(M); 
			if (MS!=null) MS.Close();
			throw E;
			}
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
		MailBox M =null;
		Message MS=null;
		try {
			M = UsrOpenW(Config,LocalPart,false);
			int mi = M.Index.GetFree();
			if (mi==-1) {
				M.Close();
				throw new Exception("@500 Mailbox full");
				}
			long MessageBytes=0;
			
			MS = M.MsgCreate();
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
			M.Close();
			} catch(Exception E) {
				MailBox.AutoClose(M);
				if (MS!=null) MS.Close();
				throw E;
			}
	}
	

	
	public void SendRemoteSession(String MailTo,String MailFrom,HashMap <String,String> Hldr,MailBoxFile MBF,String VMATTO) throws Exception { 									RawRemoteSend2(MailFrom,MailTo, Hldr, MBF,null,  null , null ,VMATTO,false);		}
	public void SendRemoteSession(String MailTo,String MailFrom,HashMap <String,String> Hldr,String Msg,String VMATTO, boolean noSSL) throws Exception { 				RawRemoteSend2(MailFrom,MailTo,Hldr, null, Msg, null,null,VMATTO,noSSL); 		}
	public void SendRemoteSession(String MailTo,String MailFrom,HashMap <String,String> Hldr,BufferedReader I, OutputStream O,String VMATTO) throws Exception { 	RawRemoteSend2(MailFrom,MailTo, Hldr,null,null,   I,  O,VMATTO,false); 				}
		
	private  void RawRemoteSend2(String MailFrom,String MailTo,HashMap <String,String> Hldr,final MailBoxFile MBF,final String MSG, final BufferedReader I,final OutputStream O,String VmatToX,boolean forceNoSSL) throws Exception {
		ExitRouterInfo ex=null;
		String t0=null;
		String tlp = J.getLocalPart(MailTo);
		String tdm = J.getDomain(MailTo);
		if (tlp.endsWith(".onion")) throw new PException("@500 Can't send MAT address into the RawSend Routine");
		boolean toTor = tdm.endsWith(".onion");
		boolean RVMATLookup=false;
		boolean putNotice=false;
		String Tag="Tor";
		String Server=tdm;
		String VmatTo = null;
		
		if (Hldr!=null) {
			if (!Hldr.containsKey("date")) Hldr.put("date", TimeString());
			if (!Hldr.containsKey("delivery-date")) Hldr.put("delivery-date", TimeString());
			if (!Hldr.containsKey("message-id")) Hldr.put("message-id", "<"+J.RandomString(16)+"@"+ ((this.EnterRoute && !MailTo.endsWith(".onion")) ? ExitRouteDomain : Onion)+">");
			}
		
		if (VmatToX!=null && !MailTo.endsWith(".onion")) throw new Exception("@500 Can't use VmatToX to iNetMailAddress");
		
		if (!toTor) {
						
			VirtualRVMATEntry VM = VMAT.SenderVirtualRVMATEntryLoad(MailTo);
			if (Config.Debug) Log("Lookup for VMAT="+ (VM==null  ? "NULL":"RVMAT")); 
			if (VM!=null) {
				Server = VM.server;
				VmatTo=MailTo;
				MailTo = VM.onionMail;
				tlp = J.getLocalPart(MailTo);
				tdm = J.getDomain(MailTo);
				toTor=true;
				Tag+="-RVMAT";
				if (tdm.compareTo(Onion)==0) {
					String fd = J.getDomain(MailFrom);
					String fl = J.getLocalPart(MailFrom);
					if (fd.compareTo(Onion)==0) throw new PException("@550 VMAT Loop trouble: Your server is rebouding message.");
					}
				} else RVMATLookup = !tdm.endsWith(".onion");
						
			}
		
		if (RVMATLookup) Tag+="-LK";
		
		if (!toTor) {//sent via inet
					if (EnterRoute) {
					//MAT / VMAT (without RVMAT)
					//send via inet
					Tag+="-nEX";
					String onionmit=null;
					if (MaxMsgXserverXHour>0) onionmit= J.getDomain(MailFrom); 
					VirtualMatEntry VM = VMAT.loadVmat(MailFrom, true);
					if (VM!=null) { //VMAT
						Tag+="-VMAT";
						t0=VM.localPart+"@"+ExitRouteDomain;
						for (String k:Hldr.keySet()) {
							String a = Hldr.get(k);
							if (a.contains(MailFrom)) {
								a=a.replace(MailFrom, t0);
								Hldr.put(k, a);
								}
							}
						Hldr.put("from", t0);
						Hldr.put("x-vmat-from", MailFrom);
						MailFrom = t0;
						putNotice=ExitNoticeE;
						if (MaxMsgXserverXHour>0) onionmit = J.getDomain(VM.onionMail);
						} else { //MAT
							Tag+="-MAT";
							String flp = J.getLocalPart(MailFrom);
							String fdo = J.getDomain(MailFrom);
							t0 = flp+"."+fdo+"@"+ExitRouteDomain;
							
							for (String k:Hldr.keySet()) { //XXX TODO Controllare il from qui !FROM!
							String a = Hldr.get(k);
							if (a.contains(MailFrom)) {
								a=a.replace(MailFrom, t0);
								Hldr.put(k, a);
								}
							}
							
							Hldr.put("from", t0); //XXX TODO Controllare il from qui !FROM!
							Hldr.put("x-mat-from", MailFrom);
							putNotice=ExitNoticeE;
							MailFrom = t0;
						}
					
					if (MaxMsgXserverXHour>0 && onionmit!=null && onionmit.endsWith(".onion")) {
						boolean puo = Tor2InetMsgCounter(onionmit);
						if (!puo) throw new PException("@451 Limit of the server messages passed. Limit is "+MaxMsgXserverXHour+" messages x hour! Change your exit into the SETTINGS.");
						}
					
					} else {
						//Send via Exit
						//Select Exit from settings
						Tag+="-Exit";
						String dou=null;
						
						if (J.getDomain(MailFrom).compareTo(Onion)==0) ex =selectExit4User(J.getLocalPart(MailFrom)); 
						if (ex==null) {
							ExitRouteList RL= GetExitList();
							ex = RL.selectBestExit();
							if (ex==null) ex=RL.selectAnExit();
							}
						
						if (ex==null) throw new Exception("@503 No exit/enter route available!");
						dou = ex.onion;
						Server=dou; 
						toTor=true;
					}
			}
		
		MXRecord[] MX=null;
		//GET MX RECORD
		boolean toInet=false;
		if (EnterRoute && !toTor) {
			Tag+="-Inet";
			MX = Main.DNSCheck.getMX(Server);
				if (MX==null || MX.length==0) throw new Exception("@500 SMTP Server not found `"+Server+"` (No MX record)");
				MXRecord.MXSort(MX); 
				toInet=true;
				} else {
				MX = new MXRecord[] { new MXRecord(1,Server) };
				}
		
		if (MX==null || MX.length==0) throw new Exception("@500 Can't find any MX record on `"+Server+"`");
		Server = MX[0].Host;
				
		Hldr=J.AddMsgID(Hldr, toInet ? ExitRouteDomain : Onion);
		if (VmatToX!=null) if (VmatTo==null) VmatTo=VmatToX; else throw new PException("@500 R6008X1 Bad usage of VmatToX/VmatTo");
			
		final HashMap <String,String> Hldr3 = J.FilterHeader(Hldr);
		final String MailTo2 = MailTo;
		final String MailFrom2 = MailFrom;
		final boolean RVMATLookup2=RVMATLookup;
		final String VmatTo2=VmatTo;
		final boolean putNotice2=putNotice;
		
		
		SrvAction A = new SrvAction(this,MX,"Send-"+Tag) {
				public void OnSession(BufferedReader RI,OutputStream RO) throws Exception {
					HashMap <String,String> Hldr2 = Hldr3;
					SMTPReply Re;
					long MessageBytes=0;
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"MAIL FROM: <"+MailFrom2+">");
					if (hasQueue && (Re.Code>399 && Re.Code<500)) throw new RetryUevent(RetryUevent.POX_FROM,Re.Code,Re.toString().trim(),this.Server);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote/from)"); 
					
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"RCPT TO: <"+MailTo2+">");
					if (hasQueue && (Re.Code>399 && Re.Code<500)) throw new RetryUevent(RetryUevent.POX_TO,Re.Code,Re.toString().trim(),this.Server);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote/to)"); 
					
					if (SupVMAT) {
					
						if (RVMATLookup2) {
							Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM VMAT LOOKUP");
							if (Config.Debug) Log("Lookup in progress");
							if (Re.Code==250) {
								String OnionMail = J.getMail(Re.Msg[0], true);
								if (OnionMail!=null) try { //Save Lookup
									VirtualRVMATEntry MT = new VirtualRVMATEntry();
									MT.server = J.getDomain(OnionMail);
									MT.onionMail = OnionMail;
									MT.mail = MailTo2;
									VMAT.SenderRVMATSave(MT);
									} catch(Exception E) {
										this.Mid.Config.EXC(E, "RVMAT_Lookup `"+this.Mid.Nick+"` on `"+this.Server+"`");
									}
								}
							} else {
								if (VmatTo2!=null)  {
									Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM VMAT TO: <"+VmatTo2+">");
									if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote/vmat)");
								}
							}
					 	} else {
					 		if (RVMATLookup2) {
					 				Log("NO VMAT: `"+Server+"` Can't Lookup `"+J.UserLog(Mid,MailTo2)+"`");
					 				} else if(VmatTo2!=null) Log("NO VMAT: `"+Server+"` Can't VMAT TO `"+J.UserLog(Mid,VmatTo2)+"`");
					 	}
					
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"DATA");
					if (Re.Code<300 || Re.Code>399) throw new Exception("@"+Re.toString().trim()+ " (remote/data)");
					
					if (I!=null && O!=null) {
						O.write("354 Enter message, ending with \".\" on a line by itself\r\n".getBytes());
						HashMap <String,String> rh = ParseHeaders(I);
						rh = J.FilterHeader(rh);
						for (String j:Hldr2.keySet()) rh.put(j, Hldr2.get(j));
						Hldr2 = rh;						
						}
										
					Hldr2.put("sender", MailFrom2);
					Hldr2.put("envelope-to", MailTo2);
					Hldr2.put("delivery-date", TimeString());
					if (Hldr2.containsKey("date")) Hldr2.put("date", TimeString());	
					Hldr2.put("x-ssl-transaction", this.SupTLS ? "YES" : "NO" );
					if (!Hldr2.containsKey("message-id")) { //TODO MESSAGE-ID
					Hldr2.put("message-id", "<"+
							J.GenPassword(10, 0).toLowerCase()+"-"+
							J.GenPassword(8, 0).toLowerCase()+"@"+HostName+">")
							;}
					
					if (this.InternetConnection && putNotice2) { 
								String sr;
								sr = "server."+Onion+"@"+this.Mid.ExitRouteDomain;
								String st=sr;
								if (ExitNotice==null) {
								st = "This is an OnionMail message. See http://onionmail.info and <mailto:${SERVER}?subject=RULEZ> for details";
								st=st.replace("${SERVER}", sr);
								} else {
								st = ExitNotice.replace("${SERVER}", sr);
								}
								
						Hldr2.put("x-notice", st);
						}
					
					if (!this.InternetConnection && VmatTo2==null) {
						String dom = J.getDomain(MailFrom2);
						if (dom.compareTo(Onion)==0) {
							String localpart = J.getLocalPart(MailFrom2);
							setSendingTORVMAT(localpart, Hldr2);
							}
						}
							
					
					String t0 = J.CreateHeaders(Hldr2);
					t0=t0.trim();
					t0+="\r\n\r\n";
					RO.write(t0.getBytes());
					long TimeOut = System.currentTimeMillis()+Config.MaxSMTPSessionTTL;
					int Modo=0;
					
					String[] Text=null;
					int TextLength=0;
					int TextLine=0;
					
					if (MBF!=null) Modo=1;
					if (MSG!=null) {
							Modo=2;
							Text=MSG.replace("\r\n", "\n").split("\\n");
							TextLength=Text.length;
							}
					if (I!=null && O!=null) Modo=3;
					
					if (Modo==0) throw new Exception("@500 Nothing to send");
					
					while(true) {
						String line=null;
						if ( System.currentTimeMillis()>TimeOut) throw new Exception("@500 Timeout");
						if (Modo==1) {
							line = MBF.ReadLn();
							if (line==null) break;
							}
						
						if (Modo==2) {
							if (TextLine==TextLength) break;
							line=Text[TextLine++];
							}
						
						if (Modo==3) {
							line = I.readLine();
							if (line==null) break;
							}
						
						line=line.replace("\r", "");
						line=line.replace("\n", "");
						if (line.compareTo(".")==0) break;
						line+="\r\n";
						RO.write(line.getBytes());
						MessageBytes+=line.length()+2;
						if (MessageBytes>=MaxMsgSize) throw new PException("@500 Message too big");
						}
					RO.write(".\r\n".getBytes());
					Re = new SMTPReply(RI);
					if (Modo==3) Re.Send(O);
					RES[0] = MessageBytes;
					}//session
			
				public void OnSSLError(SException Erro) throws Exception { 
						Log(Tag+": SSLError: "+Erro.getMessage());
						if (SSLEIDSendUserMessage==false) return;
						
						HashMap <String,String> Hldr0 = SrvSMTPSession.ClassicHeaders( "server@"+Onion, MailFrom2);
						Hldr0.put("subject", "Delivery SSL status");
						
						String msg="Sending message to: "+MailTo2+"\r\n";
						msg+="Action: Message blocked!\r\n";
						msg+="Error: "+Erro.getMessage()+"\r\n";
						msg+="Debug SrvAction tag: "+Tag+"\r\n";
					
						SSLSession s =Erro.SSLSess;
						if (s!=null) {
							msg+="SSL Session info:\n";
							msg+="SSL Chiper Suite: "+	s.getCipherSuite()+"\n";
							msg+="SSL Protocol: "+s.getProtocol()+"\n";
							msg+="SSL ID: "+Stdio.Dump(s.getId())+"\n";
							msg+="\n";
							try {
							java.security.cert.Certificate[] cp = s.getPeerCertificates();
								if (cp!=null && cp.length>0) {
									int cx =cp.length;
									msg+="PeerCertificates:\n";
									for (int ax=0;ax<cx;ax++) msg+=cp[ax].toString()+"\n";
									msg+="\n";
									}
							 } catch(Exception I) {}
							try {
								java.security.cert.Certificate[] cp = s.getLocalCertificates();
								if (cp!=null && cp.length>0) {
									int cx =cp.length;
									msg+="PeerCertificates:\n";
									for (int ax=0;ax<cx;ax++) msg+=cp[ax].toString()+"\n";
									msg+="\n";
									}
								} catch(Exception I) {}
							}
				
						try {
							String t0 = MailFrom2;
							if (J.getLocalPart(t0).endsWith(".onion")) {
								String dm = J.getDomain(t0);
								t0 = J.IfInet2Tor(t0, dm);
								}
							Mid.SendClearMessage(t0, Hldr0, msg);
						} catch(Exception E) { Log("Can't send NoSSL x SSL messge: "+E.getMessage()); }
				
				}//OnSSLError
				
			};//doAction
		A.RES = new Long[1];
		A.DoInSSL=true;
		A.DoInTKIM = !toInet;
		A.ForceSSL= !toInet;
		A.ForceTKIM = false;
		A.HostName = toInet ? (MXDomain==null ? ExitRouteDomain : MXDomain) : Onion;
		
		if (A.HostName!=null) try {
			if (SSLErrorTracker.containsKey(A.HostName)) {
				Integer[] dta = SSLErrorTracker.get(A.HostName);
				if (0!=(dta[SrvIdentity.SSLEID_Flags]&SrvIdentity.SSLEID_Flags_NoSSL)) {
					A.DoInSSL=false;
					Hldr3.put("x-ssl", "no, by SSLEID.");
					Log("SSLEID: Don't use SSL to `"+A.HostName+"`"); 
					}
				}
			} catch(Exception EX) { Config.EXC(EX, "SSLEID:APP."+Nick); }
		
		A.InternetConnection = toInet;
		A.currentExit=ex;
		if (forceNoSSL) A.DoInSSL=false;
						
		A.Do();
		
		StatMsgOut++;
		if (Server.endsWith(".onion")) StatTor2TorBy++; else StatTor2InetBy++;
		StatSendMSGBytes+=(long) A.RES[0];
				
	}
	
	/*
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
		
	}*/


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
	
	
	protected String GetFNName(String O) {
		try {
			return Maildir+"/feed/"+ J.md2st(Stdio.md5a(new byte[][] { Sale, O.toLowerCase().getBytes(),"Manifest2".getBytes() }));
		} catch(Exception E) {
				Config.EXC(E, "GetFNName `"+O+"`");
				return Maildir+"/feed/"+ Long.toHexString(O.hashCode())+"-fail"; 
				}
	}
	
	public String CreateManifest(boolean newManifest) throws Exception {
		HashMap <String,String> H = new HashMap <String,String>();
		H.put("manifest", newManifest ? "2.0" : "1.1");
		H.put("ver","TORM V="+Const.TormVer);
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
		H.put("port", Integer.toString(ExitAltPort));
		H.put("pop3sub", ( POP3CanRegister ? "R":"0" ) + (POP3CanVMAT ? "V" : "0") + " "+NewUsrLastDayCnt+" "+NewUsrMaxXDay);
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
			ExitRouterInfo[] ex = RL.getAll();
			int cx = ex.length;
			if (newManifest) {
					for (int ax=0;ax<cx;ax++) s+=ex[ax].toString()+"\r\n";
				} else {
					for (int ax=0;ax<cx;ax++) s+=ex[ax].domain+": "+ex[ax].onion+"\r\n";
				}
						
			s+="\r\n";
			for (String k:ManifestInfo.keySet()) s+=k.toLowerCase()+": "+ManifestInfo.get(k)+"\r\n";
			if (ShowFriends) {
				try {
					String[] FriendServer = RequildFriendsList();
					int lcx = FriendServer.length;
					for (int ax=0;ax<lcx;ax++) s+="@Friend-"+Integer.toString(ax,36)+": "+FriendServer[ax].toLowerCase().trim()+"\r\n";
					} catch(Exception IE) {
						Log("ManifestFriend: "+IE.getMessage());
						if (Config.Debug) IE.printStackTrace();
						}
				}
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
			//XXX ??? String msg=E.getMessage();
			
			if (E instanceof SException) {
				((SException) E).concat("COD="+cod);
				throw E;
				} else throw new Exception(E+" COD="+cod);
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
					RS.setSoTimeout(Config.MaxSMTPSessionTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote)"); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
					SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
					boolean mf2 = SrvSMTPSession.CheckTormCapab(Re, "MF2");
					
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
						
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM IAM iam.onion" +( mf2 ? "V2.0" : "V2"));
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
					if (Config.Debug) E.printStackTrace();
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
							if (T==0 || Math.abs(System.currentTimeMillis() - T) > (Config.manifestTTLS*1000L)) return false;
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
			Log("Manifest: `"+remo+"`" + (m.Friends!=null ? Integer.toString(m.Friends.length)+" Friends": ""));	
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
		
		public boolean VerifyExit(ExitRouterInfo e)   {
			e.lastCHK=System.currentTimeMillis()/1000;
			if (Config.Debug) Log("Verify `"+e.domain+"`");			
			if (e.domain.compareTo(ExitRouteDomain)==0 && e.onion.compareTo(Onion)==0) {
				e.Goods=100;
				e.Bads=0;
				e.isDown=false;
				e.isLegacy=false;
				e.isExit = EnterRoute;
				e.isTrust=true;
				e.canMX=EnterRoute;
				e.canVMAT=EnterRoute;
				return true;
				}
			Socket	RS=null;
			OutputStream RO=null;
			BufferedReader RI=null;
			SMTPReply Re=null;
			boolean SupTLS=false;
			boolean SupTORM=false;
			try {
				try {
					try {
						if (Config.ExitCheckViaTor) {
								if (Config.Debug) Log("Verify `"+e.domain+"` via TOR/SMTP");
								RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, e.onion,25); 
								} else {
								if (Config.Debug) Log("Verify `"+e.domain+"` via "+ (e.isLegacy ? "SMTP" : "ExitAltPort"));
								RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, e.domain,e.isLegacy ? 25 :  e.port);
								}
										
						} catch(Exception ef) {
						Log("Can't connect via TOR->Inet to `"+e.domain+"` Exit policy?");
						RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, e.domain, e.port);
						if (Config.Debug) Log("Verify `"+e.domain+"` via ExitAltPort");
						if (e.isLegacy) Log("Server `"+e.domain+"`could be a legacy hybrid server");
						//e.setResult(false);
						}
					 	} catch(Exception ie) {
						 RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, e.onion,25);
						 if (Config.Debug) Log("Verify `"+e.domain+"` via TOR");
					 }
				if (Config.Debug) Log("Verifying `"+e.domain+"`");
				
				RO = RS.getOutputStream();
				RI  =J.getLineReader(RS.getInputStream());
				RS.setSoTimeout(Config.MaxSMTPSessionTTL);
				Re = new SMTPReply(RI);
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" `"+e.onion+"`"); 
			
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " `"+e.onion+"`");
				SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
				SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
				if (!SupTORM || !SupTLS) {
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
					try { RS.close(); } catch(Exception IE) {}
					//modevd Log(Config.GLOG_Event,"Checking `"+oni+"` is  not an OnionMail compatible server!");
					if (Config.Debug) Log("Server `"+e.onion+"` doesn't support STARTTLS, TORM, TKIM");
					e.isBad=true;
					e.setResult(false);
					return false;
					}
				
				e.canMX = SrvSMTPSession.CheckTormCapab(Re, "MX");
				e.canVMAT = SrvSMTPSession.CheckTormCapab(Re, "VMAT");
				if (e.canMX || e.canVMAT) e.isLegacy=false;
				
			
				
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM K");
				if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " `"+e.onion+"`");
				
				byte[] pk = Re.getData();
				byte[][] sd =LoadCRT(e.onion.toLowerCase());
				if (sd==null) {
					Log(Config.GLOG_Event,"Checking `"+e.onion+"` exit without SSL Certificate in cache!");
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
					try { RS.close(); } catch(Exception IE) {}
					e.setResult(false);
					return false;
					} /// Perchè???? else e.isBad=false;
				
				if (!Arrays.equals(pk, sd[0])) {
					Log(Config.GLOG_Event,"Checking `"+e.domain+"` Invalid exit key!");
					e.isBad = true;
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
					try { RS.close(); } catch(Exception IE) {}
					return false;
					}
				
				Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
				try { RS.close(); } catch(Exception IE) {}
				e.isDown=false;
				e.setResult(true);
				if (Config.Debug) Log("Exit `"+e.domain+"` verified");
				return true;
			} catch(Exception EE) {
				if (RS!=null) try { RS.close(); } catch(Exception IE) {}
				e.setResult(false);
				e.isDown=true;
				Log(Config.GLOG_Event,"Checking `"+e.onion+"` Error: "+EE.getMessage());
				return false;
			}
		} 
		
		
		/*
		public int VerifyExit_old(String InedDom,String oni,int port,ExitRouterInfo inf)   {
			inf.lastCHK=System.currentTimeMillis()/1000;
			
			if (Config.Debug) Log("Verify `"+InedDom+"`");
			if (InedDom.compareTo(ExitRouteDomain)==0 && oni.compareTo(Onion)==0) return 1;
			Socket	RS=null;
			OutputStream RO=null;
			BufferedReader RI=null;
			SMTPReply Re=null;
	//		boolean SupTLS=false;
			boolean SupTORM=false;
			try {
				try {
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, InedDom,port);
					 } catch(Exception ie) {
						 Log("Can't connect via TOR to `"+InedDom+"` Exit policy?");
						 RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, oni,port);
					 }
				RO = RS.getOutputStream();
				RI  =J.getLineReader(RS.getInputStream());
				RS.setSoTimeout(Config.MaxSMTPSessionTTL);
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
				inf.canMX = SrvSMTPSession.CheckTormCapab(Re, "MX");
				inf.canVMAT = SrvSMTPSession.CheckTormCapab(Re, "VMAT");
				
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
		*/
		
		private void setDoFriendStatus(boolean ok,String FriendServer) {
			if (!ok) {
						if (!badSrvLast.containsKey(FriendServer)) badSrvLast.put(FriendServer, Integer.toString((int) (System.currentTimeMillis()/1000)));
						String s = badSrvNum.containsKey(FriendServer) ? badSrvNum.get(FriendServer) : "0";
						int si = J.parseInt(s);
						si++;
						badSrvNum.put(FriendServer, Integer.toString(si));
						} else {
						if (badSrvLast.containsKey(FriendServer)) {
							badSrvLast.remove(FriendServer);
							badSrvNum.remove(FriendServer);
							}
						}
		}
		
		public SrvManifest DoFriend(String FriendServer) throws Exception {
			SrvManifest M=null;
			if (FriendServer.compareToIgnoreCase(Onion)==0) return null;
			if ((Main.cmdFlags & Main.CF_F_NOSKIPFRIEND)==0 && HaveManifest(FriendServer)) {
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
					RS.setSoTimeout(Config.MaxSMTPSessionTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+" (remote)"); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO "+Onion);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					SupTLS = SrvSMTPSession.CheckCapab(Re,"STARTTLS");
					SupTORM = SrvSMTPSession.CheckCapab(Re,"TORM");
					if (!SupTLS) throw new Exception("Doesn't support STARTTLS");
					if (!SupTORM) throw new Exception("Doesn't support TORM");
					boolean newManifest = SrvSMTPSession.CheckTormCapab(Re, "MF2");
					
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
					
						Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM IAM "+Onion+ (newManifest ? " V2.0":" V2"));
						if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
						M = ReceiveManifest(Re,FriendServer);
						} else  throw new Exception("@"+Re.toString().trim()+ " (remote)");
					
					try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception Ii) {}
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
					setDoFriendStatus(true,FriendServer);
					
				} catch(Exception E) {
					try { if (RS!=null) RS.close(); } catch(Exception Ii) {}
					try { if (RO!=null) RO.close(); } catch(Exception Ii) {}
					try { if (RI!=null) RI.close(); } catch(Exception Ii) {}
					setDoFriendStatus(false,FriendServer);
					if (E instanceof SocketException) {
						String s= E.getMessage();
						if (s!=null && s.contains("Error H5B")) Log("Friend `"+FriendServer+"` Error: Can't connect"); else Log("Friend `"+FriendServer+"` "+s);
						} else { 
						Log("Friend `"+FriendServer+"` Error: "+E.toString().replace("@", ""));
						if (Config.Debug) E.printStackTrace();
						}
				}
				return M;
		}
		
		void DoFriends() throws Exception {
		SrvManifest M=null;	
		Status |= SrvIdentity.ST_FriendRun;
		Log("Begin DoFriends\n");
		//badSrvNum = null;
		//badSrvLast = null;
		
		try {
			byte[][] ef = fileLoad(Const.FIL_BAD_SRV, Const.ONM_CORE, Const.ONM);
			if (ef==null) {
					badSrvNum = new HashMap <String,String>();
					badSrvLast = new HashMap <String,String>();
					} else {
					badSrvNum = J.HashMapUnPack(ef[0]);
					badSrvLast = J.HashMapUnPack(ef[1]);
					}
			
			} catch(Exception E) {
				Config.EXC(E, "FIL_BAD_SRV");
				badSrvNum = new HashMap <String,String>();
				badSrvLast = new HashMap <String,String>();
			}
		
		HashMap <String,String> net = new HashMap <String,String>();
		String[] FriendServer = RequildFriendsList();
		if (friendsForceAdd!=null) {
			String t0 = J.Implode("\n", FriendServer);
			t0+="\n"+friendsForceAdd;
			friendsForceAdd=null;
			FriendServer=t0.split("\\n+");
			}
		String known = "\n"+J.Implode("\n", FriendServer)+"\n";
		String friendlyList="";
		known=known.toLowerCase();
		int cx=FriendServer.length;
		for (int ax=LastFriend;ax<cx;ax++) {
				LastFriend++;
				if (FriendServer[ax].compareToIgnoreCase(Onion)==0) continue;
				if (badSrvNum.containsKey(FriendServer[ax])) {
					String s = badSrvNum.get(FriendServer[ax]);
					int si = J.parseInt(s);
					if (si>Config.removeFriendAfterErrors) {
						Log("DoFriendSkip try="+si+" `"+FriendServer[ax]+"` because is historically down.");
						continue;
						}
					}
				
				M = DoFriend(FriendServer[ax]);
				
				if (M==null) continue;
										
				HashMap <String,String> N = M.getHashMap(ExitRouteList.FLT_TRUST);
				if (N.size()<3) N.putAll(M.getHashMap(ExitRouteList.FLT_VMAT));
				if (N.size()<6) N.putAll(M.getHashMap(ExitRouteList.FLT_OK));
				if (N.size()<27) N.putAll(M.getHashMap(ExitRouteList.FLT_ALL));
				
				if (N.size()!=0) {
					for (String K:N.keySet()) {
						if (net.containsKey(K)) {
							String c = N.get(K);
							if (net.get(K).compareTo(c)!=0) {
								String st = net.get(K).trim()+"\n";
								if (!("\n"+st).contains("\n"+c+"\n")) {
									st+=c;
									net.put(K, st.trim());
									}
								}
							} else net.put(K,N.get(K));
						}
					if (net.containsKey(FriendServer[ax])) net.remove(FriendServer[ax]);
					}
				
				if (Friendly && M.Friends!=null) {
					int cl = M.Friends.length;
					for (int al=0;al<cl;al++) {
						if (!known.contains("\n"+M.Friends[al]+"\n")) {
								known+=M.Friends[al]+"\n";
								friendlyList+=M.Friends[al]+"\n";
								}
							}
					}
				
				}//for
		
		if (Friendly && friendlyList.length()!=0) {
			friendlyList=friendlyList.trim();
			String[] arr = friendlyList.split("\\n+");
			int cl = arr.length;
			Log("DoFriends: Start friendly list, new "+cl+" servers");
			for (int al=0;al<cl;al++) {
					if (arr[al].length()!=0 && !net.containsKey(arr[al])) DoFriend(arr[al]);
					}
			}
				
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
		try {
			
			byte[][] fi = new byte[][] { 
					J.HashMapPack(badSrvNum)	,
					J.HashMapPack(badSrvLast)	}
					;
			
			this.fileSave(Const.FIL_BAD_SRV, fi, Const.ONM_CORE,  Const.ONM);
			
			} catch(Exception E) {
				Config.EXC(E, "DoFriend/Bad:Save");
			}
		
		Log("DoFriends Complete\n");
		LastFriend=0;
		Status &= -1 ^ SrvIdentity.ST_FriendRun;
		Status |= SrvIdentity.ST_FriendOk;
		}
	
		void SearchExit() throws Exception {
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
			ExitRouteList  ExitList = new ExitRouteList();
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
				
				if (!onionlist.contains("\n"+M.my.onion)) onionlist+=M.my.onion+"\n";
				if (!M.my.isExit) continue;
				
				String qfdn = M.my.domain.toLowerCase().trim();
				String oni = M.my.onion.toLowerCase().trim();
				if (qfdn.endsWith(".onion")) continue;
					
				if (ExitList.containsDomain(qfdn)) {
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
				ExitList.addRouter(M.my);
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
			for(String K:tl) ExitList.removeServerByDomain(K);
			
		
			Log("Verifying Exit Scan");
			ExitList.applyServerPolicy(this);
			ExitRouterInfo[] el = ExitList.getAll();
			el = ExitRouteList.queryFLTArray(el, ExitRouteList.FLT_ALL);
			cx=el.length;
			for (int ax=0;ax<cx;ax++) {
				boolean rs = VerifyExit(el[ax]);
				if (!rs)	{
							String bc = "";
							if (el[ax].isBad) bc="is bad\n";
							if (el[ax].isDown) bc+="is down\n";
							if (el[ax].isLegacy) bc+="is legacy\n";
							if (!el[ax].isExit) bc+="is not exit\n";
							bc=bc.trim();
							bc=bc.replace("\n", ", ");
							if (bc.length()==0) bc="i can!";
							Log("Exit not accepted `"+el[ax].domain+"` because "+bc);
							} else if (Config.Debug) Log("Server `"+el[ax].domain+"` is an exit OnionMail router in list.");
				} //
			
			el= ExitRouteList.queryFLTArray(el, ExitRouteList.FLT_ALL);
			
			ExitList = new ExitRouteList();
		
			ExitList.addRouters(el);
			
			byte[][] Ks = J.DerAesKey(Sale, Const.KD_ExitList);

			byte[] b =ExitList.getBytes();
			b = Stdio.AESEnc(Stdio.GetAESKey(Ks[0]), Ks[1], b);
			Stdio.file_put_bytes(Maildir+"/feed/network",b);
			b=null;
			J.WipeRam(Ks);
			Ks=null;
			System.gc();
			int dx= ExitList.Length();
			Log("Search Exit End, "+dx+" node found," +J.sPercMax(dx, cx, 100, 2)+"% of list");
			setExitList(ExitList);
			ExitStatTCR = 0; 
			GetExitList();
			}
		
		private ExitRouteList ExitListCache=null;
		private volatile long ExitRouteListTCR=0;
		private volatile long ExitStatTCR = 0;
		
		public volatile int statMaxExit = 0;
		public volatile int statMaxExitTrust=0; 
		public volatile int statMaxExitBad = 0;
		public volatile int statMaxExitDown = 0;
		
		public ExitRouteList GetExitList() throws Exception {
			if (ExitListCache==null)	 ExitListCache = LoadExitListS();
			long tcr = System.currentTimeMillis();
			ExitRouteListTCR = tcr + 300000L;
			if (Config.UseStatus && tcr>ExitStatTCR) {
				ExitRouterInfo[] a = ExitListCache.getAll();
				int cx = a.length;
				int ed=0;
				int eb=0;
				int ex=0;
				int et=0;
				for (int ax=0;ax<cx;ax++) {
					if (a[ax].isBad) {
						eb++;
						continue;
						}
					
					if (a[ax].isDown) {
						ed++;
						continue;
						}
					
					if (a[ax].isTrust) et++;
					ex++;
					}
				ExitStatTCR=tcr+60000L;
				statMaxExit = ex;
				statMaxExitTrust=et; 
				statMaxExitBad = eb;
				statMaxExitDown = ed;
				if (Config.Debug) Log("Update Exit stats");
				}
			
			return ExitListCache;
			}
		
		public void Garbage() {
			if ( System.currentTimeMillis()>ExitRouteListTCR) ExitListCache=null;
			}
		
		public synchronized ExitRouteList LoadExitListS() throws Exception { return LoadExitList(); }
		
		public synchronized void setExitList(ExitRouteList x) {  ExitListCache = x;  }
		
		public ExitRouteList LoadExitList() throws Exception {
			if (!new File(Maildir+"/feed/network").exists()) return new ExitRouteList();
			byte[][] Ks = J.DerAesKey(Sale, Const.KD_ExitList);
			byte[] b = Stdio.file_get_bytes(Maildir+"/feed/network");
			b = Stdio.AESDec(Stdio.GetAESKey(Ks[0]), Ks[1], b);
			J.WipeRam(Ks);
			Ks=null;
			ExitRouteList r = ExitRouteList.fromBytes(b);
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
		
		public String HourCode(String local) {
			long h = (Config.TimeSpoof+ System.currentTimeMillis())/3600000L;
			long i = local.hashCode();
			h^=Subs[4][4];
			h^=i;
			h=h^h<<1;
			h^=TimerSpoofFus.hashCode();
			return Long.toString(Long.toString(h,36).hashCode(),16);
			}
		
		public HashMap <String,String> UserSetParamG(String local,HashMap <String,String> np) throws Exception {
			HashMap <String,String> H = UsrGetConfig(local);
			if (H==null) H = new HashMap <String,String>();
			String error="";
			for (String k:np.keySet()) {
				String par = np.get(k);
				if (par.contains(":")) continue;
				if (":usevmat:torvmat:novmatautoset:".contains(":"+k+":")) {
					try {
						boolean bit = Config.parseY(par);
						H.put(k, bit ? "yes":"no");
						} catch(Exception E) { error+="Invalid value for `"+par+"`\n"; 	}
					continue;
					}
				
				if (k.compareTo("clear")==0) {
					if (":all:usevmat:torvmat:novmatautoset:exitdomain:exitonion:".contains(par)) {
						if (par.compareTo("all")==0) {
							for (String k2: new String[] {"usevmat","torvmat","novmatautoset","exitdomain","exitonion" }) if (H.containsKey(k2)) H.remove(k2);
							}
						if (":usevmat:torvmat:novmatautoset:exitdomain:exitonion:".contains(":"+par+":") && H.containsKey(par)) H.remove(par);
						}
					continue;
				}
				
				if (k.compareTo("exitdomain")==0) {
				ExitRouteList el = GetExitList();
				if (!el.containsDomain(par)) {
					error+="Unknown exit `"+par+"` at this time\n";
					continue;
					}
				ExitRouterInfo ef = el.getByDomain(par);
				if (ef.isBad) {
					error+="Bad exit `"+par+"`\n";
					continue;
					}
				
				if (ef.isDown) {
					error+="Exit `"+par+"` is down\n";
					continue;
					}
				H.put(k,par);
				H.put("exitonion", ef.onion);
				continue;
				}	
			
			error+="Can't set parameter `"+k+"`\n";
			}
		
		UsrSetConfig(local, H);
		H.put("_error_", error);
		return H;
		}
		
		/*
		public String UserMSGParam(String local,String par,String val) throws Exception { //TODO Da rivedere
			par=par.toLowerCase().trim();
			HashMap <String,String> H = UsrGetConfig(local);
			String v=val.trim();
					
			if (par.compareTo("lang")==0) {
					v= J.GetLangSt(v);
					if (v!=null) H.put("lang", v);
					}
			
			if (par.compareTo("exitdomain")==0) {
				ExitRouteList RL = GetExitList();
				String sv = RL.getOnion(v);
				
				if (sv==null && EnterRoute) {
					H.put("exitdomain", ExitRouteDomain);
					H.put("exitonion", Onion);
					} else if (sv!=null) {
					v = RL.onion2Domain(sv);
					if (v!=null) {
						ExitRouterInfo i = RL.getByDomain(v);
						if (i.isBad) throw new Exception("@550 This exit domain is a bad server `"+val+"`");
						if (i.isDown) throw new Exception("@550 This exit domain is now down `"+val+"`");
						H.put("exitdomain", v);
						H.put("exitonion", sv);
						} else  throw new Exception("@500 Can't set this exit domain `"+val+"`");
					} else throw new Exception("@500 Can't set exit domain `"+val+"`");
				}
			
			
			
			UsrSetConfig(local, H);
			String txt="";
			for(String K:H.keySet()) txt+=K+": "+H.get(K)+"\n";
			return txt;
		}
		*/
		
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
		
		public boolean SSLHasHash(String host) throws Exception {
			String fn = GetFNName(host)+".crth";
			return new File(fn).exists();
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
		
			if (C.length>1 && LibSTLS.useDefaultSSLCheck && EnterRoute) {
				int cx = C.length;
				if (CheckCertValidity) try {
					for (int ax=0;ax<cx;ax++) C[ax].checkValidity();
					} catch(Exception SE) {
					SSLErrorTrack(host, SrvIdentity.SSLEID_Err);
					throw new SException(SE,"@500 Validity");
					}
				cx--;
				for (int i=0;i<cx;i++) {
					C[i].verify(C[i+1].getPublicKey());
				}
				
				int dx = LibSTLS.acceptedIssuer.length;
				for (int i = 0 ; i <dx; i++) {
					try {
						C[cx].verify(LibSTLS.acceptedIssuer[i].getPublicKey());
						return;
					} catch(Exception e) {}
				}
				SSLErrorTrack(host, SrvIdentity.SSLEID_Flags_BadServer);
				throw new SException("@500 Invalid issuer`"+C[dx].getIssuerDN().getName()+"` for `"+host+"`");
			}
			
			if (!new File(fn).exists()) {
				int cx= C.length; 
				if (CheckCertValidity) try {
					for (int ax=0;ax<cx;ax++) C[ax].checkValidity();
					} catch(Exception SE) {
					SSLErrorTrack(host, SrvIdentity.SSLEID_Err);
					throw new SException(SE,"@500 Validity");
					}
				Log("New SSL CRT for `"+host+"`");
				SSLSaveNew(C,host);
				//AlphaDebugCrt(C,"N_"+host);
				///SSLToVerify.put(host, Stdio.Dump(hash).toLowerCase());
				return;
				}
			
		byte[][] X = J.DerAesKey(Sale, host);
		String t0 = fn+"h";
		boolean updateSSL = false;
		
		if (new File(t0).exists()) {
			byte[] h1 = Stdio.file_get_bytes(fn+"h");
			if (!Arrays.equals(h1,hash)) {
					if (forceVerifySSLHash && !host.endsWith(".onion")) { //XXX Non verifica su EXIT
						//AlphaDebugCrt(C,"H_"+host);
						SSLErrorTrack(host, SrvIdentity.SSLEID_EHash);
						throw new SException("@500 SSL Hash not match `"+host+"`");
						} else updateSSL=true;
					}
			}
		
		if (updateSSL) Log("Testing the new certificate for `"+host+"`");
		//if (updateSSL) AlphaDebugCrt(C,"U_"+host);
		
		byte[] in = Stdio.file_get_bytes(fn);
		in = Stdio.AES2Dec(X[0], X[0], in);
		try {
			if (updateSSL && !LibSTLS.CheckValidityDate) for (int ax=0;ax<C.length;ax++) C[ax].checkValidity(); //VerifyChani esegue opzionalmente il test.
			LibSTLS.VerifyChain (in,C,host);
			} catch(Exception ES) {
				SSLErrorTrack(host, SrvIdentity.SSLEID_EHash);
				throw new SException(ES,"@500 VerifyChain");
				}
		
		if (Config.Debug) Log("SSL OK For `"+host+"` CryptHash `"+Stdio.Dump(LibSTLS.CertHash(C, host))+"`");
		
		if (updateSSL) {
			SSLSaveNew(C,host);
			SSLErrorTrack(host, SrvIdentity.SSLEID_Flags_Changed);
			 Log("New certificate for `"+host+"` Ok"); 
			} else 	if (ifSSLE(host)) SSLErrorTrack(host, SrvIdentity.SSLEID_Ok);
		
		}
		
	


		/////////////////////////////// SSLEID SSL //////////////////////////////
		
		
		public static final int SSLEID_First = 0;
		public static final int SSLEID_Last = 1;
		public static final int SSLEID_Err = 2;
		public static final int SSLEID_Ok = 3;
		public static final int SSLEID_EHash = 4;
		public static final int SSLEID_EndTime = 5;
		public static final int SSLEID_Socket = 6;
		public static final int SSLEID_Hits = 7;
		public static final int SSLEID_CanChange = 8;
		public static final int SSLEID_Flags = 9;
		public static final int SSLEID_CurID = 10;
		public static final int SSLEID_SIZE = 11;
		
		public static final int SSLEID_Flags_Changed=1;
		public static final int SSLEID_Flags_NoSSL=2;
		public static final int SSLEID_Flags_BadServer=4;
		public static final int SSLEID_Flags_IncompatibleSSL = 8;
		public static final int SSLEID_Flags_Fixed = 16;
		public static final int SSLEID_Flags_Persistent=128;
		
		public static final int SSLEID_Flags_MASK = SSLEID_Flags_Changed | SSLEID_Flags_NoSSL | SSLEID_Flags_BadServer | SSLEID_Flags_IncompatibleSSL | SSLEID_Flags_Persistent | SSLEID_Flags_Fixed;
		
		public HashMap <String,Integer[]> SSLErrorTracker = new  HashMap <String,Integer[]>();
		private volatile long PreventTooManySSLErrorTrackGarbages=0;
		public volatile boolean SSLEIDPermitAutoChange = false;
		public volatile boolean iWantChangeIdentity = false;
		
		public void SSLEIDCmd(String host,String[] oper) throws Exception {
			
				host =host.trim();
				Integer[] dta;
				if (SSLErrorTracker.containsKey(host)) dta = SSLErrorTracker.get(host); else dta = J.newInteger(SrvIdentity.SSLEID_SIZE);
				int cx = oper.length;
				for (int ax=0;ax<cx;ax++) {
					oper[ax]=oper[ax].trim();
					if (oper[ax].length()==0) continue;
					String[] Tok = oper[ax].split("\\=",2);
					if (Tok.length!=2) throw new Exception("Syntax error in line "+(cx+1));
				
					String nval = Tok[0].toLowerCase().trim();
					Tok[1]=Tok[1].trim();
					if (Tok[1].length()==0 || nval.length()==0 ) throw new Exception("Syntax error in line "+(cx+1));
					
					int val = J.parseInt(Tok[1].toLowerCase());
				
					if (nval.compareTo("tor")==0) dta[SrvIdentity.SSLEID_CurID] = val;
					if (nval.compareTo("chg")==0) dta[SrvIdentity.SSLEID_CanChange] = val;
					if (nval.compareTo("ecrt")==0) dta[SrvIdentity.SSLEID_EHash] = val;
					if (nval.compareTo("err")==0) dta[SrvIdentity.SSLEID_Err] = val;
					if (nval.compareTo("hit")==0) dta[SrvIdentity.SSLEID_Hits] = val;
					if (nval.compareTo("ok")==0) dta[SrvIdentity.SSLEID_Ok] = val;
					if (nval.compareTo("sok")==0) dta[SrvIdentity.SSLEID_Socket] = val;
					
					if (nval.compareTo("b")==0) dta[SrvIdentity.SSLEID_Flags] = J.setBit(SrvIdentity.SSLEID_Flags_BadServer, (int)  dta[SrvIdentity.SSLEID_Flags] , val!=0);
					if (nval.compareTo("c")==0) dta[SrvIdentity.SSLEID_Flags] = J.setBit(SrvIdentity.SSLEID_Flags_Changed, (int)  dta[SrvIdentity.SSLEID_Flags] , val!=0);
					if (nval.compareTo("i")==0) dta[SrvIdentity.SSLEID_Flags] = J.setBit(SrvIdentity.SSLEID_Flags_IncompatibleSSL, (int)  dta[SrvIdentity.SSLEID_Flags] , val!=0);
					if (nval.compareTo("n")==0) dta[SrvIdentity.SSLEID_Flags] = J.setBit(SrvIdentity.SSLEID_Flags_NoSSL, (int)  dta[SrvIdentity.SSLEID_Flags] , val!=0);
					if (nval.compareTo("p")==0) dta[SrvIdentity.SSLEID_Flags] = J.setBit(SrvIdentity.SSLEID_Flags_Persistent, (int)  dta[SrvIdentity.SSLEID_Flags] , val!=0);
					if (nval.compareTo("f")==0) dta[SrvIdentity.SSLEID_Flags] = J.setBit(SrvIdentity.SSLEID_Flags_Fixed, (int)  dta[SrvIdentity.SSLEID_Flags] , val!=0);
				}
				
			int tcr=(int)(System.currentTimeMillis()/1000L);
			
			if (dta[SrvIdentity.SSLEID_First]==0) dta[SrvIdentity.SSLEID_First]=tcr;
			dta[SrvIdentity.SSLEID_Last] = tcr;
			dta[SrvIdentity.SSLEID_EndTime] = tcr + (60* Config.SSLETRefreshRate*2);
			SSLErrorTracker.put(host, dta);
				
		}
		
		public String SSLEtoString() {
			 
			String msg="";
			
			int[] par = new int[] {
					SrvIdentity.SSLEID_CurID				,
					SrvIdentity.SSLEID_EHash				,
					SrvIdentity.SSLEID_CanChange		,
					SrvIdentity.SSLEID_Err					,
					SrvIdentity.SSLEID_Socket				,
					SrvIdentity.SSLEID_Ok					,
					SrvIdentity.SSLEID_Hits					,
					SrvIdentity.SSLEID_Flags				}
					;
			
			String[] he = new String[] { "T.Id", "ECrt" , "Chg." , "Err." , "Sok.", "Ok", "Hits", "Flags" } ;
			int[] sz = new int[] { 4,4,4,4,4,4,4,6 } ;
					
			
			msg+=J.Spaced("Host",25)+" ";
			for (int ax=0;ax<he.length;ax++) msg+=J.Spaced(he[ax],sz[ax])+" ";
			msg+=J.Spaced("Date",16)+" ";
			msg+=J.Spaced("Expiry",16)+" ";
			msg+="\n";
			
			for(String host:SSLErrorTracker.keySet()) {
				Integer[] dta = SSLErrorTracker.get(host);
				msg+=J.Spaced(host,25)+" ";
				
				for (int ax=0;ax<par.length;ax++) {
					int v = dta[par[ax]];
					String s = null;
					
					if (par[ax]==SrvIdentity.SSLEID_Flags) {
						s="";
						if (0!=(v&SrvIdentity.SSLEID_Flags_Fixed)) s+="F"; else s+="-";
						if (0!=(v&SrvIdentity.SSLEID_Flags_IncompatibleSSL)) s+="I"; else s+="-";
						if (0!=(v&SrvIdentity.SSLEID_Flags_BadServer)) s+="B"; else s+="-";
						if (0!=(v&SrvIdentity.SSLEID_Flags_Changed)) s+="C"; else s+="-";
						if (0!=(v&SrvIdentity.SSLEID_Flags_NoSSL)) s+="N"; else s+="-";
						if (0!=(v&SrvIdentity.SSLEID_Flags_Persistent)) s+="P"; else s+="-";
						}
										
					if (s==null) s=Integer.toString(v);
					msg+=J.Spaced(s, sz[ax])+" ";
					}
			msg+=J.Spaced(Stdio.relativeDate( (int) dta[SrvIdentity.SSLEID_Last]),16)+" ";
			
			if (0!=(dta[SrvIdentity.SSLEID_Flags]& SrvIdentity.SSLEID_Flags_Persistent)) 
					msg+=J.Spaced("(none)",16)+" "; 
				else
					msg+=J.Spaced(Stdio.relativeDate( (int) dta[SrvIdentity.SSLEID_EndTime]),16)+" ";
			
			msg+="\n";
			}
		return msg;
		}
		
		public void SaveSSLEID() throws Exception {
			int cx = SSLErrorTracker.size();
			byte[][] dtb = new byte[cx][];
			byte[][] dta = new byte[cx][];
			int bp=0;
			for(String host:SSLErrorTracker.keySet()) {
				Integer[] i = SSLErrorTracker.get(host);
				int cl=i.length;
				int[] dw = new int[cl];
				for (int al=0;al<cl;al++) dw[al] = i[al];
				dtb[bp] = Stdio.Stosxi(dw,2 );
				dta[bp] = host.getBytes();
				bp++;
				}
			
			byte[] b = Stdio.MxAccuShifter(new byte[][] {
						 Stdio.MxAccuShifter(dta,1) ,
						 Stdio.MxAccuShifter(dtb,2)
					}, Const.MX_SSLEID,true)
					;
			dta=null;
			dtb=null;

			byte[] key = Stdio.sha256a(new byte[][] { Sale, Subs[3] , Nick.getBytes() } );
			byte[] iv = Stdio.md5a(new byte[][] { key, Sale });
			
			b = Stdio.AES2Enc(key, iv, b);
			Stdio.file_put_bytes(Maildir+"ssleid.dat", b);
			
		}
		
		public void LoadSSLEID() throws Exception {
						
			String fn =Maildir+"ssleid.dat";
			if (!new File(fn).exists()) return;
			
			byte[] b= Stdio.file_get_bytes(fn);

			byte[] key = Stdio.sha256a(new byte[][] { Sale, Subs[3] , Nick.getBytes() } );
			byte[] iv = Stdio.md5a(new byte[][] { key, Sale });
			
			b = Stdio.AES2Dec(key, iv, b);
			byte dta[][] = Stdio.MxDaccuShifter(b, Const.MX_SSLEID);
			b=null;
			byte dtb[][] = Stdio.MxDaccuShifter(dta[1], 2);
			dta = Stdio.MxDaccuShifter(dta[0], 1);
			
			int cx = dta.length;
			for (int ax=0;ax<cx;ax++) {
				int[] dw = Stdio.Lodsxi(dtb[ax], 2);
				Integer[] val = J.newInteger(SrvIdentity.SSLEID_SIZE);
				for (int al=0;al<dw.length;al++) val[al]=dw[al];
				String host = new String(dta[ax]);
				host=host.toLowerCase().trim();
				SSLErrorTracker.put(host, val);
				}
			
			dta=null;
			dtb=null;
			
		}
			
		public void CheckSSLOperations() throws Exception {
			int eHash=0;
			int nHost=0;
			boolean lastExitBad=false;

			String cld="";
			int tcr = (int) (System.currentTimeMillis()/1000L);
			String msg="";
			
			for (String host:SSLErrorTracker.keySet()) {
				nHost++;
				Integer[] dta = SSLErrorTracker.get(host);
				
				if (0!=(dta[SrvIdentity.SSLEID_Flags] & SrvIdentity.SSLEID_Flags_Fixed)) continue;
				
				if (host.endsWith(".onion")) {
					dta[SrvIdentity.SSLEID_Flags] |= SrvIdentity.SSLEID_Flags_BadServer;
					eHash++;
					continue;
					}
				
				if (dta[SrvIdentity.SSLEID_Err]>0) {
							if (dta[SrvIdentity.SSLEID_Err]>0 && dta[SrvIdentity.SSLEID_Ok] ==0) {
									dta[SrvIdentity.SSLEID_Flags] |= SrvIdentity.SSLEID_Flags_NoSSL | SrvIdentity.SSLEID_Flags_Persistent | SrvIdentity.SSLEID_Flags_IncompatibleSSL;
									Log("The SSL Certificate of `"+host+"` is incompatible.");
									msg+="The SSL Certificate of `"+host+"` is incompatible.\n";
									}
							}  	
								
				if (dta[SrvIdentity.SSLEID_CurID]==Config.TORIdentityNumber) {
						if (dta[SrvIdentity.SSLEID_EHash]>0) {
								eHash++;
								if ( dta[SrvIdentity.SSLEID_EHash]>dta[SrvIdentity.SSLEID_Ok] ) dta[SrvIdentity.SSLEID_CanChange]++;
								dta[SrvIdentity.SSLEID_EHash]=0;
								dta[SrvIdentity.SSLEID_Ok]=0;
								dta[SrvIdentity.SSLEID_EndTime] = (int)(System.currentTimeMillis()/1000L)+86400;
								Log("The SSL Certificate of `"+host+"` is changing.");
								msg+="The SSL Certificate of `"+host+"` is changing.\n";
								}
					
					} else {
						if (dta[SrvIdentity.SSLEID_EHash]>0) {
								if ( dta[SrvIdentity.SSLEID_EHash]>dta[SrvIdentity.SSLEID_Ok] ) {
									dta[SrvIdentity.SSLEID_Flags] |= SrvIdentity.SSLEID_Flags_Changed;
									dta[SrvIdentity.SSLEID_EndTime] = (int)(System.currentTimeMillis()/1000L)+86400;
									dta[SrvIdentity.SSLEID_CurID] = Config.TORIdentityNumber;
									if (SSLEIDPermitAutoChange) try {
											Log("The SSL Certificate of `"+host+"` is updated");
											msg+="The SSL Certificate of `"+host+"` is updated\n";
											String fn = GetFNName(host)+".crt";
											new File(fn).delete();
											new File(fn+"h").delete();
											} catch(Exception I) {
												Config.EXC(I, "SSLOperations.ChCRT."+Nick);
											} else {
												msg+="Please verify the SSL Certificate of `"+host+"`\n";
												Log("The SSL Certificate of `"+host+"` is changed. Please verify!");
											}
									}
								}
					if (dta[SrvIdentity.SSLEID_EHash]==0 && dta[SrvIdentity.SSLEID_Ok]>0 && dta[SrvIdentity.SSLEID_CanChange]>0) {
						 dta[SrvIdentity.SSLEID_Flags]=0;
						 dta[SrvIdentity.SSLEID_EndTime]=0;
						 lastExitBad=true;
						}
					}
			SSLErrorTracker.put(host, dta);
			
			if (
					(dta[SrvIdentity.SSLEID_Flags]&SrvIdentity.SSLEID_Flags_Persistent)==0 &&
					tcr>dta[SrvIdentity.SSLEID_EndTime]
					) cld+=host+"\n";
			}			
		
			for (String host:cld.split("\\n+")) SSLErrorTracker.remove(host);
			PreventTooManySSLErrorTrackGarbages=System.currentTimeMillis()+5000L;
			
			int p =(int)  Math.ceil((eHash / (nHost!=0 ? nHost : 1))*100.0);
			if (eHash>Config.MaxSSLEHash || p>Config.MaxSSLEHashP) iWantChangeIdentity=true;
			if (eHash>0) Log("Bad SSL Hosts = "+eHash+" Change identity = "+ ( iWantChangeIdentity ? "yes": "no")+" LastExit was bad = "+(lastExitBad?"Yes":"no"));
			
			if (eHash>0) msg="Bad SSL Hosts "+eHash+"\n"+msg;
			if (iWantChangeIdentity) msg="I need to change TOR identity!\n"+msg;
			if (lastExitBad) msg="Last TOR ExitNode is bad!\n"+msg;
			if (Config.SSLSysopMessages && msg.length()>0) try {
				msg+=SSLEtoString();
				
				int chk = msg.hashCode();
				String fch = Maildir+"/ssleid.chk";
				boolean send = true;
				
				if (new File(fch).exists()) try {
					byte[] tmp = Stdio.file_get_bytes(fch);
					int[] z = Stdio.Lodsxi(tmp, 4);
					if (z[0]==chk) send=false;
				} catch(Exception e) { Config.EXC(e, "SSLEID.CHK:Load"); }
				
				try {
					byte[] tmp =Stdio.Stosxi(new int[] { chk} , 4);
					Stdio.file_put_bytes(fch, tmp);
				} catch(Exception e)  { Config.EXC(e, "SSLEID.CHK:Save"); }
				
				if (send) {
					msg=msg.replace("\n", "\r\n");
					HashMap <String,String> Hldr= SrvSMTPSession.ClassicHeaders("server@"+Onion, "sysop@"+Onion);
					Hldr.put("subject", "SSLEID Server's message");
					SendLocalMessage("sysop", Hldr, msg);
				} else Log("SSLEID Equals");
				msg=null;
				} catch(Exception I) { Config.EXC(I,Nick+": Can't send sysop SSL message!"); }
			
		}
		
		public boolean ifSSLE(String host) { 
				if (Config.SSLEDisabled) return false;
				return SSLErrorTracker.containsKey(host.toLowerCase().trim()); }
		
		public void SSLErrorTrack(String host,int SSLEID) throws Exception {
			if (Config.SSLEDisabled) return;
			
			host=host.toLowerCase().trim();
			long tcrl = System.currentTimeMillis();
			int tcr = (int) (tcrl/1000L);
			Integer[] dta=null;
			if (SSLErrorTracker.containsKey(host)) dta = SSLErrorTracker.get(host); else {
				dta = J.newInteger(SrvIdentity.SSLEID_SIZE);
				dta[SrvIdentity.SSLEID_First] = tcr;
				dta[SrvIdentity.SSLEID_CurID]=Config.TORIdentityNumber; 
				}
					
			dta[SSLEID]++;
			dta[SrvIdentity.SSLEID_Hits]++;
			dta[SrvIdentity.SSLEID_Last] = tcr;
			dta[SrvIdentity.SSLEID_EndTime] = tcr+ (Config.SSLETRefreshRate*120);
			
			SSLErrorTracker.put(host, dta);
			
			if (PreventTooManySSLErrorTrackGarbages>tcrl) return;
			PreventTooManySSLErrorTrackGarbages=tcrl+5000L;
			
			synchronized(SSLErrorTracker) {
				String del="";
				for(String k:SSLErrorTracker.keySet()) {
					dta = SSLErrorTracker.get(k);
					if ((dta[SrvIdentity.SSLEID_Flags]&SrvIdentity.SSLEID_Flags_Persistent)!=0) continue;
					if (tcr>dta[SrvIdentity.SSLEID_EndTime]) del +=k+"\n";
					}
				
				String garb[] = del.split("\\n+");
				for (String k:garb) SSLErrorTracker.remove(k);
				}
						
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
		
		
		
	/*
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
		*/
		/*
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
		
		 */
		
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
					RS.setSoTimeout(Config.MaxSMTPSessionTTL);
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
			if (logonTempData==null) throw new Exception("Cant create BOOT without `CVMF3805TMP`");
							
			Log("Create BOOT");
			try {
						String[] slist = RequildFriendsList();
						String s0="\n";
						int cx= slist.length;
						for (int ax=0;ax<cx;ax++) {
								String fn="\n"+slist[ax].toLowerCase().trim()+"\n";
										if (s0.contains(fn)) continue;
										if (Config.NoBootFromSameMachine) {
											if (OnTheSameMachine.contains(fn)) continue;
											}
										s0+=slist[ax].toLowerCase().trim()+"\n"; 
								}
											
						s0=s0.trim();
						slist=s0.split("\\n+");
						if (slist.length==0 || s0.length()==0) throw new Exception("No server available to build  BootSequence file");
						RemoteKSeedInfo[] info = new RemoteKSeedInfo[slist.length];
						byte[] rky = Stdio.MXImplode(logonTempData, 0x7C01F6C7);		//Implode Server KeyBlock 0x7C01F6C7 is the magic number
						J.WipeRam(logonTempData);		//Destroy KeyBlock
						logonTempData=null;
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
								String SysOpTXTPath;
								if (Config.AlternatePositionSysOpTxt!=null) {
									SysOpTXTPath=Config.AlternatePositionSysOpTxt+Nick+"/sysop.txt";
									new File(SysOpTXTPath).mkdirs();
									} else SysOpTXTPath=Maildir+"/sysop.txt";
								
								PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(SysOpTXTPath, true)));
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
									if (logonTempData!=null) J.WipeRam(logonTempData);
									logonTempData=null;
									String ab = EX.getMessage();
									if (ab!=null && ab.contains("@")) Log(Config.GLOG_Server,ab.replace('@', ' ')); else Config.EXC(EX, "SCBF`"+Onion+"`"); 
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
					RS.setSoTimeout(Config.MaxSMTPSessionTTL);
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
		//	byte[] dta=null;
			
			try {
			
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, oni,25);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionTTL);
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
			if (Config.isManuReserverdUser(user)) throw new PException("@550 Blocked or reserved username");
			
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
			re.Par.put("vmatmail","N/A");
			re.Par.put("vmatpass","(no password)");
		
			ExitRouteList EL = GetExitList();
			ExitRouterInfo SE = EL.selectBestExit();
			
			re.Par.put("inetaddr", user+"."+Onion +"@" + ((SE==null) ? "<exit address>" : SE.domain));
			
			if (SE!=null && SE.canVMAT) try {
				VirtualRVMATEntry RVM = VMATRegister(user+"@"+SE.domain,user);
				if (RVM!=null) {
					re.Par.put("vmatmail",RVM.mail);
					re.Par.put("vmatpass",RVM.passwd);
					re.Par.put("inetaddr", RVM.mail);
					} 
				} catch(Exception E) {
						if (Config.Debug) E.printStackTrace();
						String msge=E.getMessage();
						if (msge==null) msge=null;
						if (msge!=null & msge.startsWith("@")) Log("RQUS: Error "+msge.substring(1)); else Config.EXC(E, "RQUS.VMAT");
						}
			
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
			if (!NewUsrEnabled) throw new Exception("@550 SR6003 Operation not permitted");
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
			if (!NewLstEnabled) throw new Exception("@550 SR6004 Operation not permitted");
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
			boolean bm= Main.ConfVars!=null;
			if (bm) bm = Main.ConfVars.containsKey(Nick+"-pgp-key");
			
			if (!bm) Main.echo("\nDo you want to insert a PGP Public & Private key for server`"+Nick+"`\n\tYes, No ?");
			boolean re=false;
			BufferedReader In = J.getLineReader(System.in);
					
			if (bm) re=true; else try { re = Config.parseY(In.readLine().trim().toLowerCase()); } catch(Exception I) { Main.echo("NO\n"); }
			
					if (re) try {
						String Pat;
						if (bm) {
							Pat = Main.ConfVars.get(Nick+"-pgp-key");
							if (Pat.length()==0) {
								String x ="OM:[ERR] Invalid PGP key path on header `"+Nick+"-pgp-key"+"`";
								Main.out(x+"\n");
								throw new Exception(x);
								}
						} else {
							Main.echo("Enter the ASCII file name: >");
							Pat= In.readLine().trim();
							}
						Pat = new String(Stdio.file_get_bytes(Pat));
						String Pass;
						if (bm && Main.ConfVars.containsKey(Nick+"-pgp-pass")) {
							Pass = Main.ConfVars.get(Nick+"-pgp-pass");
							Main.ConfVars.put(Nick+"-pgp-pass", J.RandomString(64));
							System.gc();
							Main.ConfVars.remove(Nick+"-pgp-pass");
							System.gc();
						} else {
							Main.echo("Enter the "+Nick+"'s PGP KEY Passphrase: >");
							Pass = In.readLine().trim();
							}
						
						String Priv = J.ParsePGPPrivKey(Pat);
						Pat = J.ParsePGPKey(Pat);
						UserSetPGPKey(Pat, "server",true);
						UserSetPGPKey(Priv, Const.SRV_PRIV,true);
						byte[] b = Pass.getBytes("UTF-8");
						b=Stdio.AESEncMulP(Sale, b);
						Stdio.file_put_bytes(Maildir+"/head/hldr", b);
						Main.out((bm ?"OM:[PGP_OK]"+Nick+" ":"" )+"PGP Keys for `"+Nick+"` is set!\n");
						} catch(Exception EX) {
							String ms = EX.getMessage();
							Main.out((bm ?"OM:[PGP_ERR]"+Nick+" ":"" )+"Error: "+ms+"\n");
							Log(Config.GLOG_Server, "Can't set PGP Keys: "+ms);
							if (Config.Debug) EX.printStackTrace();
						}
					
				if (bm) {
					if (Main.ConfVars.containsKey(Nick+"-delkey")) {
						String[] x = new String[] { Nick+"-pgp-key" , Nick+"-pgp-pass" , Nick+"-delkey" };
						String pg = Main.ConfVars.get(Nick+"-pgp-key" );
						if (pg!=null) try { J.Wipe(pg, false); } catch(Exception E) { Config.EXC(E, Nick+".DelPGPKeys"); }
						for(String k:x) {
							Main.ConfVars.put(k, J.RandomString(32));
							System.gc();
							Main.ConfVars.put(k, "");
							Main.ConfVars.remove(k);
							}
						System.gc();
					}
				}
		}
		
		public void SrvAutoPGPKeys() throws Exception {
			
			Log("Generating new PGP KeyPair");
			if (Main.ConfVars==null) Main.echo("Creating Server's PGP keys Please wait...\n");
			
			ByteArrayOutputStream Public = new ByteArrayOutputStream();
			ByteArrayOutputStream Private = new ByteArrayOutputStream();
			//long r = Stdio.NewRndLong() % 365;
			//r=r*86400;
			
			long TimeFrom=0;
			if (SSlInfo.containsKey("from")) TimeFrom = J.parseInt(SSlInfo.get("from"));
			if (TimeFrom<1) TimeFrom = System.currentTimeMillis() - (86400000L * Math.abs(Stdio.NewRndLong() % 365)+86400000L);
			
			String id;
			if (AutoPGPID!=null) {
				String st = AutoPGPID.trim();
				st = ExpandStr(st);
				st=st.replace('<', ' ');
				st=st.replace('>', ' ');
				st=st.trim();
				st+=" <server@"+Onion+">";
				id=st;
				} else id="server@"+Onion;
			
			String Pws = PGPKeyGen.KeyGen(
						new Date(TimeFrom),
						id,
						Public, 
						Private)
						;
			
			String Pub = new String(Public.toByteArray());
			UserSetPGPKey(Pub, "server",true);
			UserSetPGPKey(new String(Private.toByteArray()), Const.SRV_PRIV,true);
			byte[] b = Pws.getBytes("UTF-8");
			b=Stdio.AESEncMulP(Sale, b);
			Stdio.file_put_bytes(Maildir+"/head/hldr", b);
			Pws=J.RandomString(Pws.length());
			Pws=null;
			Stdio.file_put_bytes(Maildir+"/publicKey.asc", Pub.getBytes());
			Private.reset();
			Private.close();
			Private=null;
			Private=Public;
			Public.reset();
			Public=null;
			Private=null;
			System.gc();
			Log("PGP KeyPair generated!");
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
		
		public VirtualRVMATEntry VMATRegister(String vmat,final String localpart) throws Exception {
			if (VMAT==null) throw new Exception("VMATRegister: VMAT Disabled");
			
			final String vmatLocal = J.getLocalPart(vmat);
			final String vmatDom=J.getDomain(vmat);
			if (vmatLocal==null || vmatDom==null) throw new Exception("@500 Invalid VMAT address `"+vmat+"`");
			ExitRouteList RL= GetExitList();
			String Server = RL.getOnion(vmatDom);
			if (Server==null) throw new Exception("@500 Can't find exit `"+vmatDom+"`");
			
			SrvAction A = new SrvAction(this,Server,"VMATRegister") {
				
				public void OnSession(BufferedReader RI,OutputStream RO) throws Exception {
					if (!this.SupVMAT) throw new Exception("@500 VMAT is not supported by `"+this.Server+"`");
					VirtualRVMATEntry M=null;
					SMTPReply Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM VMAT REGISTER "+vmatLocal+" "+localpart);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					if (Re.Msg.length<3) throw new Exception("@500 Invalid VMAT REGISTER reply");
					M=new VirtualRVMATEntry();
					M.mail=J.getMail(Re.Msg[0], false);
					M.onionMail=J.getMail(Re.Msg[1],true);
					M.passwd=Re.Msg[2];
					M.server=this.Server;
					
					if (M.mail==null || !M.mail.contains("@"+vmatDom)) throw new Exception("@500 Invalid VMAT address in reply `"+M.mail+"`");
					if (M.onionMail==null || M.onionMail.compareTo(localpart+"@"+Onion)!=0) new Exception("@500 Invalid mail address in reply `"+M.onionMail+"`");
					if (M.passwd.length()==0) throw new Exception("@500 Invalid password in VMAT reply");
					
					int cx = Re.Msg.length;
					if (cx>3) {
						cx-=3;
						String rsa = new String();
						for (int ax=0;ax<cx;ax++) rsa+=Re.Msg[ax+3].trim();
						M.sign = J.Base64Decode(rsa);
						rsa=null;
						}
					
					this.RES = new Object[] { M };
					}
			} ;
			A.DoInSSL=true;
			A.DoInTKIM=true;
			A.Do();

			if (A.RES==null) throw new Exception("@500 No VMAT[0] Data");
			VirtualRVMATEntry M =(VirtualRVMATEntry) A.RES[0];
			if (M==null) throw new Exception("@500 No VMAT Data");
			VMAT.recipientSetRVMAT(localpart, M.mail);
			VMAT.saveRVMATinTor(localpart, M);
			boolean setDef=true;
			try {
				HashMap <String,String> Conf = UsrGetConfig(localpart);
				if (Conf!=null) { 
					if (!Conf.containsKey("torvmat")) Conf.put("torvmat", "yes");
					if (Conf.containsKey("novmatautoset")) try { setDef = true ^ Config.parseY(Conf.get("novmatautoset")); } catch(Exception I) {}
					} else {
						Conf = new HashMap <String,String>();
						Conf.put("torvmat", "yes");
						Conf.put("novmatautoset", "no");
					}
				this.UsrSetConfig(localpart, Conf);
				} catch(Exception E) {
					Config.EXC(E, Nick+".RegVMAT/Conf"); 
				}
			
			if (setDef) VMAT.setRVMATinTor(localpart, J.getDomain(M.mail));
			return M;
		}		
						
		public void VMATEnable(String vmat,String localpart,final String passwd,final boolean stat) throws Exception {
			if (VMAT==null) throw new Exception("VMATEnable: VMAT Disabled");
			
			final String vmatLocal = J.getLocalPart(vmat);
			final String vmatDom=J.getDomain(vmat);
			if (vmatLocal==null || vmatDom==null) throw new Exception("@500 Invalid VMAT address `"+vmat+"`");
			ExitRouteList RL= GetExitList();
			String Server = RL.getOnion(vmatDom);
			if (Server==null) throw new Exception("@500 Cant' find exit `"+vmatDom+"`");
			
			SrvAction A = new SrvAction(this,Server,"VMATEnable") {
				
				public void OnSession(BufferedReader RI,OutputStream RO) throws Exception {
					if (!this.SupVMAT) throw new Exception("@500 VMAT is not supported by `"+this.Server+"`");
					VirtualRVMATEntry M=null;
					SMTPReply Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM VMAT CHG "+vmatLocal+" "+passwd+" "+(stat ? "TRUE":"FALSE"));
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					}
			} ;
			A.DoInSSL=true;
			A.DoInTKIM=true;
			A.Do();

			if (stat) VMAT.recipientSetRVMAT(localpart, vmat); else VMAT.recipientDeleteRVMAT(localpart, vmat);
			
		}		
		
		public void VMATDelete(String vmat,String localpart,final String passwd) throws Exception {
			if (VMAT==null) throw new Exception("VMATDelete: VMAT Disabled");
			
			final String vmatLocal = J.getLocalPart(vmat);
			final String vmatDom=J.getDomain(vmat);
			if (vmatLocal==null || vmatDom==null) throw new Exception("@500 Invalid VMAT address `"+vmat+"`");
			ExitRouteList RL= GetExitList();
			String Server = RL.getOnion(vmatDom);
			if (Server==null) throw new Exception("@500 Cant' find exit `"+vmatDom+"`");
			
			SrvAction A = new SrvAction(this,Server,"VMATDelete") {
				
				public void OnSession(BufferedReader RI,OutputStream RO) throws Exception {
					if (!this.SupVMAT) throw new Exception("@500 VMAT is not supported by `"+this.Server+"`");
					SMTPReply Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM VMAT CHG "+vmatLocal+" "+passwd+" DELETE");
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()+ " (remote)");
					}
			} ;
			A.DoInSSL=true;
			A.DoInTKIM=true;
			A.Do();
			VMAT.recipientDeleteRVMAT(localpart, vmat);
			
		}		
		
		private volatile int[] RMXCacheS = new int[128];
		private volatile int[] RMXCacheT=new int[128];
		private volatile boolean[] RMXCacheB = new boolean[128];
		private volatile  int RMXCacheTTL = 10;
		
		public void setRMXCache(int sz,int ttl) {
			RMXCacheTTL=ttl;
			RMXCacheS = new int[sz];
			RMXCacheT=new int[sz];
			RMXCacheB = new boolean[sz];
			}
		
		public int RMXCacheGet(String versrc) {
			int cx = RMXCacheS.length;
			int tcr = (int) System.currentTimeMillis()/60000;	
			int chk = versrc.hashCode();
			
			for (int ax=0;ax<cx;ax++) {
				if (RMXCacheS[ax]==chk) {
					RMXCacheT[ax] = tcr + RMXCacheTTL;
					return RMXCacheB[ax] ? 3 : 2;
					}
				
				if (tcr>RMXCacheT[ax]) {
						RMXCacheT[ax]=0;
						RMXCacheS[ax]=0;
						}
			}
			return 0;
		}
		
		public void RMXCacheSet(String versrc,boolean ok) {
			int tcr = (int) System.currentTimeMillis()/60000;	
			int cx = RMXCacheS.length;
			int chk = versrc.hashCode();
			int oldT = tcr;
			int oldI=-1;
			int zeroI=-1;
			for (int ax=0;ax<cx;ax++) {
				if (RMXCacheS[ax]==chk) {
					RMXCacheT[ax] = tcr + RMXCacheTTL;
					RMXCacheB[ax]=ok;
					return;
					}
			if (tcr>RMXCacheT[ax]) {
					RMXCacheT[ax]=0;
					RMXCacheS[ax]=0;
					}
			
			if (zeroI==-1 && RMXCacheS[ax]==0) zeroI=ax;
			if (RMXCacheT[ax]<oldT) {
				oldT=RMXCacheT[ax];
				oldI=ax;
				}
			}
		
		if (zeroI==-1) zeroI=oldI;
		if (zeroI==-1) zeroI=0;
		
		RMXCacheS[zeroI]=chk;
		RMXCacheB[zeroI]=ok;
		RMXCacheT[zeroI]=tcr+RMXCacheTTL;
		}
		
		public boolean VerifySMTPInetTest(String versrc) throws Exception {
			
		int ch = RMXCacheGet(versrc);	
		if (ch!=0) {
				if (Config.Debug) Log("RMX by cache");
				return (ch&1)!=0;
				}
		
		 ExitRouteList el = GetExitList();
		 ExitRouterInfo ex = el.selectExit(true);
		 
		 if (ex==null) {
			 	Log("Can't verify `"+versrc+"` no MX available");
			 	return true;
		 		}
		 
		 try {
			 MXRecord[] mx = remoteSMTPTest(ex.onion,versrc);
			 ex.setResult(true);
			 boolean bit;
			 if (mx==null || mx.length==0) bit=false; else bit=true;
			 RMXCacheSet(versrc, bit);
			 return bit;
		 	} catch(Exception E) {
		 	Log("VerifySMTPInetTest Error: "+E.getMessage());
		 	ex.setResult(false);
		 	return true;
		 	}
		
		}
		
		public MXRecord[] remoteSMTPTest(String server,final String verify) throws Exception {
			SrvAction A = new SrvAction(this,server,"Remote VRFY `"+verify+"`") {
				public void OnSession(BufferedReader RI,OutputStream RO) throws Exception {
					if (!this.SupTORM) throw new Exception("@550 Server doesn't support TORM `"+this.Server+"`");
					if (!this.SupMX) throw new Exception("@550 Server doesn't support MX `"+this.Server+"`");
					SMTPReply Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM MX "+verify);
					if (Re.Code<200 || Re.Code>299) this.RES=null; else this.RES = Re.Msg;
					}
				};
			
			A.DoInSSL=false;
			A.DoInTKIM=false;
			
			A.Do();
			if (A.RES==null || A.RES.length==0) return null;
			int cx = A.RES.length;
			MXRecord[] MX = new MXRecord[cx];
			for (int ax=0;ax<cx;ax++) {
					String s = (String) A.RES[ax];
					s=s.toLowerCase().trim();
					String[] tok = s.split("\\s+");
					if (tok.length<2) return null;
					MX[ax] = new MXRecord(Config.parseIntS(tok[0]),tok[1]);
					}
			MXRecord.MXSort(MX);
			return MX;
		}
		
		public String VoucherCreate(int DynaScanMins) throws Exception {
			byte[] a = new byte[14];
			Stdio.NewRnd(a);
			if (DynaScanMins<1) DynaScanMins=VoucherLength;
			
			int ts = DynaScanMins!=0 ? (int)(DynaScanMins+((System.currentTimeMillis()+Config.TimeSpoof)/60000L)) : 0;
			
			Log("ts "+ts+" "+Long.toHexString(ts));
			byte[] cod = Stdio.md5a(new byte[][] { Sale, Subs[7&a[13]] , Subs[7&a[12]] });
			
			for (int ax=0;ax<4;ax++) {
				a[ax] = (byte) (255&ts);
				a[ax]^=cod[ax];
				a[ax]^=cod[15&cod[ax^15]];
				ts=ts>>8;
				}
			 				
			byte[] b = Stdio.md5a(new byte[][] { a , Sale });
			byte[] c = new byte[30];
			System.arraycopy(a, 0, c, 0, 14);
			System.arraycopy(b, 0, c, 14, 16);
			
			return J.Base64Encode(c);
			}
		
		public static final int VOUCHER_UNKNOWN=0;
		public static final int VOUCHER_OK=1;
		public static final int VOUCHER_USED=-1;
		public static final int VOUCHER_OLD=-2;
		
		public void VoucherLogClear() {
			try {
				HashMap<String,String> x = new HashMap<String,String>();
				byte[] e =J.HashMapPack(x);
				x=null;
				byte[][] in = new byte[][] { e ,e };
				Stdio.SFileSave(this, in,  Const.SFS_VOUCHER);
				} catch(Exception E) { Config.EXC(E, "VoucherLogClear"); }
			}
		
		public String VoucherLogGet(String vc) throws Exception {
			
			HashMap <String,String> vs= null;
			HashMap <String,String> vl= null;
			
			try {
				byte[][] in = Stdio.SFileLoad(this, Const.SFS_VOUCHER);
				vs = J.HashMapUnPack(in[0]);
				vl = J.HashMapUnPack(in[1]);
			} catch (Exception E) {
					 vs= new HashMap <String,String> ();
					 vl= new HashMap <String,String> ();
				}
			
			if (vc==null) {
				String st="";
				for(String k:vl.keySet()) {
					st+="Voucher: "+k+"\n";
					st+="\tStatus: "+vs.get(k)+"\n";
					st+="\tLog:\n\t";
					st+=vl.get(k).replace("\n", "\n\t");
					st+="--------\n\n";
					}
				return st;
				} else {
				if (!vl.containsKey(vc)) return null;
				return "Voucher: "+vc+"\nStatus: "+vs.get(vc)+"\nLog:\n"+vl.get(vc)+"\n";
				}
			
		}
		
		public void VoucherLogDel(String vc)  {
			try {
				HashMap <String,String> vs= null;
				HashMap <String,String> vl= null;
				
				try {
					byte[][] in = Stdio.SFileLoad(this, Const.SFS_VOUCHER);
					vs = J.HashMapUnPack(in[0]);
					vl = J.HashMapUnPack(in[1]);
				} catch (Exception E) {
					 vs= new HashMap <String,String> ();
					 vl= new HashMap <String,String> ();
				}
				
				vs.remove(vc);
				vl.remove(vc);

				byte[][] in = new byte[][] { J.HashMapPack(vs) , J.HashMapPack(vl) };
				Stdio.SFileSave(this, in,  Const.SFS_VOUCHER);
			} catch(Exception EV) { Config.EXC(EV, "VoucherLogDel"); }
		}
		
		public void VoucherLog(String vc,int st,String msg)  {
			try {
				HashMap <String,String> vs= null;
				HashMap <String,String> vl= null;
				
				try {
					byte[][] in = Stdio.SFileLoad(this, Const.SFS_VOUCHER);
					vs = J.HashMapUnPack(in[0]);
					vl = J.HashMapUnPack(in[1]);
				} catch (Exception E) {
					 vs= new HashMap <String,String> ();
					 vl= new HashMap <String,String> ();
				}
				
				long tcr = this.Time();
				vs.put(vc, Integer.toString(15+st,36)+" "+Integer.toString((int)(tcr/1000L)));
				String l=null;
				if (vl.containsKey(vc)) l = vl.get(vc); else l="";
				msg=msg.replace('\n', ' ');
				l+=Integer.toString(15+st,36)+" "+J.TimeStandard(tcr)+"\t"+msg.trim()+"\n";
				String[] t0 = l.split("\\n+");
				int cx = t0.length;
				
				if (cx>3) {
					l="";
					for (int ax=1;ax<cx;ax++) l+=t0[ax]+"\n";
					}
				
				t0=null;
				vl.put(vc, l.trim());
				byte[][] in = new byte[][] { J.HashMapPack(vs) , J.HashMapPack(vl) };
				Stdio.SFileSave(this, in,  Const.SFS_VOUCHER);
			} catch(Exception EV) { Config.EXC(EV, "VoucherLogSC"); }
		}
		
		public void VoucherLogGarbage() {
			long tcr = (int)(System.currentTimeMillis()/1000L);
			
			try {
				HashMap <String,String> vs= null;
				HashMap <String,String> vl= null;
				
				try {
					byte[][] in = Stdio.SFileLoad(this, Const.SFS_VOUCHER);
					vs = J.HashMapUnPack(in[0]);
					vl = J.HashMapUnPack(in[1]);
				} catch (Exception E) {
					 vs= new HashMap <String,String> ();
					 vl= new HashMap <String,String> ();
				}
				
				String rm="";
				for(String k:vs.keySet()) {
					String s = vs.get(k);
					if (s.length()<2) continue;
					s=s.substring(2);
					long t = J.parseLong(s.trim());
					if ( tcr - t > 864000) rm+=k+"\n";
				}
				
				rm=rm.trim();
				int cx=0;
				if (rm.length()>0) {
					String[] rma=rm.split("\\n+");
					cx = rma.length;
					for (int ax=0;ax<cx;ax++) {
						vs.remove(rma[ax]);
						vl.remove(rma[ax]);
						}
					}
				if (cx>0) 	Log("VoucherLogGarbage: "+cx+" records removed");
				
				byte[][] in = new byte[][] { J.HashMapPack(vs) , J.HashMapPack(vl) };
				Stdio.SFileSave(this, in,  Const.SFS_VOUCHER);
			} catch(Exception EV) { Config.EXC(EV, "VoucherLogGarb"); }
		}
						
		public synchronized int VoucherTest(String vc,boolean save) throws Exception {
			byte[] c = J.Base64Decode(vc);
			if (c.length!=30) return 0;
			byte[] a = new byte[14];
			byte[] b = new byte[16];
			System.arraycopy(c, 0, a, 0, 14);
			System.arraycopy(c, 14, b, 0, 16);
			byte[] v = Stdio.md5a(new byte[][] { a , Sale });
			if (!Arrays.equals(b, v)) return VOUCHER_UNKNOWN;
					
			int ts=0;
			byte[] cod = Stdio.md5a(new byte[][] { Sale, Subs[7&a[13]] , Subs[7&a[12]] });
			for (int ax=3;ax>-1;ax--) {
				ts=ts<<8;
				byte by = a[ax];
				by^=cod[ax];
				by^=cod[15&cod[ax^15]];
				ts|=(int)(255&by);
				}
			
			if (ts!=0) {
				int ts2 =(int)((System.currentTimeMillis()+Config.TimeSpoof)/60000L);
				if (ts2>ts) return VOUCHER_OLD;
				}

			v = Stdio.md5a(new byte[][] { b , Sale, a, v });
			for (int ax=0;ax<14;ax++) a[ax]^=v[ax];
			int maxc=0;
			
			String x = Maildir+"/keys/invite.lst";
			RandomAccessFile O=null;
			boolean fin=false;
			try {
				O = new RandomAccessFile(x,"rw");
				O.seek(0);
				if (O.length()!=0) {
					maxc = O.readShort();
					for (int ax=0;ax<maxc;ax++) {
					v = new byte[14];
					O.read(v);
					if (Arrays.equals(v, a)) { 
							fin=true; 
							break; 
							}
					}
				} else O.writeShort(0);
				
			if (save) {
				O.write(a);
				maxc=maxc+1;
				O.seek(0);
				O.writeShort(maxc);
				}
			O.close();	
			} catch(Exception E) {
				try { O.close(); } catch(Exception I) {};
				throw E;
				}	
			 
			if (fin) return VOUCHER_USED; else return VOUCHER_OK;
			
		}
		
		public SMTPReply checkRemoteServer(String server) throws Exception {
			if (!EnterRoute) throw new PException("@500 This is not an exit router");
			MXRecord[] MX = Main.DNSCheck.getMX(server.toLowerCase().trim());
			if (MX==null || MX.length==0) return new SMTPReply(550,"No MX Record");
			MXRecord.MXSort(MX); 
			String st="";
			int cx = MX.length;
			
			for (int ax=0;ax<cx;ax++) st+=MX[ax].Priority+" "+MX[ax].Host+"\n";
			st=st.trim();
			return new SMTPReply(220,st.split("\\n+"),"TORM MX");
			}
		
		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, Nick, st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server, Nick, st); 	}

		public ExitRouterInfo selectExit4User(String localpart) throws Exception {
			String dou=null;
						
			HashMap <String,String> Conf = UsrGetConfig(localpart);
			if (Conf!=null && Conf.containsKey("exitdomain")) dou=Conf.get("exitdomain");
			
			ExitRouteList RL= GetExitList();
			ExitRouterInfo ex = null;
			if (dou!=null) ex= RL.selectExitByDomain(dou, false);
			if (ex==null) ex= RL.selectBestExit();
			RL=null;
			return ex;
			}
		
		public boolean setSendingTORVMAT(String localpart, final HashMap <String,String> Hldr) {
			try {
				HashMap <String,String> Conf = UsrGetConfig(localpart);
				boolean use = true; //XXX Setta come default yes per utenti mindless!
				VirtualRVMATEntry VM=null;
				if (Conf!=null && Conf.containsKey("torvmat")) try { use = Config.parseY( Conf.get("torvmat")); } catch(Exception I) {}
				if (use)  VM = VMAT.loadRVMATinTor(localpart);	
				if (Config.Debug) Log("TORVMAT Session " +( VM==null ? "NO":"YES")); 
				
				if (VM!=null) {
					Hldr.put("from", VM.mail); // !FROM!
					Hldr.put("x-vmat-server", VM.server);
					if (VM.sign!=null && VM.sign.length>0){
						String s0[] = new String[] { J.Base64Encode(VM.sign) };
						s0=J.WordWrapNT(s0[0], 64);
						s0 = new String[] { J.Implode(" ", s0) };
						Hldr.put("x-vmat-sign",s0[0]);
						s0=null;
						}
					return true;
					}
				} catch(Exception E) {
					Config.EXC(E, Nick+".setSendingVMAT `"+J.UserLog(this,localpart)+"`");
				}
			return false;
		}
		
		//fufufa!!!
		public ExitRouterInfo selectExit4User(String localpart,final HashMap <String,String> Hldr ) throws Exception {
			String dou=null;
						
			HashMap <String,String> Conf = UsrGetConfig(localpart);
			if (Conf!=null && Conf.containsKey("exitdomain")) dou=Conf.get("exitdomain");
			
			ExitRouteList RL= GetExitList();
			ExitRouterInfo ex = null;
			if (dou!=null) {
					ex= RL.selectExitByDomain(dou, false);
					if (ex!=null && Conf!=null && Conf.containsKey("usevmat")) {
						boolean use=false;
						try { use = Config.parseY(Conf.get("usevmat")); } catch(Exception XE) {}
						if (use) {
							VirtualRVMATEntry VM = VMAT.SenderVirtualRVMATEntryLoad(localpart+"@"+Onion);
							if (VM!=null) {
								Hldr.put("from", VM.mail);
								Hldr.put("x-rvmat-server", VM.server);
								}
							}
						}
					}
			if (ex==null) ex= RL.selectBestExit();
			RL=null;
			return ex;
			}

		public String mailTor2Inet(String onionMail,String exitDom) throws Exception {
			VirtualRVMATEntry VM = VMAT.SenderVirtualRVMATEntryLoad(onionMail);
			if (VM!=null) {
				return VM.mail;
			} else {
				String a = J.getLocalPart(onionMail);
				String b = J.getDomain(onionMail);
				if (exitDom==null && EnterRoute) exitDom=ExitRouteDomain;
				if (exitDom==null) {
					ExitRouteList rl = GetExitList();
					ExitRouterInfo x = rl.selectAnExit();
					if (x==null) throw new Exception("@550 No exit router available for "+Onion);
					return a+"."+b+"@"+x.domain;
					}
			return a+"."+b+"@"+exitDom;
			}
		}

		public VirtualRVMATEntry LookupVMAT(final String mail,boolean forceLookup) throws Exception {
			VirtualRVMATEntry VM=null;
			ExitRouterInfo ex = null;
			String dom = J.getDomain(mail);
			
			if (!forceLookup) {
				VM = VMAT.SenderVirtualRVMATEntryLoad(mail);
				if (VM!=null) return VM;
				ExitRouteList EL = GetExitList();
				ex = EL.getByDomain(dom);
				EL=null;
				}
			
			if (ex==null) {
					ex = new ExitRouterInfo();
					ex.isLegacy=true;
					ex.canVMAT=true;
					ex.port=25;
					ex.onion = dom;
					ex.domain=dom;
					}
			
			SrvAction A = new SrvAction(this,ex.onion,"VMATLookup") {
				public void OnSession(BufferedReader RI,OutputStream RO) throws Exception {
					if (this.SupVMAT) {
							SMTPReply Re = SrvSMTPSession.RemoteCmd(RO,RI,"TORM VMAT LOOKUP "+mail);
							if (Re.Code<200 || Re.Code>299) this.RES = null; else this.RES =  Re.Msg;
							} else  this.RES = null;
					}
				};
				
			A.DoInSSL=true;
			A.ForceTKIM=false;
			A.DoInTKIM=false;
			
			try {
				A.Do();
				if (A.RES!=null) {
					String[] a = (String[]) A.RES;
					String rs = J.getMail(a[0],true);
					if (rs==null) Log("Bad VMAT Lookup on `"+A.Server+"`");
					VM = new VirtualRVMATEntry();
					VM.onionMail = rs;
					VM.mail=mail;
					VM.server = J.getDomain(rs);
					return VM;
					}
				} catch(Exception E) {
					Log("Can't Lookup via `"+A.Server+"` E: "+E.getMessage());
					}
			return null;
		}
		
		public boolean Tor2InetMsgCounter(String srv) {
			int h = srv.hashCode();
			int z = -1;
			int tcr = (int) ((Config.TimeSpoof+ System.currentTimeMillis())/3600000L);
			int cx = LimSrvMHour.length;
			
			if (cx>256) {
				int c0=0;
				for (int ax=0;ax<cx;ax++) {
					if (LimSrvMHash[ax]==0) c0++;
					if (c0>32) break;
					}
				if (c0>32) {
						if (Config.Debug) Log("Redim-- exit counters");
						redimCounter();
						}
				}
			
			for (int ax=0;ax<cx;ax++) {
				if (LimSrvMHour[ax]!=0 && tcr>LimSrvMHour[ax]) {
					LimSrvMHour[ax]=0;
					LimSrvMMsg[ax]=0;
					LimSrvMHash[ax]=0;
					}
				
				if (LimSrvMHash[ax]==h) { 
					if (LimSrvMHour[ax]==tcr) {
						LimSrvMMsg[ax]++;
						if (LimSrvMMsg[ax]>=MaxMsgXserverXHour) return false;
						}
					return true;
					}
			
				if (z==-1 && LimSrvMHash[ax]==0) z=ax;
				}
			
			if (z!=-1) {
				LimSrvMHour[z]=tcr;
				LimSrvMMsg[z]=1;
				LimSrvMHash[z]=h;
				return true;
				}
			
			if (Config.Debug) Log("Redim++ exit counters");
			int[] a = new int[cx+1];
			int[] b = new int[cx+1];
			int[] c = new int[cx+1];
			System.arraycopy(LimSrvMHour, 0, a, 0, cx);
			System.arraycopy(LimSrvMMsg, 0, b, 0, cx);
			System.arraycopy(LimSrvMHash, 0, c, 0, cx);
			a[cx]=tcr;
			b[cx]=1;
			c[cx]=h;
			LimSrvMHash=c;
			LimSrvMMsg=b;
			LimSrvMHour=a;
			return true;
			}  
		
		private synchronized void  redimCounter() {
			int cx = LimSrvMHour.length;
			int[] a = new int[cx];
			int[] b = new int[cx];
			int[] c = new int[cx];
			int dx=0;
			for (int ax=0;ax<cx;ax++) {
				if (LimSrvMHash[ax]!=0) {
					a[dx] = LimSrvMHour[ax];
					b[dx] = LimSrvMMsg[ax];
					c[dx] = LimSrvMHash[ax];
					dx++;
					}
				}
			if (dx==cx) return;
			int[] d = new int[dx];
			int[] e = new int[dx];
			int[] f = new int[dx];
			System.arraycopy(a, 0, d, 0, dx);
			System.arraycopy(b, 0, e, 0, dx);
			System.arraycopy(c, 0, f, 0, dx);
			LimSrvMHash=c;
			LimSrvMMsg=b;
			LimSrvMHour=a;
		}

public void setAutoConfig() {
		try {
			String fp = Maildir+"/config-v1.1.xml";
			if (new File(fp).exists()) return;
			
			InputStream I=  SrvIdentity.class.getResourceAsStream("/resources/config-v1.1.xml.src");
			BufferedReader S = J.getLineReader8(I);
			String buf="";
			while(true) {
							String li=S.readLine();
							if (li==null) break;
							buf+=li+"\r\n";
							}
			I.close();
			buf=buf.replace("%ONION%", Onion);
			buf=buf.replace("%NICK%", Nick);
			Stdio.file_put_bytes(fp, buf.getBytes("UTF-8"));
		} catch(Exception E) {
			Config.EXC(E, Nick+".setAutoConfig");
			if (Config.Debug) E.printStackTrace();
			}
	}
		
	public int PGPSendKey(String usr,String dfile) throws Exception {
		int rs=0;
		String dn;
		if (new File(dfile).exists()) dn = new String( Stdio.file_get_bytes(dfile) ); else dn=" ";
			
		String ls = PGPKeyServers;
		if (ls==null) ls=Config.PGPKeyServers; 
		if (ls==null) throw new PException("@550 No PGP keyservers!");
		String[] KS =Config.StringList(ls);
		int cx = KS.length;
		
		String hs = "@"+Long.toString(ls.hashCode(),36)+"@";
		String mhs=hs;
		
		if (dn.contains(" "+hs+" ")) return 0;
		
		for (int ax=0;ax<cx;ax++) {
			String li =KS[ax].toLowerCase().trim();
			hs = Long.toString(li.hashCode(),36);
			
			if (dn.contains(" "+hs+" ")) { 
					rs++; 
					continue;
					}
			
			if (li.length()==0) {
				rs++ ;
				continue;
				}
			
			li=li+":11371";
		
			String tok[] = li.split("\\:");
			int port = J.parseInt(tok[1]);
			li = tok[0].trim();
			if (port<1 || port>65535) continue;
			if (PGPSendKey(usr,li,port)) { 
					rs++;
					dn+=hs+" ";
					}
		}
		
	if (rs==cx) dn+=mhs+" ";
	Stdio.file_put_bytes(dfile, dn.getBytes());
	
	return rs;
	} 

	public boolean PGPSendKey(String usr,String server,int port) throws Exception {
		String y;
		usr=usr.toLowerCase().trim();
		if ("@sysop@server@".contains("@"+usr+"@")) y = usr+"@"+Onion; else y=Long.toString(usr.hashCode(),36);
		Log("Sending PGP public key `"+y+"` to `"+server+":"+port+"`");
		String PGP = UserGetPGPKey(usr);
		if (PGP==null) {
			Log("No PGP KEY available for `"+y+"`");
			return false;
			}
		
		PGP = PGPSpoofNSA(PGP,true);
		PGP = PGP.trim()+"\r\n";
		PGP="keytext=" + URLEncoder.encode(PGP, "ISO-8859-1");
		
		int cx = PGP.length();
		PGP="POST /pks/add HTTP/1.0\r\n"+
				"Host: "+server+ (port!=80 ? ":"+port : "")+"\r\n"+
				"Content-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: "+cx+"\r\n\r\n"+ PGP;
		
		Socket RS=null;
		OutputStream O=null;
		BufferedReader I=null;
		InputStream is =null;
		try {
			if (EnterRoute) {
				if (ExitIP!=null) RS = new Socket(server,port,ExitIP,0); else RS = new Socket(server,port);
				} else RS =  J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, server,port);
			RS.setSoTimeout(3000);
			O  = RS.getOutputStream();
			is = RS.getInputStream();
			I = J.getLineReader(is);
			O.write(PGP.getBytes());
			PGP=null;
			PGP = I.readLine();
			String[] tok = PGP.split("\\s+",3);
			if (tok.length<3) throw new PException("Inalid HTTP reply");
			int status = J.parseInt(tok[1]);
			if (status!=200) throw new PException("HTTP status: "+status+" "+tok[2]);
			HashMap <String,String> Hldr = J.ParseHeaders(I);
			boolean bit=true;
			if (Hldr.containsKey("x-hkp-results-count")) {
					String x =Hldr.get("x-hkp-results-count").trim();
					Log("HKP Results Count: "+x);
					if (J.parseInt(x)<1) bit=false;
					}
			int cl = 0;
			if (Hldr.containsKey("content-length")) cl = J.parseInt(Hldr.get("content-length"));
			if (cl>2048) cl=2048;
			byte[] bf = new byte[cl];
			is.read(bf);
			bf=null;
			try { O.close(); } catch(Exception Ig) {}
			try { I.close(); } catch(Exception Ig) {}
			try { is.close(); } catch(Exception Ig) {}
			try { RS.close(); } catch(Exception Ig) {}
			return bit;
			} catch(Exception E) {
			if (O!=null) try { O.close(); } catch(Exception Ig) {}
			if (I!=null) try { I.close(); } catch(Exception Ig) {}
			if (is!=null) try { is.close(); } catch(Exception Ig) {}
			if (RS!=null) try { RS.close(); } catch(Exception Ig) {}
			if (E instanceof PException) {
				Log("KeyServer: "+E.getMessage()+"\n");
				} else {
				Config.EXC(E, Nick+"."+"PGPSendKey");
				if (Config.Debug) E.printStackTrace();
				}
			return false;
			}
	}

public String ExpandStr(String in) {
	String rs=new String();
	int cx = in.length();
	for (int ax=0;ax<cx;ax++) {
		char c = in.charAt(ax);
		if (c=='%' && ax+1!=cx) {
			ax++;
			c=in.charAt(ax);
			
			if (c=='n') rs+=Nick;
			if (c=='o') rs+=Onion;
			if (c=='x' && EnterRoute) rs+=ExitRouteDomain;
			if (c=='m' && EnterRoute) rs+=MXDomain;
			if (c=='t') rs+=TimeString();
			if (c=='v' && !NoVersion) rs+=Main.getVersion();
			if (c=='T') rs+=EnterRoute ? "EXIT":"NORMAL";
			if (c=='E') rs+=EnterRoute ? "Exit":"";
			if (c=='s') rs=rs.trim();
			try {
				if (c=='h') rs+=LibSTLS.GetCertHash(MyCert); 
				} catch(Exception I) {}
			
			if (c=='%') rs+="%";
			} else {
			rs+=c;	
			}
		}
	return rs;
}

///// SSLVerify //////

public String SSLManualVerify(String host,boolean useTKIMv) throws Exception {
	
	SrvAction A = new SrvAction(this,host,"SSLMVerif") {
			public void OnSession(BufferedReader RI,OutputStream RO) throws Exception { 
					Mid.Log(Tag+": Server Ok, TKIM="+this.TKIMOk);
					
					RES[0] +="Session started:\n";
					RES[0] +="TKIM: "+ (this.SupTKIM ? "Supported" : "Unsupported") + ", "+(this.TKIMOk ? "Verified" : "Not Verified")+"\n";
					
			
					if (this.SupTLS && this.SSLSocketPointer!=null) try {
						Mid.CheckSSL(this.SSLSocketPointer, this.Server,this.Tag);
						Mid.Log(Tag+": Server Ok, SSL=Ok");
						RES[0]+="SSL: OK, Verified\n";
						} catch(Exception SE) {
							Mid.Log(Tag+": Server Error, SSL Error: "+SE.getMessage());
							RES[0]+="SSL: Error "+SE.getMessage()+"\n";
						} else RES[0]+="SSL Not enabled!\n";
					
					if (this.SupTLS && this.SSLSocketPointer!=null) try {
						SSLSession ha = this.SSLSocketPointer.getHandshakeSession();
						SSLSession s = this.SSLSocketPointer.getSession();
						if (ha!=null) {
							RES[0]+="SSL HandShake session info:\n"; 
							RES[0]+="SSL Chiper Suite: "+	ha.getCipherSuite()+"\n";
							RES[0]+="SSL Protocol: "+ha.getProtocol()+"\n";
							RES[0]+="SSL ID: "+Stdio.Dump(ha.getId())+"\n";
							RES[0]+="\n";
							}
							
						if (s!=null) {
							RES[0]+="SSL Session info:\n";
							RES[0]+="SSL Chiper Suite: "+	s.getCipherSuite()+"\n";
							RES[0]+="SSL Protocol: "+s.getProtocol()+"\n";
							RES[0]+="SSL ID: "+Stdio.Dump(s.getId())+"\n";
							RES[0]+="\n";
							}
						
						RES[0]+="SSL Certificates:\n";
						javax.security.cert.X509Certificate[] C = LibSTLS.getCert(this.SSLSocketPointer);
						int cx =C.length;
						for (int ax=0;ax<cx;ax++) RES[0]+="Certifiate "+(ax+1)+"\n"+C[ax].toString()+"\n\n";
						} catch(Exception E) {
							RES[0]+="Error: "+E.getMessage()+"\n";
							Config.EXC(E, "SSLVerify."+Mid.Nick);
							if (Config.Debug) E.printStackTrace();
						}
					
					SrvSMTPSession.RemoteCmd(RO,RI,"QUIT");
					}
			};
	
	A.acceptAllCrt=true;
	A.DoInSSL=true;
	A.DoInTKIM=true;
	A.ForceSSL=true;
	A.InternetConnection=false;
	A.ForceTKIM=false;
	A.TestTKIM=useTKIMv;
	A.RES = new String[] { "" };
	
	A.RES[0]+="Test server and SSL of `"+host+"` ";
	if (useTKIMv) A.RES[0]+=" using TKIM:\n"; else A.RES[0]+="without TKIM:\n"; 
	A.RES[0]+="\nBegin SMTP session test:\n\n";
	Log("Test server `"+host+"` TKIM="+useTKIMv);
	long tcr=System.currentTimeMillis();
	try {
		A.Do();
		A.RES[0]+="Operation complete!\n";
		} catch(Exception GE) {
			A.RES[0]+="Operation Error: "+GE.getMessage()+"\n";
			A.RES[0]+="Session position: ";
			if (A.ActionPosition==SrvAction.APOX_CONNECT) A.RES[0]+="Connecting";
			if (A.ActionPosition==SrvAction.APOX_END) A.RES[0]+="End of session";
			if (A.ActionPosition==SrvAction.APOX_HELLO) A.RES[0]+="Server EHLO";
			if (A.ActionPosition==SrvAction.APOX_INIT) A.RES[0]+="Initialize ServerAction";
			if (A.ActionPosition==SrvAction.APOX_SESSION) A.RES[0]+="SMTP Session in progress";
			if (A.ActionPosition==SrvAction.APOX_STARTTLS) A.RES[0]+="STARTTLS Handshake";
			if (A.ActionPosition==SrvAction.APOX_STARTTLS_HELLO) A.RES[0]+="EHLO after STARTTLS Handshake";
			if (A.ActionPosition==SrvAction.APOX_TKIM) A.RES[0]+="Server TKIM auth";
			A.RES[0]+="\n";
		}
	long ftr = System.currentTimeMillis();	
	tcr = ftr-tcr;
	A.RES[0]+="Time length of the transaction "+
				Long.toString((long)Math.floor(tcr/60000))+":"+
				Long.toString((long)Math.floor(tcr/1000) % 60)+"."+
				Long.toString(tcr % 1000)+"\n\n";
	return (String) A.RES[0];
	}

//////////// QUEUE/////////////

public MailQueueSender[] QueueSender= null;
public MailQueue Queue = null;
private ScheduledExecutorService QueueRun=null;
public boolean hasQueue = false;

public void EnableQueue() throws Exception {
	if (QueueRun!=null) return;
	Queue = new MailQueue(this);
	try { Queue.Load(); } catch(Exception E) { Config.EXC(E, Nick+".EnableQueueLoad"); }
	
	QueueSender = new MailQueueSender[Config.QueueThreads];
	final SrvIdentity Questo =this;
	
	Runnable ServerOp = new Runnable() {
				long scad=System.currentTimeMillis()+1000L;
				public void run() {
					try {
						int cx = QueueSender.length;
							for (int tx =0;tx<cx;tx++) {
							int nxt =-1;
							
							synchronized(Queue) { nxt = Queue.getNext(); }
							
							if (nxt==-1) return;
							Log("QueueRun "+nxt+" "+tx);
							
							long tcr=System.currentTimeMillis();
							int fre=-1;
							for (int ax=0;ax<cx;ax++) {
								if (QueueSender[ax]!=null && tcr>QueueSender[ax].Scad) {
									if (QueueSender[ax].running) try { QueueSender[ax].interrupt(); } catch(Exception I) {}
									QueueSender[ax]=null;
									fre=ax;
									}
								}
							System.gc();
							
							if (fre==-1) for (int ax=0;ax<cx;ax++) {
									if (QueueSender[ax]!=null && !QueueSender[ax].running) { fre=ax; break; }
									if (QueueSender[ax]==null) { fre=ax; break; }
									}
							
							if (fre==-1) {
								Log("No Queue threads free");
								return;
								}
							
							MsgQueueEntry Q = null;
							synchronized(Queue) { Q = Queue.UnQueue(nxt); }
							
							QueueSender[fre] = new MailQueueSender(Q,Questo);
							tcr=System.currentTimeMillis();
							if (tcr>scad) break;
							}
						Log("End Queue Run");
						} catch(Exception E) {
							Config.EXC(E, Nick+".QueueRun");
							if (Config.Debug) E.printStackTrace();
						}
					
					}
				} ;
				
	QueueRun=Executors.newSingleThreadScheduledExecutor();
	QueueRun.scheduleAtFixedRate(ServerOp,60,300, TimeUnit.SECONDS); 
	hasQueue=true;
	}

public HashMap <String,String> RulezList = null;

public void RefreshRulezList() throws Exception {
	if (RulezList==null) RulezList=new HashMap <String,String>();
	for(File dh: new File[] { new File(Config.RootPathConfig) , new File(Maildir),new File(Maildir+"/rulez") }) {
	String[] lst = dh.list();
	int cx =lst.length;
	for (int ax=0;ax<cx;ax++) {
		String s = lst[ax];
		
		if (
				s.startsWith("rulez") && (
						s.endsWith(".rul") 	|| 
						s.endsWith(".txt") )
						) {
				String[] Tok = s.split("\\-",2);
				String sec=null;
				if (Tok.length>1) sec=Tok[1].toLowerCase(); else sec="rulez."; 
				Tok = sec.split("\\.");
				sec=Tok[0].trim();
				RulezList.put(sec.toLowerCase(), "!");
			}
		}
	}

	for (String f:new String[] { Maildir+"/rulez/rulez.lst" ,  Config.RootPathConfig+"/rulez.list"  }) {
		if (!new File(f).exists()) continue;
		byte[] fi = Stdio.file_get_bytes(f);
		if (f.endsWith(".lst")) {
				fi = Stdio.AES2Dec(Subs[4], Subs[3], fi);
				byte[][] r = Stdio.MxDaccuShifter(fi,0x5aa5);
				fi=r[0];
				}
		String lst = new String(fi);
		fi=null;
		lst=lst.trim();
		String[] lin = lst.split("\\n+");
		int cx =lin.length;
		if (!lin[0].contains("[RULEZ]")) {
			Log("Invalid rulez file list `"+f+"`");
			continue;
			}
		for (int ax=1;ax<cx;ax++) {
			String[] tok = lin[ax].trim().split("\\s+",2);
			if (tok.length<2) continue;
			tok[0] = tok[0].toLowerCase();
			if (tok[0].matches("[a-z0-9\\-\\_]{1,40}") && RulezList.containsKey(tok[0])) {
					RulezList.put(tok[0], tok[1].trim());
					}
			}
		}
	}

public void SaveRulezList() throws Exception {
	String re="[RULEZ]\n";
	for (String k:RulezList.keySet()) {
		re=re+k.toLowerCase()+"\t"+RulezList.get(k)+"\n";
		}
	byte[] b= re.getBytes();
	b = Stdio.MxAccuShifter(new byte[][] { b} , 0x5aa5 ,true);
	b =Stdio.AES2Enc(Subs[4], Subs[3], b);
	Stdio.file_put_bytes(Maildir+"/rulez/rulez.lst", b);
	}

public String getRulezText(String per,String osection,HashMap <String,String> Hldr,boolean asNew) throws Exception {
				
		osection=osection.toLowerCase().trim();
		String section="";
		if (osection.matches("[a-z0-9]{1,40}")) section=osection;
		boolean isList = section.compareTo("list")==0;
		String list="";
		if (isList) {
			for (String k:RulezList.keySet()) {
				if (k.contains("-") || k.contains("_")) continue;
				list+=J.Spaced(k, 20)+J.Spaced(RulezList.get(k), 50)+"\n";
				}
			}

		if (section.length()>0) section="-"+section;
		String[] rul =new String[] {
					per!=null ? Maildir+"/rulez/"+per+section : null ,
							Maildir+"/rulez/rulez"+section+".txt",
							Maildir+"/rulez/rulez"+section+".rul",
							Maildir+"/rulez"+section+".txt",
							Maildir+"/rulez"+section+".rul",
							Config.RootPathConfig+"rulez"+section+".txt",
							Config.RootPathConfig+"rulez"+section+".rul"}
							;
				
		for(String tr: rul) {
					if (tr==null) continue;
					if (new File(tr).exists()) {
						boolean isr = tr.endsWith(".rul");
						
						FileInputStream r=null;
						BufferedReader l=null;
						MailBoxFile  ru=null;
						HashMap <String,String> H=null;
						if (isr) {
							ru = new MailBoxFile();
							ru.OpenAES(tr, Sale, false);
							String tmp="";
							while(true) {
								String li = ru.ReadLn();
								if (li==null || li.length()==0) break;
								tmp+=li+"\r\n";
								}
							
							l = J.getLineReader( new ByteArrayInputStream( tmp.getBytes()));
							H = J.ParseHeaders(l);
							H = J.FilterHeader(H);
							tmp=null;
							
							} else {
							r = new FileInputStream(tr);
							l = J.getLineReader(r);
							H = J.ParseHeaders(l);
							H = J.FilterHeader(H);
							}
						
						H.put("x-generated", "server cmd");
						H.put("from", "server@"+Onion);
						if (!H.containsKey("subject")) H.put("subject", Nick+" RULEZ "+section.toUpperCase()+" ("+Onion+")");
						H.put("date", TimeString());
						String msg="";
						while(true) {
							String s;
							try {
								if (isr) s= ru.ReadLn(); else s = l.readLine();
								} catch(EOFException EX) { break; }
							
							if (s==null) break;
							s=s.replace("\r", "");
							s=s.replace("\n", "");
							msg+=s+"\n";
							if (msg.length()>131072) break;
							}
						
						if (isr) ru.Close(); else {
							l.close();
							r.close();
							}
						
						if (msg.contains("%%")) {
							msg=msg.replace("%%ONION%%", Onion);
							msg=msg.replace("%%NICK%%", Nick);
							msg=msg.replace("%%EXIT%%", EnterRoute ? ExitRouteDomain : Onion );
							if (isList) msg=msg.replace("%%LIST%%", list);
							}
						if (msg.contains("\\%\\%")) msg=msg.replace("\\%\\%","%%");
						list=null;
						
						for (String k:H.keySet()) {
							String v = H.get(k);
							
							if (v.contains("%%")) {
								v=v.replace("%%ONION%%", Onion);
								v=v.replace("%%NICK%%", Nick);
								v=v.replace("%%EXIT%%", EnterRoute ? ExitRouteDomain : Onion );
								}
							Hldr.put(k, v);
							}
						
						Hldr.put("date", TimeString());
						Hldr.put("x-generated", "server cmd");
						if (asNew) {
							String t0 = Hldr.get("subject");
							if (t0==null) t0="";
							t0 = ("[RULEZ "+osection.toUpperCase()).trim()+"] "+t0;
							Hldr.put("subject", t0);
							Hldr.put("x-generated", "rulez news");
							}
						return msg;
					} 
			}
		
		Log(Config.GLOG_Event,"No rulez set in[] "+rul+" Section= `"+osection+"`");
		if (asNew) return null;
		
		Hldr.put("x-generated", "server cmd");
		Hldr.put("from", "server@"+Onion);
		Hldr.put("subject", Nick+" RULEZ "+section.toUpperCase()+" ("+Onion+")");
		Hldr.put("date", TimeString());
		return "NO RULEZ SET" + (osection.length()>0 ? " for `"+osection+"`" : "")+"\n";
		}

public void SA_RULEZ(String da,String per,String osection,boolean PGPSession,boolean asNew) throws Exception {
		
		HashMap <String,String> H = new HashMap <String,String>();
		String msg = getRulezText(per, osection, H,asNew);
		if (msg==null) return;
		H.put("to", da);
		if (asNew) H.put("reply-to", "sysop@"+Onion);
		
		if (PGPSession) msg=SrvPGPMessage(da,H,msg);	
		SendMessage(da, H, msg);
		msg=null;
		}

	public HashMap <String,String> GetNewsRulez() {
		try {
			byte[][] b = Stdio.SFileLoad(this, Const.RULEZNEWS, Const.FI_RULEZ, true);
			return J.HashMapUnPack(b[0]);
			} catch (Exception E) {
				return new HashMap <String,String>();
			}
		}
	
public void fileSave(String relName,byte[][] data, long magicNumber,String ext) throws Exception { //TODO new
	byte[] p0 = Stdio.sha256a(new byte[][] { relName.getBytes() , Sale , Long.toString(magicNumber,36).getBytes() } );
	int x = 15 & Subs[p0[0]&15][p0[1]&15];
	byte[] p1 = Stdio.sha256a(new byte[][] { relName.getBytes() , Sale, Subs[x], Long.toString(magicNumber,36).getBytes(),p0 } );
	byte[] iv = Stdio.md5a(new byte[][] { Subs[6] , p1 });
	
	byte[] d = Stdio.MxAccuShifter( data ,(int) (magicNumber  & 0xFFFFL) ,true);
	d = Stdio.AES2Enc(p0, iv, d);
	d = Stdio.AES2Enc(p1, iv, d);
	J.WipeRam(p0);
	J.WipeRam(p1);
	J.WipeRam(iv);
	byte[] nm = Stdio.md5a(new byte[][] { Subs[7] , relName.getBytes() , Sale , Long.toString(magicNumber,33).getBytes() } );
	String nom = Maildir+"/data/d"+Integer.toString(nm[0]&255,36);
	new File(nom).mkdirs();
	nom+="/" + J.md2st(nm)+"."+ext;
	Stdio.file_put_bytes(nom, d);
	System.gc();
	}
	
public byte[][] fileLoad(String relName, long magicNumber,String ext) throws Exception { //TODO new
	byte[] nm = Stdio.md5a(new byte[][] { Subs[7] , relName.getBytes() , Sale , Long.toString(magicNumber,33).getBytes() } );
	String nom = Maildir+"/data/d"+Integer.toString(nm[0]&255,36)+"/" + J.md2st(nm)+"."+ext;
	if (!new File(nom).exists()) return null;
	
	byte[] p0 = Stdio.sha256a(new byte[][] { relName.getBytes() , Sale , Long.toString(magicNumber,36).getBytes() } );
	int x = 15 & Subs[p0[0]&15][p0[1]&15];
	byte[] p1 = Stdio.sha256a(new byte[][] { relName.getBytes() , Sale, Subs[x], Long.toString(magicNumber,36).getBytes(),p0 } );
	byte[] iv = Stdio.md5a(new byte[][] { Subs[6] , p1 });
	
	byte[] d = Stdio.file_get_bytes(nom);
	d = Stdio.AES2Dec(p1, iv, d);
	d = Stdio.AES2Dec(p0, iv, d);
	J.WipeRam(p0);
	J.WipeRam(p1);
	J.WipeRam(iv);
	System.gc();
	return Stdio.MxDaccuShifter(d, (int) (magicNumber  & 0xFFFFL));
	}
	
 public void fileDelete(String relName, long magicNumber,String ext) throws Exception { //TODO new
	byte[] nm = Stdio.md5a(new byte[][] { Subs[7] , relName.getBytes() , Sale , Long.toString(magicNumber,33).getBytes() } );
	String nom = Maildir+"/data/d"+Integer.toString(nm[0]&255,36)+"/" + J.md2st(nm)+"."+ext;
	if (new File(nom).exists()) J.Wipe(nom, Config.MailWipeFast);
 	}

 ////////////////
 public String SA_FriendErrList() throws Exception {
	 	byte[][] ef =  fileLoad(Const.FIL_BAD_SRV, Const.ONM_CORE, Const.ONM);
		if (ef==null) return null;
				
		String st="";
				HashMap <String,String> badSrvNum = J.HashMapUnPack(ef[0]);
				HashMap <String,String> badSrvLast = J.HashMapUnPack(ef[1]);
				int cur = (int)(System.currentTimeMillis()/1000);
				for ( String k:badSrvNum.keySet()) {
					int x = cur - J.parseInt(badSrvLast.get(k));
					x=x/86400;
					st+=k+"\t"+J.Spaced(badSrvNum.get(k),4)+"\t";
					st+=J.Spaced(Integer.toString(x)+"D",5);
					if (x>Config.removeFriendAfterErrors) st+='H';  else st+='D';
					st+="\n";
					}
				
				return st;
 	}
 /*
 public void AlphaDebugCrt(javax.security.cert.X509Certificate[] C,String host) {
	try {
			long a = System.currentTimeMillis();
			String bna = Maildir+"/local/";
			File xa = new File(bna);
			if (!xa.exists()) {
					xa.mkdirs();
					xa.mkdir();
					}
			bna+= Long.toString(a,36)+"_"+host+"_";
			for (int i  = 0 ; i<C.length;i++) {
				Stdio.file_put_bytes(bna+Integer.toString(i)+".ctxc",C[i].getEncoded());
			}
		} catch(Exception ex) { ex.printStackTrace(); }
	 
 }*/
 
 public void SA_FriendErrDel() throws Exception { fileDelete(Const.FIL_BAD_SRV, Const.ONM_CORE, Const.ONM); }

protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
