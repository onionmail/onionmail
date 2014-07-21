/*
 * Copyright (C) 2013-2014 by Tramaci.Org
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
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.openpgp.PGPEncryptedData;

	public class Config {
		public int TextCaptchaMode = TextCaptcha.MODE_NOISE | TextCaptcha.MODE_SWY | TextCaptcha.MODE_SYM | TextCaptcha.MODE_INV;
		public String TextCaptchaFile = null;
		public int TextCaptchaSize=5;
		
		public int MaxHTTPSession = 10; 
		public long MaxHTTPReq=12000;
		public long MaxHTTPRes=15000;
		public int HTTPKeepAlive=5; //Seconds.
		public int HTTPPipelining=4; //requests max
		public int HTTPMaxBuffer=8192; //bytes 
		
		public String HTTPServerName="OnionMail";
		public String HTTPLogFile=null;
		public HashMap <String,Boolean> HTTPCached = new HashMap <String,Boolean>();
		public HashMap <String,String> MIMETypes = new HashMap <String,String>();
		public HashMap <String,String> HTTPETEXVar = new HashMap <String,String>();
		public String HTTPBasePath=null;
		
		public boolean UseStatus=true;//TODO Config
		public boolean UseKernel=true;
		public boolean	ExitCheckViaTor = false;						
		public int GarbageFreq = 2000;									//Frequenza di Garbage collector per le Onion e le connessioni inattive.
				
		public InetAddress DNSServer = null; 							//IP Server DNS
		public int DNSSoTimeout = 1000;									//Timeout richieste DNS al server
		public boolean DNSEnableMX = true;						//Abilita le onion MX (mail)
		public boolean DNSAddAMX = true;							//Forza A record in risporte MX
		public boolean DNSInAddr = true;								//Risponde a in-adds.arpa. per gli indirizzi locali.
				
		public int OnionTTL = 60000;										//TTL Per una onion
		public int MaxConnectionXPort = 10;							//Max. Connessioni per porta per onion
		public int MaxConnectionIdle=600000;						//TTL Per un proxy onion su una porta intattivo
		public int MaxHosts = 320;											//Max. num di onion contemporanee
		
		public NetArea LocalNetArea=null;								//Network loncale di assegnamento ip 127.0.0.0
		public InetAddress LocalNet = null;								//Indirizzo ip (rete) locale tipicamente 127.0.0.0
		public int LocalFisrtIp = 2;											//Numero del primo IP da assegnare 2 = 127.0.0.2
		public int LocalIPReleaseTime=5;									//Tempo di rilascio IP non utilizzati. (Secondi)
		
		public InetAddress TorIP = null;									//Indirizzo IP di tor 127.0.0.1
		public int TorPort= 9150;												//Porta SOCKS4A ti tor 9050
	
		public InetAddress[] NoIP = null;									//Lista IP da non usare in LocalNet
		public int[] NoPort = null;											//Lista di porte da non usare per le onion.
		
		public NetArea NetAllow = null;									//Rete in cui è consentito operare
		public InetAddress[] NetAllowIp = null;						//Ip che possono operare
		public InetAddress[] NetNoAllowIp = null;					//Ip che non possono operare
		public boolean NetDisallowAll=false;							//Disattiva tutto eccetto ciò che può

		public boolean DNSLogQuery = true;						//Logga query DNS
		
		public String IANAPortFile = null;
		public Map<String,Integer> PortName = new HashMap<>();
		public boolean UsePortName=false;
		
		public String LogFile = null;
		public String PidFile = null;
		
		public int DefaultPort = 80;											//Default port.
		public static boolean Debug = false;									//Debug log
		public boolean LogStdout = false;								//Copia log in stdout
	
		public int MaxSMTPSession = 10;
		public int MaxSMTPSessionTTL = 600000;
		public int MaxSMTPSessionInitTTL = 10000;
					
		public SrvIdentity[] SMPTServer= new SrvIdentity[0];
		
		public long TimeSpoof=0;
		public String TimeSpoofFus = "+0000";
		
		public int DNSCheckTimeout = 5000;
		public int DNSCheckRetry = 1;
		
		public boolean EnableDNSBL = true;
		public int DNSBLCacheSize = 100;
		public int DNSBLCacheTTL = 100; //"
		public boolean DNSBLUseCache =true;
		public boolean DNSBLForceMainDNSServer = false;
		
		public boolean MindlessCompilant = false;
		
		public NetArea DNSBLNoCheck = null;
		
		public HashMap <String,Integer> IPSpec = new HashMap<String, Integer>();
		public String ReservedUserName="";
		public static final int IPS_NoDNSBL = 1;
		public static final int IPS_SPAM = 2;
		
		public boolean SMTPEnterRoute = false;
		public boolean SMTPVerifySender = true;	
		
		public boolean MailWipeFast = true;
		public int MailRetentionDays = 30;
			
		public int PasswordSize = 24;
		public int PasswordMaxStrangerChars=4;
				
		public int MaxUsrBlackListEntry=16;
		
	//	public String ServerBlackList = "server.bl"; //T\ODO dddd
	//	public byte[] BlackSale=new byte[16];			//T\ODO sale
		
		public PublicKey SK = null;
		public boolean BlackFlg = false;
	
		public int ControlPort = 9100;
		public InetAddress ControlIP = null; //InetAddress.getByAddress(new byte[] { 127,0,0,1 });
		public int MaxTTLControlSession=86400;
		public int MaxControlSessions=2;
			
		public int TorDNSBLCacheSize= 200;
		public int TorDNSBLCacheTTL = 600;
		
		public int ListThreadsMax=5;  
		public long ListThreadsTTL = 600000L;
		public long MessagesGarbageEvery=600000L;
		
		public String RootPathConfig=null;
		public String RootPass=J.GenPassword(80, 80);
		
		public int MaxTrustDbEntry = 1024;
		
		public String ResPath=null; 
	
		public HashMap <String,String> SSLCtrl = new HashMap<String, String>();

		
		public int SMTPPreHelloWait=500;
		public String[] FriendServer= new String[0];
		
		public String DefaultLang="en-en";
				
		public String[] SPAMSrvCheck = new String[] {};
				
		public int MaxDoFriendOld=60; //TODO in config minuti Par/Conf 
		public boolean SSLJavaHasBug = false; 
		
		public boolean UseBootSequence = true;
		
		public int MinBootDerks = 1;
		public int PGPEncryptedDataAlgo = 0;
		public String PGPEncryptedDataAlgoStr="DEFAULT";
		public String[] PGPSpoofVer = null;
		public String PGPRootUserPKeyFile = null;
		public boolean PGPStrictKeys = false;
		public int AESKeyRoundExtra = 0;
		public String PGPKeyServers=null;
			
		public boolean VerfySenderViaSimulation=true;
		public boolean NoBootFromSameMachine=false;
		public boolean AutoDeleteReadedMessages=true;
		
		public RSALog RLOG = null;
		
		private HashMap<String,Integer> VMATErrorPolicy = new  HashMap<String,Integer>();
		
		public static void echo(String st) { System.out.print(st); }
		
		public static int parseInt(String st,String name) throws Exception {
			int p =-1;
			try { p = Integer.parseInt(st); } catch(Exception E) {}
			if (p<1 || p>65535) throw new Exception("Invalid "+name+" `"+st+"`");
			return p;
		}
		
		public static int parseInt(String st,String name,int min,int max) throws Exception {
			int p =min-1;
			try { p = Integer.parseInt(st); } catch(Exception E) {}
			if (p<min || p>max) throw new Exception("Invalid "+name+" `"+st+"` (must be between "+min+" "+max+")");
			return p;
		}
		
		public static int parseInt(String st,String name,int max) throws Exception {
			int p =-1;
			try { p = Integer.parseInt(st); } catch(Exception E) {}
			if (p<1 || p>max) throw new Exception("Invalid "+name+" `"+st+"`");
			return p;
		}
		
		public static int parseInt(String st) throws Exception {
			int p =-1;
			try { p = Integer.parseInt(st); } catch(Exception E) {}
			if (p<1 || p>65535) throw new Exception("Invalid value `"+st+"`");
			return p;
		}
		
		public static int parseIntS(String si) throws Exception {
			int p =-1;
			int cx=si.length();
			String st="";
			for (int ax=0;ax<cx;ax++) {
				int c = si.codePointAt(ax);
				if (c>47 && c<58) st+=si.charAt(ax);
				}
			try { p = Integer.parseInt(st); } catch(Exception E) {}
			if (p<1 || p>65535) return 0;
			return p;
		}
		
		private static int ParseExitList(Config C,BufferedReader br, int line,HashMap <String,Integer> P) throws Exception {
			String li = null;
					while((li=br.readLine())!=null) {
						line++;
						li = li.trim();
						if (li.length()==0) continue;
						if (li.charAt(0) =='#') continue;
						String[] tok = li.split("\\#",2);

						li = tok[0];
						li = li.trim();
						if (li.length()==0) continue;
						tok = li.split("\\s+",2);
						if (li.compareTo("}")==0) return line;
						
						if (tok[0].compareTo("clear")==0 && tok.length==1) {
							P =new HashMap <String,Integer>();
							continue;
							}
						
						if (tok.length!=2) throw new Exception("Parameter required in line "+line);
						tok[1]=tok[1].toLowerCase().trim();
						
						String dom;
						String lp;
						boolean lo = false;
						if (tok[0].contains("@")) {
							String a = J.getMail(tok[0], false);
							if (a==null) throw new Exception("Invalid Mail address `"+tok[0]+"`");
							lp = J.getLocalPart(a);
							dom = J.getDomain(a);
							if (dom.endsWith(".onion")) throw new Exception("Can't assign policy to OnionMail");
							} else {
							dom=tok[0];
							if (dom.endsWith(".onion")) throw new Exception("Can't assign policy to Hiden service");
							lp="*";
							lo=true;
							}
												
						if (tok[1].compareTo("clear")==0) {
							for (String k:P.keySet()) {
								String[] a = k.split("\\@");
								if (a[1].compareTo(dom)==0 && (lo || a[0].compareTo(lp)==0)) P.remove(k);
								}							
							}
						
						dom=lp+"@"+dom;
						lp=null;
						boolean k=false;
						int st=0;
																		
						if (tok[1].contains("i")) { st = SrvIdentity.EXP_NoEntry; k=true; }
						if (tok[1].contains("o")) { st |= SrvIdentity.EXP_NoExit; k=true; }
						if (tok[1].contains("k")) {
									k=true;
									if (st!=0) throw new Exception("Can't enable all and block!");
									}

						if (!k) throw new Exception("Invalid policy flags `"+tok[1]+"`");
						P.put(dom, st);
						
					}
				throw new Exception("Incomplete exit policy list");
		}
		
		private static Object[] ParseLines(Config C,BufferedReader br, int line,String exc) throws Exception {
			String li = null;
			String ret="";
					while((li=br.readLine())!=null) {
						line++;
						li = li.trim();
						if (li.length()==0) continue;
						if (li.charAt(0) =='#') continue;
						String[] tok = li.split("\\#",2);

						li = tok[0];
						li = li.trim();
						if (li.length()==0) continue;
						if (li.compareTo("}")==0) {
								ret=ret.trim();
								return new Object[] { line , ret.split("\\n+") };
								}
						ret+=li+"\n";
						}
						throw new Exception(exc);
		}
		
		
		private static HashMap <String,Integer> copypol(HashMap <String,Integer>P) {
			HashMap <String,Integer> q=new HashMap <String,Integer>();
			for(String k:P.keySet()) q.put(k, P.get(k));
			return q;
		}
		
		private static int ParseSMTP(Config C,BufferedReader br,String nick,int line,HashMap <String,Integer> SP,String CPath ) throws Exception {
			int ne = C.SMPTServer.length;
			SrvIdentity[] ST0= new SrvIdentity[ne+1];
			System.arraycopy(C.SMPTServer,0, ST0, 0, ne);
			if (!nick.matches("[a-z0-9\\-\\.\\_]{3,40}")) throw new Exception("Invalid server NickName `"+nick+"`");
			
			C.SMPTServer=ST0;
			C.SMPTServer[ne] = new SrvIdentity(C);
			C.SMPTServer[ne].Nick=nick;
			C.SMPTServer[ne].EnabledVMAT="\n";
			C.SMPTServer[ne].DisabledVMAT="\n";
			C.SMPTServer[ne].AutoDeleteReadedMessages = C.AutoDeleteReadedMessages;
			C.SMPTServer[ne].HTTPBasePath  = C.HTTPBasePath;
			for (String k:C.HTTPCached.keySet()) C.SMPTServer[ne].HTTPCached.put(k, C.HTTPCached.get(k));
			for (String k:C.HTTPETEXVar.keySet()) C.SMPTServer[ne].HTTPETEXVar.put(k, C.HTTPETEXVar.get(k));
			
			for (String k:C.VMATErrorPolicy.keySet()) C.SMPTServer[ne].VMATErrorPolicy.put(k, C.VMATErrorPolicy.get(k));
			
			HashMap <String,Integer> P = Config.copypol(SP);
			
			String li = null;
			boolean onioned=false;
					while((li=br.readLine())!=null) {
						line++;
						li = li.trim();
						if (li.length()==0) continue;
						if (li.charAt(0) =='#') continue;
						String[] tok = li.split("\\#",2);

						li = tok[0];
						li = li.trim();
						if (li.length()==0) continue;
						tok = li.split("\\s+",2);
						String cmd = tok[0].toLowerCase();
						if (li.compareTo("}")==0) break;
						
						if (tok.length!=2) throw new Exception("Parameter required in line "+line); 
											
						
						if (cmd.compareTo("onion")==0) {
							String t0 = tok[1].toLowerCase();
							if (!t0.matches("[a-z0-9]{16}\\.onion")) throw new Exception("Invalid onion address `"+t0+"` in server. Edit configuration files!");
							for (int ax=0;ax<ne;ax++) if (C.SMPTServer[ax].Onion.compareTo(t0)==0) throw new Exception("SMTP Server onion `"+t0+"` conflict between `"+C.SMPTServer[ax].Nick+"` and `"+nick+"`");
							C.SMPTServer[ne].Onion = t0;
							onioned=true;
							continue;
							}
						
						if (cmd.compareTo("passwd")==0) {
							C.SMPTServer[ne].PassWd = tok[1].trim();
							continue;
							
						}
						
						if (cmd.compareTo("identtextfile")==0) {
							C.SMPTServer[ne].IdentText = J.MapPath(CPath, tok[1]);
							if (!new File(C.SMPTServer[ne].IdentText).exists()) throw new Exception("IdentTextFile not found `"+C.SMPTServer[ne].IdentText+"`");
							continue;
						}
						
						if (cmd.compareTo("logvoucherto")==0) {
							C.SMPTServer[ne].LogVoucherTo = J.MapPath(CPath, tok[1]);
							continue;
						}
						
						if (cmd.compareTo("manifest")==0) {
							String[] TOK = tok[1].split("\\s+",2);
							if (TOK.length!=2) throw new Exception("Invalid Manifest parameter");
							TOK[0]=TOK[0].toLowerCase();
							if (TOK[0].matches("}[a-z0-9\\-\\_]+")) throw new Exception("Invalid manifest parameter name `"+TOK[0]+"`");
							if (TOK[1].length()==0) throw new Exception("Manifest parameter can't be empty");
							if (C.SMPTServer[ne].ManifestInfo.containsKey(TOK[0])) throw new Exception("Manifest parameter `"+TOK[0]+"` arleady defined");
							C.SMPTServer[ne].ManifestInfo.put(TOK[0], TOK[1]);
							continue;
							}
						
						if (cmd.compareTo("manifestweb")==0) {
							if (!onioned) throw new Exception("Cant put this parameter here!");
							C.SMPTServer[ne].ManifestInfo.put("httpsubs",C.SMPTServer[ne].Onion);
							String x = tok[1].trim().toLowerCase();
							C.SMPTServer[ne].ManifestInfo.put("rqus","true");
							if (x.contains("voucher")) C.SMPTServer[ne].ManifestInfo.put("subsmode","voucher"); 
								else if (x.contains("public")) C.SMPTServer[ne].ManifestInfo.put("httpmode","public"); else throw new Exception("Invalid ManifestWeb mode");
							continue;
							}
						
						
						if (cmd.compareTo("exitroutedomain")==0) {  
										if (!tok[1].matches("[a-zA-Z0-9\\.\\-]{2,40}\\.[a-zA-Z0-9]{2,6}")) throw new Exception("Invalid domain `"+tok[1]+"`");
										C.SMPTServer[ne].ExitRouteDomain = tok[1].toLowerCase().trim();
										continue;
										}
						
						if (cmd.compareTo("mxdomain")==0) {  
										if (!tok[1].matches("[a-zA-Z0-9\\.\\-]{2,40}\\.[a-zA-Z0-9]{2,6}")) throw new Exception("Invalid domain `"+tok[1]+"`");
										C.SMPTServer[ne].MXDomain = tok[1].toLowerCase().trim();
										continue;
										}
						
						if (cmd.compareTo("newusrenabled ")==0) { 
										C.SMPTServer[ne].NewUsrEnabled  = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("httpport")==0) { 
										C.SMPTServer[ne].LocalHTTPPort  = Config.parseInt(tok[1], "port", 1,65535);
										continue;
										}
						
						if (cmd.compareTo("hashttp")==0) { 
										C.SMPTServer[ne].HasHTTP  = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("httpservername")==0) { 
										C.SMPTServer[ne].HTTPServerName  =tok[1];
										continue;
										}
						
						if (cmd.compareTo("httpcache")==0) {
										C.SMPTServer[ne].HTTPCached.put(tok[1], true);
										continue;
										}
						
						if (cmd.compareTo("httpncache")==0) {
										C.SMPTServer[ne].HTTPCached.put(tok[1], false);
										continue;
										}
						
						if (cmd.compareTo("etexvar")==0) {
										String tk[] = tok[1].split("\\s+",2);
										if (tk.length!=2) throw new Exception("Invalid use of ETEXVar");
										C.SMPTServer[ne].HTTPETEXVar.put(tk[0], tk[1]);
										continue;
										}
												
						if (cmd.compareTo("httpaccess")==0) {
										String st = tok[1].toLowerCase().trim();
										String tk[] = st.split("\\s+");
										if (tk.length<2) throw new Exception("Invalid HTTPAccess");
										tk[0]=tk[0].toLowerCase();
										int x = 0;
										if (tk[0].contains("k")) x=HTTPServer.ACCESS_OK;
										if (tk[0].contains("l")) x|=HTTPServer.ACCESS_LIST;
										if (tk[0].contains("u")) x|=HTTPServer.ACCESS_USER;
										if (tk[0].contains("r")) x|=HTTPServer.ACCESS_ROOT;
										if (tk[0].contains("d")) x=HTTPServer.ACCESS_DENIED;
										C.SMPTServer[ne].HTTPAccess.put(tok[1], x);
										continue;
										}
						
						if (cmd.compareTo("httplogfile")==0) { 
										C.SMPTServer[ne].HTTPLogFile  =J.MapPath(CPath, tok[1]);
										File Ft = new File(C.SMPTServer[ne].HTTPLogFile);
										if (Ft.isDirectory()) throw new Exception("Not a file `"+C.SMPTServer[ne].HTTPLogFile+"`");
										continue;
										}
						
						if (cmd.compareTo("httpbasepath")==0) { 
										C.SMPTServer[ne].HTTPBasePath  =J.MapPath(CPath, tok[1]);
										File Ft = new File(C.SMPTServer[ne].HTTPBasePath);
										if (!Ft.exists()) throw new Exception("Path not found `"+C.SMPTServer[ne].HTTPBasePath+"`");
										if (!Ft.isDirectory()) throw new Exception("Not a directory `"+C.SMPTServer[ne].HTTPBasePath+"`");
										continue;
										}
						
						if (cmd.compareTo("newusrxday")==0) { 
										String str[] = tok[1].split("\\s+");
										int xd = Config.parseInt(str[0], "users", 0, 65535);
										int xh = xd;
										if (str.length==2) xh = Config.parseInt(str[1], "users", 0, xd);
										C.SMPTServer[ne].NewUsrMaxXDay  = xd;
										C.SMPTServer[ne].NewUsrMaxXHour  = xh;
										if (xh!=0 || xd!=0) C.SMPTServer[ne].NewUsrEnabled=true;
										continue;
										}					
																	
						if (cmd.compareTo("newlstenabled ")==0) { 
										C.SMPTServer[ne].NewLstEnabled  = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("autopgpkeys")==0) { 
										C.SMPTServer[ne].AutoPGP  = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("autopgpupdate")==0) { 
										C.SMPTServer[ne].AutoPGPUpdate  = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("autopgpid")==0) { 
										if (tok[1].compareToIgnoreCase("NULL")==0) C.SMPTServer[ne].AutoPGPID = null; else C.SMPTServer[ne].AutoPGPID  = tok[1];
										continue;
										}
									
																	
						if (cmd.compareTo("noversion")==0) { 
										C.SMPTServer[ne].NoVersion  = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("publicip")==0 || cmd.compareTo("exitip")==0) {
										C.SMPTServer[ne].ExitIP = Config.ParseIp(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("newlstxday")==0) { 
										String str[] = tok[1].split("\\s+");
										int xd = Config.parseInt(str[0], "lists", 0, 65535);
										int xh = xd;
										if (str.length==2) xh = Config.parseInt(str[1], "lists", 0, xd);
										C.SMPTServer[ne].NewLstMaxXDay  = xd;
										C.SMPTServer[ne].NewLstMaxXHour  = xh;
										if (xh!=0 || xd!=0) C.SMPTServer[ne].NewLstEnabled=true;
										continue;
										}		
												
						if (cmd.compareTo("maxmsgxuserxhour")==0) {
							if (tok[1].toLowerCase().contains("no")) C.SMPTServer[ne].MaxMsgXUserXHour=0; else C.SMPTServer[ne].MaxMsgXUserXHour=Config.parseInt(tok[1], "messages", 1,65535);
							continue;
							}
						
						if (cmd.compareTo("maxmsgexitxhour")==0) {
							if (tok[1].toLowerCase().contains("no")) C.SMPTServer[ne].MaxMsgXserverXHour=0; else C.SMPTServer[ne].MaxMsgXserverXHour=Config.parseInt(tok[1], "messages", 1,65535);
							continue;
							}
						
						
						if (cmd.compareTo("rmxcache")==0) { 
										String str[] = tok[1].split("\\s+");
										int rmxSz  = Config.parseInt(str[0], "servers", 0,65535);
										int rmxTl = 10;
										if (str.length>1) rmxTl =  Config.parseInt(str[0], "minutes", 1,1440);
										C.SMPTServer[ne].setRMXCache(rmxSz, rmxTl);
										continue;
										}	
						
						if (cmd.compareTo("multidelivermaxrcptto")==0) { 
										C.SMPTServer[ne].MultiDeliverMaxRCPTTo = Config.parseInt(tok[1], "addresses", 2, 128);
										continue;
										}
												
						if (cmd.compareTo("exitaltport ")==0) { 
										C.SMPTServer[ne].ExitAltPort  = Config.parseInt(tok[1], "port", 1, 65535);
										continue;
										}
						
						if (cmd.compareTo("exitmultipleserverdelivery")==0) { 
										C.SMPTServer[ne].ExitNotMultipleServerDelivery  = true ^ Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("statfile")==0) { 
										C.SMPTServer[ne].StatFile = J.MapPath(CPath, tok[1]);
										continue;
										}
						
						if (cmd.compareTo("binstatfile")==0) { 
										C.SMPTServer[ne].binaryStatsFile = J.MapPath(CPath, tok[1]);
										continue;
										}
																		
						if (cmd.compareTo("onlyonion")==0) { 
										C.SMPTServer[ne].OnlyOnion = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("maxserverderkpoint")==0) { 
										C.SMPTServer[ne].MaxServerDERKPoint = Config.parseInt(tok[1], "Credit", 1, 255);
										continue;
										}
												
						if (cmd.compareTo("onlyonionfrom")==0) { 
										C.SMPTServer[ne].OnlyOnionFrom = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("autodeletereaded")==0) { 
										C.SMPTServer[ne].AutoDeleteReadedMessages = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("application")==0) {
										Application a = Config.parseApplicationFile( J.MapPath(CPath, tok[1]));
										if (C.SMPTServer[ne].Applications==null) C.SMPTServer[ne].Applications=new HashMap <String,Application>();
										if (C.SMPTServer[ne].Applications.containsKey(a.localPart)) throw new Exception("Application `"+a.localPart+"` arleady loaded");
										C.SMPTServer[ne].Applications.put(a.localPart, a);
										continue;
										}
						
						if (cmd.compareTo("pgpkeyserver")==0) {
							if (tok[1].compareToIgnoreCase("$global")==0) 
									C.SMPTServer[ne].PGPKeyServers = C.PGPKeyServers; 
								else 
									C.SMPTServer[ne].PGPKeyServers = Config.AddToStringList(C.SMPTServer[ne].PGPKeyServers, tok[1].trim()); 
							continue;
							}		
						
						if (cmd.compareTo("onlyonionto")==0) { 
										C.SMPTServer[ne].OnlyOnionTo = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("exitpolicy")==0) {
									line=Config.ParseExitList(C,br,line,P);
									continue;
									}
						
						if (cmd.compareTo("canpop3register")==0) { 
										C.SMPTServer[ne].POP3CanRegister = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("canpop3vmat")==0) { 
										C.SMPTServer[ne].POP3CanVMAT = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("vmatallow")==0) {
									Object[] o = Config.ParseLines(C,br,line,"Incomplete VMATAllow section");
									line=(int) o[0];
									String[] t0 = (String[]) o[1];
									for (int ax=0;ax<t0.length;ax++) {
											t0[ax]=t0[ax].toLowerCase();
											t0[ax]=t0[ax].trim();
											if (t0[ax].compareTo("*")==0) {
													C.SMPTServer[ne].EnabledVMAT+="\n*\n";
												} else if (!t0[ax].matches("[0-9a-z\\.\\-\\_]{5,25}")) throw new Exception("Syntax error in VMATAllow: "+(ax+1)+"`"+t0[ax]+"`"); 
													C.SMPTServer[ne].EnabledVMAT+=t0[ax]+"\n";
												}
									continue;
									}
						
						if (cmd.compareTo("vmatdeny")==0) {
									Object[] o = Config.ParseLines(C,br,line,"Incomplete VMATDeny section");
									line=(int) o[0];
									String[] t0 = (String[]) o[1];
									for (int ax=0;ax<t0.length;ax++) {
											t0[ax]=t0[ax].toLowerCase();
											t0[ax]=t0[ax].trim();
											if (t0[ax].compareTo("*")==0) {
													C.SMPTServer[ne].DisabledVMAT+="\n*\n";
												} else if (!t0[ax].matches("[0-9a-z\\.\\-\\_]{5,25}")) throw new Exception("Syntax error in VMATDeny: "+(ax+1)); 
													C.SMPTServer[ne].DisabledVMAT+=t0[ax]+"\n";
												}
									continue;
									}
						
						if (cmd.compareTo("exitbad")==0) {
							if (C.SMPTServer[ne].ExitBad!=null) throw new Exception("Too many ExitBad sequence");
							Object[] o = Config.ParseLines(C,br,line,"Incomplete ExitBad section");
							line=(int) o[0];
							String[] t0 = (String[]) o[1];
							String r0=",";
							int cx=t0.length;
							for (int ax=0;ax<cx;ax++) {
								String a = t0[ax].toLowerCase().trim();
								if (a.length()==0) continue;
								if (!a.matches("[a-z0-9\\.\\-\\_]{4,80}")) throw new Exception("R6082 Invalid domain `"+a+"`");
								a=a+",";
								if (!r0.contains(","+a)) r0+=a;
								}
							C.SMPTServer[ne].ExitBad=r0;
							continue;
							}
						
						if (cmd.compareTo("exitgood")==0) {
							if (C.SMPTServer[ne].ExitGood!=null) throw new Exception("Too many exitgood sequence");
							Object[] o = Config.ParseLines(C,br,line,"Incomplete exitgood section");
							line=(int) o[0];
							String[] t0 = (String[]) o[1];
							String r0=",";
							int cx=t0.length;
							for (int ax=0;ax<cx;ax++) {
								String a = t0[ax].toLowerCase().trim();
								if (a.length()==0) continue;
								if (!a.matches("[a-z0-9\\.\\-\\_]{4,80}")) throw new Exception("R6081 Invalid domain `"+a+"`");
								a=a+",";
								if (!r0.contains(","+a)) r0+=a;
								}
							C.SMPTServer[ne].ExitGood=r0;
							continue;
							}
						
						if (cmd.compareTo("exitnotice")==0) { 
										tok[1]=tok[1].trim();
										if (tok[1].compareToIgnoreCase("DISABLED")==0) {
											C.SMPTServer[ne].ExitNotice=null;
											C.SMPTServer[ne].ExitNoticeE=false;
											continue;
											} else if (tok[1].compareToIgnoreCase("DEFAULT")==0) {
											C.SMPTServer[ne].ExitNotice=null;
											C.SMPTServer[ne].ExitNoticeE=true;	
											continue;	
											} 
										C.SMPTServer[ne].ExitNotice=tok[1];
										C.SMPTServer[ne].ExitNoticeE=true;
										if (!C.SMPTServer[ne].ExitNotice.contains("${SERVER}") && C.SMPTServer[ne].ExitNotice.toLowerCase().contains("<mailto:")) Main.echo("Warning:\n\tExitNotice not contasins `${SERVER}`\n");
										continue;
										}
						
						if (cmd.compareTo("enterroute")==0 || cmd.compareTo("exitroute")==0) { 
										C.SMPTServer[ne].EnterRoute = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("canrelay")==0) { 
										C.SMPTServer[ne].CanRelay = Config.parseY(tok[1]);
										continue;
										}
						
						if (cmd.compareTo("vmaterr")==0 && tok.length>1) {
							String[] tk = tok[1].split("\\s+");
							if (tk.length<2) throw new Exception("Syntax error");
							tk[0]=tk[0].toUpperCase();
							tk[1]=tk[1].toUpperCase();
							if (!" HIDE STAR SHOW ".contains(" "+tk[1]+" ")) throw new Exception("Invalid value `"+tk[1]+"`");
							if (!" SRV_ERR1 N_VMAT FALSE_VMAT FALSE_SENDER1 FALSE_SENDER2 NOT_VER * ".contains(" "+tk[0]+" ")) throw new Exception("Invalid vmat value `"+tk[0]+"`");
							int bits = 3;
							if (tk[1].contains("HIDE")) bits=0;
							if (tk[1].contains("STAR")) bits=1;
							if (tk[1].contains("SHOW")) bits=2;
							C.SMPTServer[ne].VMATErrorPolicy.put(tk[0], bits);
							continue;
							}
						
						if (cmd.compareTo("servertype")==0) {
										tok[1]=tok[1].toLowerCase().trim();
										if (tok[1].compareTo("custom")==0) continue;
										
										if (tok[1].compareTo("exit")==0) {
											C.SMPTServer[ne].EnterRoute=true;
											C.SMPTServer[ne].OnlyOnionFrom=false;
											C.SMPTServer[ne].OnlyOnionTo=false;
											C.SMPTServer[ne].CanRelay=false;
											continue;
											}
										
										if (tok[1].compareTo("normal")==0) {
											C.SMPTServer[ne].EnterRoute=false;
											C.SMPTServer[ne].OnlyOnionFrom=false;
											C.SMPTServer[ne].OnlyOnionTo=false;
											C.SMPTServer[ne].CanRelay=false;
											continue;
											}
										
										if (tok[1].compareTo("tor")==0) {
											C.SMPTServer[ne].EnterRoute=false;
											C.SMPTServer[ne].OnlyOnionFrom=true;
											C.SMPTServer[ne].OnlyOnionTo=true;
											C.SMPTServer[ne].CanRelay=false;
											continue;
											}
										continue;
										}
							
						if (cmd.compareTo("verspoof")==0) {
								String st= tok[1].trim()+".0.0.0.0";
								String vr[] = st.split("\\.+");
								long vc=0;
								String vrs="";
								for (int ax=0;ax<4;ax++) {
									int a = J.parseInt(vr[ax].trim());
									vc<<=16;
									vc|=a&65535;
									vrs+=Integer.toString(a)+" ";									
									}
								vrs=vrs.trim();
								Main.Version = vrs;
								Main.VersionID = vc;
								Main.VersionExtra="";
								continue;
								}
						
						if (cmd.compareTo("timespoof")==0) {
							String[] TOK = tok[1].trim().split("\\s+");
							int cl =TOK.length;
							if (cl<0) throw new Exception("Invalid TimeSpoof");
							C.SMPTServer[ne].TimerSpoof = Config.ParseTMP(TOK[0], -86400,86400);
							for (int al=1;al<cl;al++) {
								if (TOK[al].contains("~")) C.SMPTServer[ne].TimerSpoofVibration = Config.ParseTMP(TOK[al].replace('~',' ').trim(), -3600,3600);
								if (TOK[al].contains("<")) C.SMPTServer[ne].TimerSpoofMinEveryDelta = Config.ParseTMP(TOK[al].replace("<", "").trim(), 0,36000);
								if (TOK[al].contains(">")) C.SMPTServer[ne].TimerSpoofMaxEveryDelta = Config.ParseTMP(TOK[al].replace(">", "").trim(), 0,36000);
								String st0 = TOK[al].trim();
								if (st0.matches("\\-[0-9]{4}")) C.SMPTServer[ne].TimerSpoofFus =st0;
								if (st0.matches("\\+[0-9]{4}")) C.SMPTServer[ne].TimerSpoofFus =st0;
								if (st0.matches("\\[A-Za-z]{3}")) C.SMPTServer[ne].TimerSpoofFus =st0.toUpperCase();
							}
							continue;
						}
						
						if (cmd.compareTo("maxtimespoof")==0) {
							String[] TOK = tok[1].trim().split("\\s+");
							if (TOK.length!=2) throw new Exception("MaxTimeSpoof Requires 2 parameters!");
							C.SMPTServer[ne].TimerSpoofMaxPast =  Config.ParseTMP(TOK[0].trim(),0,864000)*1000L;
							C.SMPTServer[ne].TimerSpoofMaxFuture =  Config.ParseTMP(TOK[0].trim(),0,86400)*1000L;
							} 
						
						if (cmd.compareTo("sslinfo")==0) {
						if (C.SMPTServer[ne].SSlInfo == null) C.SMPTServer[ne].SSlInfo = new HashMap <String,String>();
						
						String[] TOK = tok[1].trim().split("\\s+",2);
						String kk = TOK[0].toLowerCase().trim();
						String vv = TOK[1].replace("\\_"," ").trim();
	
						
						if (kk.compareTo("from")==0) vv = Long.toString(System.currentTimeMillis() - Config.ParseTMPF(vv,-315361000, 315361000));
						if (kk.compareTo("to")==0) {
								long aa = System.currentTimeMillis();
								if (C.SMPTServer[ne].SSlInfo.containsKey("from")) aa=J.parseLong(C.SMPTServer[ne].SSlInfo.get("from"));
								aa+= Config.ParseTMPF(vv,-315361000, 315361000);
								vv = Long.toString(aa);		
								}
						
						C.SMPTServer[ne].SSlInfo.put(kk, vv);
						continue;	
						}
						
						if (cmd.compareTo("port")==0||cmd.compareTo("smtpport")==0) {
							C.SMPTServer[ne].LocalPort = Config.parseInt(tok[1], "port");
							continue;
							}
						
						if (cmd.compareTo("canrelay")==0) {
							C.SMPTServer[ne].CanRelay = Config.parseY(tok[1]);
							continue;
							}
												
						if (cmd.compareTo("usessl")==0) {
							C.SMPTServer[ne].isSSL = Config.parseY(tok[1]);
							continue;
							}
								
						
						if (cmd.compareTo("pop3port")==0) {
							C.SMPTServer[ne].LocalPOP3Port = Config.parseInt(tok[1], "port");
							continue;
							}
						
						if (cmd.compareTo("maxmsgxuser")==0) {
							C.SMPTServer[ne].MaxMsgXuser = Config.parseInt(tok[1], "messages",1,65535);
							continue;
							}
						
						if (cmd.compareTo("localip")==0) {
							C.SMPTServer[ne].LocalIP = Config.ParseIp(tok[1]);
							continue;
						}
											
						if (cmd.compareTo("banner")==0) {
							C.SMPTServer[ne].Banner = tok[1];
							continue;
						}
						
						if (cmd.compareTo("maildir")==0) {
							C.SMPTServer[ne].Maildir = tok[1];
							continue;
						}
						
						if (cmd.compareTo("maxspamentryxyser")==0) {
							C.SMPTServer[ne].MaxSpamEntryXUser =parseInt(tok[1],"Entry",0,1024);
							continue;
						}
						
						if (cmd.compareTo("maxmailinglistsize")==0) {
							C.SMPTServer[ne].MaxMailingListSize =parseInt(tok[1],"Users",0,327657);
							continue;
						}
					
						if (cmd.compareTo("lang")==0) {
							C.SMPTServer[ne].DefaultLang =J.GetLangSt(tok[1]);
							if (C.SMPTServer[ne].DefaultLang==null) throw new Exception("Invalid or unknown language `"+tok[1]+"`");
							continue;
							}
								
						if (cmd.compareTo("publiccontrolport")==0) {
							if (tok[1].compareToIgnoreCase("disabled")==0) continue;
							C.SMPTServer[ne].PublicControlPort=Config.parseInt(tok[1],"Port",1,65535);
							continue;
							}
						
						if (cmd.compareTo("publiccontrolip")==0) {
							if (tok[1].compareToIgnoreCase("disabled")==0) continue;
							C.SMPTServer[ne].PublicControlIP=Config.ParseIp(tok[1]);
							continue;
							}
						
						if (cmd.compareTo("maxmsgsize")==0) {
							String st0 =tok[1].replace(" ", "");
							st0 =st0.toUpperCase();
							if (!st0.matches("[0-9\\-\\.\\,MKB]+")) throw new Exception("Invalid size `"+tok[1]+"`"); 
							st0 =st0.replace("\\-", "");
							st0 =st0.replace("\\.", "");
							st0 =st0.replace("\\,", "");
							st0 =st0.replace("M", "000000");
							st0 =st0.replace("K", "000");
							st0 =st0.replace("B", "");
							try { C.SMPTServer[ne].MaxMsgSize = Integer.parseInt(st0); } catch(Exception E) { throw new Exception("Invalid size `"+tok[1]+"`"); }
							continue;
						}
						
					}
				
				if (C.SMPTServer[ne].HasHTTP && C.SMPTServer[ne].HTTPBasePath==null) throw new Exception("HTTP Server of `"+C.SMPTServer[ne].Nick+"` must have a HTTPBasePath");
					
				C.SMPTServer[ne].ExitEnterPolicyBlock=P;	
				if (Main.OnlyLoad) return line;
				
				if (Main.RandomHeart!=null) {
					Main.echo("\t  + Initialize RandomHeart ... ");
					SecureRandom rnd = Stdio.getRandom();
					long x= rnd.nextLong();
					Main.echo("\t"+J.Spaced(Long.toHexString(x),16)+" Ok\n");
				}
				
				try {
					File F = new File(C.SMPTServer[ne].Maildir);
					if (!F.exists() || !C.SMPTServer[ne].CheckServerPresent()) {
						
						if (Main.Oper!=Main.Oper_Gen_ServerS) {
							echo("\nYou must generate the servers!\n\tUse --gen-servers option\n");
							System.exit(2);
							}
						
						echo("Creating new SMTP Server `"+C.SMPTServer[ne].Nick+"` \t ... ");
						C.SMPTServer[ne] = C.CreateServer(C.SMPTServer[ne] );
						echo(" Done!\n\n");
						
						} else {
						if (!F.isDirectory()) throw new Exception("Invalid file or directory `"+C.SMPTServer[ne].Maildir+"` please remove it!");
						C.SMPTServer[ne] = C.InitServer(C.SMPTServer[ne]);
						if (Main.SetPGPSrvKeys)	C.SMPTServer[ne].SrvSetPGPKeys();
						}
				
				C.SMPTServer[ne].BlackList=new IPList(C.SMPTServer[ne],"spam.ip");
				
				if (C.SMPTServer[ne].DisabledVMAT.trim().length()==0 && C.SMPTServer[ne].EnabledVMAT.trim().length()==0) {
					C.SMPTServer[ne].EnabledVMAT="\n*\n";
					}
				
				} catch(Exception E) {
					String ms = E.getMessage();
					if (ms.startsWith("@")) {
							Main.echo(" Error!\n\t"+ms+"\n");
							System.exit(2);
						} else {
							Main.echo(" Error!\n\tServer Exception: "+ms+"\n");
							E.printStackTrace();
							System.exit(2);
						}
				}
							
				return line;
		}
		
		
		
		public static Config LoadFromFile(String filepath) throws Exception {

			BufferedReader br;
			Config C = new Config();
			C.LocalFisrtIp=0;
			C.MaxHosts=0;
			String RunBanner=null;
			HashMap <String,Integer> Poly = new HashMap <String,Integer>();
			C.LocalNetArea = NetArea.ParseNet("127.0.0.1/8");
			C.VMATErrorPolicy.put("SRV_ERR1", 1);
			C.VMATErrorPolicy.put("N_VMAT", 1);
			
			String SMTPS="\n";
			String Friends="\n";
			String PGPRnd=null;
			FileInputStream F = new FileInputStream(filepath);
			int line=0;
			String dnsbl=null;
			C.RootPathConfig = J.GetPath(filepath);
			
			FileInputStream STKF[] = new FileInputStream[8];
			int[] STKLine = new int[8];
			String[] Path = new String[8];
			String[] CFile = new String[8];
			BufferedReader[] STKbr = new BufferedReader[8];
			
			int StackPoint=1;
			
			Path[0] = J.GetPath(filepath);
			String CPath=Path[0];
			STKLine[0]=0;
			STKF[0] = F;
			CFile[0] = filepath;
			br = new BufferedReader(new InputStreamReader(new DataInputStream(F)));
			STKbr[0]=br;
						
			String ConfList="\n"+filepath+"\n";
			String exitbad="";
			String exitgood="";
			boolean feedIsGood=false;
			
			try {
				while(true) {	
							
							String li = null;
							while((li=br.readLine())!=null) {
								line++;
																
								li = li.trim();
								if (li.length()==0) continue;
								if (li.charAt(0) =='#') continue;
								String[] tok = li.split("\\#",2);
		
								li = tok[0];
								li = li.trim();
								if (li.length()==0) continue;
								tok = li.split("\\s+");
								String cmd = tok[0].toLowerCase();
								boolean fc=false;
								
								if (cmd.compareTo("@include")==0) {
									tok[1] = J.MapPath(CPath, tok[1]);
									Main.echo("\tInclude: `"+tok[1]+"`\n");
									if (ConfList.contains("\n"+tok[1]+"\n")) throw new Exception("File `"+tok[1]+"` arleady included"); 
									ConfList+=tok[1]+"\n";
									
									if (StackPoint==7) throw new Exception("Config Stack Overflow. Max=8");
									Path[StackPoint] = J.GetPath(tok[1]);
									STKLine[StackPoint]=line;
									STKF[StackPoint]=F;
									STKbr[StackPoint]=br;
									StackPoint++;
									CFile[StackPoint] = tok[1];
									F = new FileInputStream(tok[1]);
									br = new BufferedReader(new InputStreamReader(new DataInputStream(F)));
									line=0;
									CPath = J.GetPath(tok[1]);
									continue;							
								}
								
								if (cmd.compareTo("path")==0) {
									CPath = tok[1].trim()+"/";
									CPath=CPath.replace("\\", "/");
									CPath=CPath.replace("//", "/");
									CPath=CPath.replace("//", "/");
									File x = new File(CPath);
									if (!x.exists() || !x.isDirectory() || !x.canRead()) throw new Exception("Path access error `"+CPath+"`");
									}
								
								if (cmd.compareTo("dnsserver")==0) { fc=true; C.DNSServer = ParseIp(tok[1]); }
								if (cmd.compareTo("torip")==0) { fc=true; C.TorIP = ParseIp(tok[1]); }
								
								if (cmd.compareTo("errstdout")==0) {
									fc=true;
									if (Config.parseY(tok[1])) System.setErr(System.out);
									}
								
								if (cmd.compareTo("friends")==0 && tok.length==2 && tok[1].compareTo("{")==0) {
									while(true) {
										line++;
										li = br.readLine();
										if (li==null) break;
										li=li.trim();
										tok = li.split("\\#",2);
										li=tok[0];
										li=li.trim();
										if (li.length()==0) continue;
										if (li.compareTo("}")==0) break;
										li=li.toLowerCase();
										if (!XOnionParser.isOnion(li)) throw new Exception("Invalid onion address");
										String t9=XOnionParser.getKey(li)+".onion";
										if (!Friends.contains("\n"+t9+"\n")) Friends=Friends+t9+"\n";
										}
									fc=true;
									}
								
								if (cmd.compareTo("smtpserver")==0) {
									fc=true;
									
									if (tok.length!=3) throw new Exception("Sysntax error for SMTPServer");
									if (tok[2].compareTo("{")!=0)  throw new Exception("Sysntax error for SMTPServer, { requierd.");
									
									if (SMTPS.contains("\n"+tok[1].toLowerCase().trim()+"\n")) throw new Exception("SMTP Server `"+tok[1]+"` Arleady defined");
									SMTPS+=tok[1].toLowerCase().trim()+"\n";
									line=ParseSMTP(C,br,  tok[1].trim(),line,Poly,CPath);
								}
								
								if (cmd.compareTo("exitpolicy")==0) {
									fc=true;
									line=ParseExitList(C,br,line,Poly);
									}
								
								if (cmd.compareTo("localnet")==0) {
									fc=true;
									C.LocalNetArea = NetArea.ParseNet(tok[1]);
									C.LocalNet = C.LocalNetArea.getFirstIP();
									if (C.MaxHosts==0) C.MaxHosts = C.LocalNetArea.getMask() - 2;
									if (C.MaxHosts>65535) C.MaxHosts=65535;
									C.LocalFisrtIp = C.LocalNetArea.getNumberOfFirstIP();
									if (C.LocalFisrtIp==0) C.LocalFisrtIp=1;
									}
								
								if (cmd.compareTo("netallow")==0) {
									fc=true;
									if (tok[1].toLowerCase().contains("local")) C.NetAllow = C.LocalNetArea; 
									else if (tok[1].toLowerCase().contains("all")) C.NetAllow = null; 
									else C.NetAllow = NetArea.ParseNet(tok[1]);
									}
								
								if (cmd.compareTo("logfile")==0) {
									fc=true;
										if (tok[1].toLowerCase().compareTo("stdout")==0) C.LogFile=null; else {
											C.LogFile= J.MapPath(CPath, tok[1]);
											try {
												File Fi = new File(C.LogFile);
												if (!Fi.exists()) Main.file_put_bytes(C.LogFile, new byte[] {32} );
												} catch(Exception EP) { throw new Exception("Log file error `"+tok[1]+"`"); }
											}
										}
								
								if (cmd.compareTo("runbanner")==0) {
										fc=true;
										String tk[] = li.split("\\s+",2);
										if (RunBanner==null) RunBanner="";
										RunBanner+="\n"+tk[1];
										}
								
								if (cmd.compareTo("forversion")==0) {
									fc=true;
									String[] tk = tok[1].split("\\.+");
									int cl = tk.length-1;
									if (cl>4) cl=4;
									long t0=0;
									for (int ax=cl;ax>-1;ax--) {
										t0 |= parseInt(tk[ax],"version",0,65535);
										t0<<=16;
										}
									if (t0<Main.VersionID) Main.echo("Warning: Config file for incompatible version");
									
								}
								
							if (cmd.compareTo("portnames")==0) {fc=true; C.IANAPortFile = J.MapPath(CPath, tok[1]); }
							if (cmd.compareTo("netdefaultdeny")==0) { fc=true; C.NetDisallowAll=Config.parseY(tok[1]); }
							if (cmd.compareTo("dnslogquery")==0) { fc=true; C.DNSLogQuery=Config.parseY(tok[1]); }
							if (cmd.compareTo("mailwipefast")==0) { fc=true; C.MailWipeFast=Config.parseY(tok[1]); }
							
							if (cmd.compareTo("httpcache")==0) {
									C.HTTPCached.put(tok[1], true);
									fc=true; 
									}
						
						if (cmd.compareTo("httpncache")==0) {
										C.HTTPCached.put(tok[1], false);
										fc=true; 
										}
								
								if (cmd.compareTo("maxhttpsessions")==0) { 
										C.MaxHTTPSession  = Config.parseInt(tok[1], "thread", 1, 65535);
										fc=true; 
										}	
								
								if (cmd.compareTo("httpservername")==0) { 
										C.HTTPServerName=tok[1];
										fc=true; 
										}
								
								if (cmd.compareTo("httpbasepath")==0) { 
										fc=true; 
										C.HTTPBasePath  =J.MapPath(CPath, tok[1]);
										File Ft = new File(C.HTTPBasePath);
										if (!Ft.exists()) throw new Exception("Path not found `"+C.HTTPBasePath+"`");
										if (!Ft.isDirectory()) throw new Exception("Not a directory `"+C.HTTPBasePath+"`");
										}
										
								if (cmd.compareTo("httplogfile")==0) { 
										fc=true; 
										C.HTTPLogFile  =J.MapPath(CPath, tok[1]);
										File Ft = new File(C.HTTPLogFile);
										if (Ft.isDirectory()) throw new Exception("Not a file `"+C.HTTPLogFile+"`");
										}
								
								if (cmd.compareTo("maxhttpreq")==0) { 
										fc=true; 
										C.MaxHTTPReq=Config.parseInt(tok[1], "milliseconds", 1, 60000); 
										}
								
								if (cmd.compareTo("maxhttpres")==0) { 
										fc=true; 
										C.MaxHTTPRes=Config.parseInt(tok[1], "seconds", 1, 128)*1000L; 
										}
											
								if (cmd.compareTo("httpkeepalive")==0) { 
										fc=true; 
										C.HTTPKeepAlive=Config.parseInt(tok[1], "seconds", 1, 600); 
										}
								
								if (cmd.compareTo("maxhttppipelining")==0) { 
										fc=true; 
										C.HTTPPipelining=Config.parseInt(tok[1], "requests", 1, 256); 
										}
								
								if (cmd.compareTo("maxhttpreqbuffer")==0) { 
										fc=true; 
										C.HTTPMaxBuffer=Config.parseInt(tok[1], "KB", 1, 256)*1024;; 
										}
								
								if (cmd.compareTo("etexvar")==0) {
										if (tok.length!=3) throw new Exception("Invalid use of ETEXVar");
										C.HTTPETEXVar.put(tok[1], tok[2]);
										fc=true; ;
										}						
								
								if (cmd.compareTo("pgpgenbits")==0) { fc=true; PGPKeyGen.DEFAULT_BITS=Config.parseInt(tok[1], "bits", 1024, 4096); }
								if (cmd.compareTo("pgpgens2kcount")==0) { fc=true; PGPKeyGen.DEFAULT_S2KCOUNT=Config.parseInt(tok[1], "count", 0, 255); }
								if (cmd.compareTo("pgpgencertaintry")==0) { fc=true; PGPKeyGen.DEFAULT_CERTAINTRY=Config.parseInt(tok[1], "certaintry", 1, 4096); }
								
								if (cmd.compareTo("pgpgenpubexpy")==0) try { 
									fc=true; 
									byte[] bi = Stdio.HexData(tok[1].trim());
									PGPKeyGen.DEFAULT_PUBEXP = new BigInteger(bi);
									} catch(Exception E) { throw new Exception("Invalid public exponent big integer bytes"); }
								
								if (cmd.compareTo("pgpgenpasswordsize")==0) { fc=true; PGPKeyGen.DEFAULT_PASS_SIZE=Config.parseInt(tok[1], "characters", 8, 4096); }
								if (cmd.compareTo("pgpgenpasswordstrange")==0) { fc=true; PGPKeyGen.DEFAULT_PASS_STRANGE=Config.parseInt(tok[1], "characters", 8, 4096); }
								if (cmd.compareTo("pgpkeyserver")==0) { fc=true; C.PGPKeyServers = Config.AddToStringList(C.PGPKeyServers,tok[1].trim()); }					
								
								if (cmd.compareTo("ssljavahasbug")==0) { fc=true; C.SSLJavaHasBug=Config.parseY(tok[1]); }
								if (cmd.compareTo("ssljava6regression")==0) { fc=true; LibSTLS.j7regression=Config.parseY(tok[1]); }
								if (cmd.compareTo("sslopenjbug")==0) { fc=true; LibSTLS.openJBug=Config.parseY(tok[1]); }
								if (cmd.compareTo("sslnoedc")==0) { fc=true; LibSTLS.noEDC=Config.parseY(tok[1]); }
								if (cmd.compareTo("sslnodsa")==0) { fc=true; LibSTLS.noDSDSA=Config.parseY(tok[1]); }
								if (cmd.compareTo("sslautotest")==0) { 
										fc=true;
										if (Config.parseY(tok[1])) {
											String f0 = filepath+".sslTest";
											boolean rs=false;
											boolean doTest;
											if (new File(f0).exists()) try {
													rs = Config.parseY(new String(Stdio.file_get_bytes(f0)).trim());
													doTest=false;
													} catch(Exception E) {
														doTest=true;
													} else doTest=true;
											
											if (doTest) rs = LibSTLS.TestJavaDiMerdaBug(C.Debug); 
											
											if (rs) {
													LibSTLS.noDSDSA=true;
													LibSTLS.noEDC=true;
													}
											
											try {
												String s= rs ? "yes":"no";
												Stdio.file_put_bytes(f0, s.getBytes());
												} catch(Exception I) {}
											if (rs&&Main.ConfVars==null) Main.echo("Warning: BAD SSL Limitations in your JVM!\n");
											} 
										}
								
								if (cmd.compareTo("sslusebc")==0) { fc=true; LibSTLS.useBC=Config.parseY(tok[1]); } // Not used!
																
								if (cmd.compareTo("ssldisableciphersuites")==0) {
									Object[] o = Config.ParseLines(C,br,line,"Incomplete SSLDisableCipherSuites section");
									line=(int) o[0];
									String[] t0 = (String[]) o[1];
									String tmp="";
									for (int ax=0;ax<t0.length;ax++) {
											t0[ax]=t0[ax].toUpperCase();
											t0[ax]=t0[ax].trim();
											if (t0[ax]=="") continue;
											if (!t0[ax].matches("[0-9A-Z\\_]+")) throw new Exception("Invalid cipher suite `"+t0[ax]+"`");
											tmp+=t0[ax]+"\n";
											}
									tmp=tmp.trim();
									t0=tmp.split("\\n+");
									tmp=null;
									LibSTLS.setDisabledChipers(t0);
									continue;
									}								
								
								if (cmd.compareTo("ssldisableprotocols")==0) {
									Object[] o = Config.ParseLines(C,br,line,"Incomplete SSLDisableProtocols section");
									line=(int) o[0];
									String[] t0 = (String[]) o[1];
									String tmp="";
									for (int ax=0;ax<t0.length;ax++) {
											t0[ax]=t0[ax].toUpperCase();
											t0[ax]=t0[ax].trim();
											if (t0[ax]=="") continue;
											if (!t0[ax].matches("[0-9A-Z\\_\\.\\-]+")) throw new Exception("Invalid protocol `"+t0[ax]+"`");
											tmp+=t0[ax]+"\n";
											}
									tmp=tmp.trim();
									t0=tmp.split("\\n+");
									tmp=null;
									LibSTLS.setDisabledProtocols(t0);
									continue;
									}			
								
								if (cmd.compareTo("usebootsequence")==0) { fc=true; C.UseBootSequence=Config.parseY(tok[1]); }
								if (cmd.compareTo("aeskeyroundextra")==0) { fc=true; C.AESKeyRoundExtra=Config.parseInt(tok[1],"Round", 0, 15); }		
								if (cmd.compareTo("rsakeygenbc")==0) { fc=true;; }
								if (cmd.compareTo("usekernel")==0) { fc=true; C.UseKernel	=Config.parseY(tok[1]); }
								if (cmd.compareTo("usestatus")==0) { fc=true; C.UseStatus	=Config.parseY(tok[1]); }
								
								if (cmd.compareTo("rsalog")==0 && tok.length>1) {
									fc=true;
									String lf = J.MapPath(CPath, tok[1]);
									if (!new File(lf).exists()) throw new Exception("RSA Log doesn't exits `"+lf+"`\n\tUse --gen-log to create");
									String pw;
									if (tok.length<3) {
										Main.echo("\nTo open RSA log in write mode i need the passphrase.\n\tPassphrase:> ");
										BufferedReader In = J.getLineReader(System.in);
										pw = In.readLine();
										pw=pw.trim();
										} else pw=tok[2].trim();
									C.RLOG = new RSALog(lf,pw.getBytes(),false);																		
									}
								
								if (cmd.compareTo("textcaptcha")==0) {
									fc=true;
									int a=0;
									
									if (tok.length<3) throw new Exception("Wrong parameters number");
									tok[1]=tok[1].toUpperCase().trim();
									if (tok[1].contains("X")) a |= TextCaptcha.MODE_SWX;
									if (tok[1].contains("Y")) a |= TextCaptcha.MODE_SWY;
									if (tok[1].contains("N")) a |= TextCaptcha.MODE_NOISE;
									if (tok[1].contains("I")) a |= TextCaptcha.MODE_INV;
									if (tok[1].contains("S")) a |= TextCaptcha.MODE_SYM;
									if (tok[1].contains("R")) a |= TextCaptcha.MODE_RANDOM;
									if (tok[1].contains("8")) a |= TextCaptcha.MODE_UTF8;
									if (a==0) a=TextCaptcha.MODE_SWX|TextCaptcha.MODE_SWY|TextCaptcha.MODE_NOISE|TextCaptcha.MODE_SYM;
									
									C.TextCaptchaMode=a;
									C.TextCaptchaFile = J.MapPath(CPath, tok[2]);
									TextCaptcha.LoadFonts(C.TextCaptchaFile);
									if (tok.length>3) C.TextCaptchaSize = Config.parseInt(tok[3], "characters", 4, 9);
									}								
								
								if (cmd.compareTo("randomheart")==0) { fc=true; Main.RandomHeart=J.MapPath(CPath, tok[1]); }
								
								if (cmd.compareTo("verfysenderviasimulation")==0) { fc=true; C.VerfySenderViaSimulation=Config.parseY(tok[1]); }
								if (cmd.compareTo("nobootfromsamemachine")==0) { fc=true; C.NoBootFromSameMachine=Config.parseY(tok[1]); }
								if (cmd.compareTo("exitcheckviator")==0) { fc=true; C.ExitCheckViaTor=Config.parseY(tok[1]); }
								
								if (cmd.compareTo("dnssotimeout")==0) { fc=true; C.DNSSoTimeout=Config.parseInt(tok[1],"milliseconds timeout",2000); }
								if (cmd.compareTo("maxsmtpsession")==0) { fc=true; C.MaxSMTPSession=Config.parseInt(tok[1],"smtp connections value",512); }
								if (cmd.compareTo("maxsmtpsessioninitttl")==0) { fc=true; C.MaxSMTPSessionInitTTL=Config.parseInt(tok[1],"seconds timeout")*1000; }
								if (cmd.compareTo("maxsmtpsessionttl")==0) { fc=true; C.MaxSMTPSessionTTL=Config.parseInt(tok[1],"seconds timeout")*1000; }
								if (cmd.compareTo("smtpverifysender")==0) { fc=true; C.SMTPVerifySender=Config.parseY(tok[1]); }
								if (cmd.compareTo("controlip")==0) { fc=true; C.ControlIP=Config.ParseIp(tok[1]); }
								if (cmd.compareTo("controlport")==0) { fc=true; C.ControlPort=Config.parseInt(tok[1], "port", 1,65535); }
								if (cmd.compareTo("messagesgarbageevery")==0) { fc=true; C.MessagesGarbageEvery=60000L*Config.parseInt(tok[1], "minutes", 1,1440); }
								if (cmd.compareTo("rootpass")==0) { fc=true; C.RootPass=tok[1].trim(); }
								if (cmd.compareTo("smtpprehellowait")==0) { fc=true; C.SMTPPreHelloWait=Config.parseInt(tok[1], "milliseconds", 0, 2000); }
								if (cmd.compareTo("rundns")==0) { fc=true;  }
								if (cmd.compareTo("listthreadsmax")==0) { fc=true; C.ListThreadsMax=Config.parseInt(tok[1],"Threads", 0, 256); }
							//	if (cmd.compareTo("serverblacklist")==0) { fc=true; C.ServerBlackList=J.MapPath(CPath, tok[1]); }
								if (cmd.compareTo("passwordmaxstrangerchars")==0) { fc=true; C.PasswordMaxStrangerChars=Config.parseInt(tok[1],"Chars", 1, 256); }
								if (cmd.compareTo("maxdofriendold")==0) { fc=true; C.MaxDoFriendOld=Config.parseInt(tok[1],"Minutes", 1, 1440); }
								
								if (cmd.compareTo("vmaterr")==0) {
									if (tok.length<3) throw new Exception("Syntax error");
									tok[1]=tok[1].toUpperCase();
									tok[2]=tok[2].toUpperCase();
									if (!" HIDE STAR SHOW ".contains(" "+tok[2]+" ")) throw new Exception("Invalid value `"+tok[2]+"`");
									if (!" SRV_ERR1 N_VMAT FALSE_VMAT FALSE_SENDER1 FALSE_SENDER2 NOT_VER * ".contains(" "+tok[1]+" ")) throw new Exception("Invalid vmat value `"+tok[1]+"`");
									int bits = 3;
									if (tok[2].contains("HIDE")) bits=0;
									if (tok[2].contains("STAR")) bits=1;
									if (tok[2].contains("SHOW")) bits=2;
									C.VMATErrorPolicy.put(tok[1], bits);
									fc=true;
									}
								
								if (cmd.compareTo("mimetypes")==0) {
									Object[] o = Config.ParseLines(C,br,line,"Incomplete MIMETypes section");
									line=(int) o[0];
									String[] t0 = (String[]) o[1];
									String tmp="";
									for (int ax=0;ax<t0.length;ax++) {
											t0[ax]=t0[ax].trim();
											if (t0[ax]=="") continue;
											t0[ax]=t0[ax].replace("\t", " ");
											String tk[] = t0[ax].split("\\s+",2);
											if (
													tk.length!=2		||
													!tk[0].matches("[a-zA-Z0-9]{1,40}")	||
													!tk[1].matches("[a-zA-Z0-9\\-\\.\\_\\/\\s\\;\\=\\+]{1,100}")
													) throw new Exception("Invalid MIMEType `"+t0[ax]+"`");
											C.MIMETypes.put(tk[0], tk[1]);
											}
									
									tmp=tmp.trim();
									t0=tmp.split("\\n+");
									tmp=null;
									LibSTLS.setDisabledChipers(t0);
									continue;
									}				
								
								if (cmd.compareTo("passwordsize")==0) { fc=true; C.PasswordSize=Config.parseInt(tok[1],"Chars", 7, 256); }
								if (cmd.compareTo("minbootderks")==0) { fc=true; C.MinBootDerks=Config.parseInt(tok[1],"Servers", 1, 16); }
								if (cmd.compareTo("mailretentiondays")==0) { fc=true; C.MailRetentionDays=Config.parseInt(tok[1],"Days", 4, 365); }
								if (cmd.compareTo("pgpstrictkeys")==0) { fc=true; C.PGPStrictKeys=Config.parseY(tok[1]); }
								if (cmd.compareTo("autodeletereaded")==0) { fc=true; C.AutoDeleteReadedMessages = Config.parseY(tok[1]); }
								
								if (cmd.compareTo("pgpencrypteddataalgo")==0) { 
										fc=true;
										int x = -1;
										String tk = tok[1].trim().toUpperCase();
										if (tk.compareTo("AES128")==0) x= PGPEncryptedData.AES_128;
										if (tk.compareTo("AES192")==0) x= PGPEncryptedData.AES_192;
										if (tk.compareTo("AES256")==0) x= PGPEncryptedData.AES_256;
										if (tk.compareTo("BLOWFISH")==0) x= PGPEncryptedData.BLOWFISH;
										if (tk.compareTo("CAST5")==0) x= PGPEncryptedData.CAST5;
										if (tk.compareTo("IDEA")==0) x= PGPEncryptedData.IDEA;
										if (tk.compareTo("SAFER")==0) x= PGPEncryptedData.SAFER;
										if (tk.compareTo("TRIPLEDES")==0) x= PGPEncryptedData.TRIPLE_DES;
										if (tk.compareTo("TWOFISH")==0) x= PGPEncryptedData.TWOFISH;
										if (tk.compareTo("DEFAULT")==0) x= 0;
										if (x==-1) throw new Exception("Invalid PGP Parameter `"+tk+"`");
										C.PGPEncryptedDataAlgo=x;
										C.PGPEncryptedDataAlgoStr=tk;
										}
																
								if (cmd.compareTo("pgpversionspoofer")==0 && tok.length==2 && tok[1].compareTo("{")==0) {
									while(true) {
										line++;
										li = br.readLine();
										if (li==null) break;
										li=li.trim();
										tok = li.split("\\#",2);
										li=tok[0];
										li=li.trim();
										if (li.length()==0) continue;
										if (li.compareTo("}")==0) break;
										if (PGPRnd==null) PGPRnd="\n";
										if (!PGPRnd.contains("\n"+li+"\n")) PGPRnd=PGPRnd+li+"\n";
										}
									fc=true;
									}
								
								if (cmd.compareTo("pgprootuserpkeyfile")==0) {
									fc=true;
									C.PGPRootUserPKeyFile = J.MapPath(CPath, tok[1]);
									if (!new File (C.PGPRootUserPKeyFile).exists()) throw new Exception("Public PGP key file not found `"+C.PGPRootUserPKeyFile+"`");
								}
								
								if (cmd.compareTo("respath")==0) { 
										fc=true; 
										C.ResPath=tok[1];
										if (C.ResPath.compareToIgnoreCase("@res")==0 || C.ResPath.compareToIgnoreCase("@resource")==0) C.ResPath=null; else C.ResPath = J.MapPath(CPath, C.ResPath);
										}
							
								if (cmd.compareTo("enablednsbl")==0) { fc=true; C.EnableDNSBL  =Config.parseY(tok[1]); }
								if (cmd.compareTo("dnsblusecache")==0) { fc=true; C.DNSBLUseCache   =Config.parseY(tok[1]); }
								if (cmd.compareTo("dnsblforcemaindnsserver")==0) { fc=true; C.DNSBLForceMainDNSServer   =Config.parseY(tok[1]); }
								if (cmd.compareTo("mindlesscompilant")==0) { fc=true; C.MindlessCompilant   =Config.parseY(tok[1]); }
							
								if (cmd.compareTo("listthreadsmax")==0) { fc=true; C.ListThreadsMax   =Config.parseInt(tok[1], "Instances number", 0, 1024); }
								if (cmd.compareTo("listthreadsttl")==0) { fc=true; C.ListThreadsTTL   =60000L * Config.parseInt(tok[1], "Minutes", 1, 1024); }
																
								if (cmd.compareTo("dnsbliplist")==0) {
										fc=true;
										if (tok[1].compareTo("{")!=0) throw new Exception("Syntax error");
										if (C.IPSpec != null) throw new Exception("DNSBLIPList arleady defined");
										C.IPSpec = new HashMap<String, Integer>();
										while((li=br.readLine())!=null) {
											li=li.trim();
											line++;
											if (li.compareTo("}")==0) break;
											if (li.length()==0) continue;
											tok = li.split("\\s+",2);
											if (tok.length!=2) throw new Exception("Flags required");
											if (!tok[0].matches("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")) throw new Exception("Invalid ip address '"+tok[0]+"'");
											int i = 0;
											tok[1]=tok[1].toLowerCase().trim();
											
											if (tok[1].contains("spam")) i = Config.IPS_SPAM;
											if (tok[1].contains("ok")) i = Config.IPS_NoDNSBL;
											
											if (i==0) throw new Exception("Unknown parameter '"+tok[1]+"'");
											C.IPSpec.put(tok[0], i);
											}
								}
								
								if (cmd.compareTo("dnsblservers")==0) {
									fc=true;
									if (tok[1].compareTo("{")!=0) throw new Exception("Syntax error");
									if (dnsbl != null) throw new Exception("DNSBLServers arleady defined");
									dnsbl="";
									
									while((li=br.readLine())!=null) {
										li=li.trim();
										line++;
										if (li.compareTo("}")==0) break;
										if (li.length()==0) continue;
										if (!li.matches("[a-zA-Z0-9\\.\\-]{2,40}\\.[a-zA-Z0-9]{2,6}")) throw new Exception("Invalid domain `"+tok[1]+"`");
										li=li.toLowerCase();
										dnsbl+=li+"\n";
										}	
									
									dnsbl=dnsbl.trim();
									C.SPAMSrvCheck = dnsbl.split("\\n+");
									dnsbl="1";
								}
						
								if (cmd.compareTo("dnsblnochecknetarea")==0) { fc=true; C.DNSBLNoCheck    =NetArea.ParseNet(tok[1]); }
								
								if (cmd.compareTo("dnsblcachesize")==0) { fc=true; C.DNSBLCacheSize =Config.parseInt(tok[1],"entry",1024); }
								if (cmd.compareTo("dnsblcachettl")==0) { fc=true; C.DNSBLCacheTTL =Config.parseInt(tok[1],"seconds",1,3600); }
								if (cmd.compareTo("dnschecktimeout")==0) { fc=true; C.DNSCheckTimeout =Config.parseInt(tok[1],"milliseconds timeout",63,5000); }
								if (cmd.compareTo("dnscheckretry")==0) { fc=true; C.DNSCheckRetry  =Config.parseInt(tok[1],"retry number",0,16); }
								
								if (cmd.compareTo("timespoofdelta")==0) { 
											fc=true;
											if (tok[1].length()==0) throw new Exception("Invalid time Spoof Delta");
											boolean si = (tok[1].charAt(0) == '-');
											if (si || tok[1].charAt(0)=='+') tok[1] = tok[1].substring(1);
											String[] Tik = tok[1].split("\\:|\\/|\\-|\\\\|\\.");
											String[] what = new String[] {		"seconds"			,"minute"			,"hour"		,"day"		,"month"	,	"year" 	};
											int[] vmax = new int[] {				59					,59					,23			,31			,12			,	100		};
											int[] tik = new int[6];
											int tla = Tik.length;
											if (tla>5) tla=5;
											for (int cl = 0;cl<tla;cl++) tik[5-cl] = Config.parseInt(Tik[cl],what[cl],0,vmax[cl]);
											int cl = tik[0] + 
														(tik[1]*60)	+
														(tik[2]*3600) +
														(tik[3]*86400) +
														(tik[4]*2678400) +
														(tik[5]*31536000) 
														;
											
											if (si) cl=-cl;
											C.TimeSpoof=cl;
											if (tok.length==3) {
												if (tok[2].length()!=4 || !tok[2].matches("[\\+\\-].[0-9]{4}")) throw new Exception("Invalid time spoof delta");
												C.TimeSpoofFus = tok[2];
												}
											}
								
								if (cmd.compareTo("defaultonionport")==0) { 
										fc=true; 
										C.DefaultPort=Integer.parseInt(tok[1]);
										if (C.DefaultPort<1 || C.DefaultPort>65535) throw new Exception("Invalid default port "+C.DefaultPort);
										}
								
								if (cmd.compareTo("onionttl")==0) { fc=true; C.OnionTTL=(int)(Integer.parseInt(tok[1])*1000); }
								if (cmd.compareTo("maxconnectionidle")==0) { fc=true; C.MaxConnectionIdle=(int)(Config.parseInt(tok[1])*1000); }
								if (cmd.compareTo("maxhosts")==0) {
									fc=true;
										C.MaxHosts=(int)(Integer.parseInt(tok[1]));
										if (C.MaxHosts<4 || C.MaxHosts>65535) {
												F.close(); 
												throw new Exception("Invalid MaxHosts value! (From 4 to 65535)"); 
												}
										}
								if (cmd.compareTo("maxconnectionxport")==0) { fc=true; C.MaxConnectionXPort=(int)(Integer.parseInt(tok[1])); }
								if (cmd.compareTo("torport")==0) { fc=true; C.TorPort=(int)(Integer.parseInt(tok[1])); }
								if (cmd.compareTo("dnsenablemx")==0) { fc=true; C.DNSEnableMX = Config.parseY(tok[1]); }
								if (cmd.compareTo("dnsaddamx")==0) { fc=true;  C.DNSAddAMX = Config.parseY(tok[1]); }
								if (cmd.compareTo("dnsinaddr")==0) { fc=true; C.DNSInAddr = Config.parseY(tok[1]); }
								if (cmd.compareTo("runsmtp")==0) { fc=true; }
								
								if (cmd.compareTo("debug")==0) { 
										fc=true; 
										C.Debug = Config.parseY(tok[1]);
										LibSTLS.Debug=C.Debug;
										}
								
								if (cmd.compareTo("logtostdout")==0) { fc=true; C.LogStdout = Config.parseY(tok[1]); }
					
								if (cmd.compareTo("noports")==0) try {
									fc=true;
									C.NoPort = new int[tok.length-1];
									int t1 = C.NoPort.length;
									for (int t2=0;t2<t1;t2++) {
										C.NoPort[t2] = Integer.parseInt(tok[1+t2]);
										if (C.NoPort[t2]<0 || C.NoPort[t2]>65535) throw new Exception();
										}
									} catch(Exception FG) { throw new Exception("Invalid port"); }
								
								if (cmd.compareTo("nolocalip")==0) { fc=true; C.NoIP = ParseIPList(tok, false, true,"none empty nothing nobody unused"); }
								if (cmd.compareTo("netallowip")==0) { fc=true; C.NetAllowIp = ParseIPList(tok,true,true,"all"); }
								if (cmd.compareTo("netdenyip")==0) { fc=true; C.NetNoAllowIp = ParseIPList(tok,true,true,"none empty nothing nobody unused"); }
								
								
								if (cmd.compareTo("exitbad")==0) {
										Object[] o = Config.ParseLines(C,br,line,"Incomplete ExitBad section");
										line=(int) o[0];
										String[] t0 = (String[]) o[1];
										String r0=",";
										int cx=t0.length;
										for (int ax=0;ax<cx;ax++) {
											String a = t0[ax].toLowerCase().trim();
											if (a.length()==0) continue;
											if (!a.matches("[a-z0-9\\.\\-\\_]{4,80}")) throw new Exception("Invalid domain `"+a+"`");
											a=a+",";
											if (!r0.contains(","+a)) r0+=a;
											}
										exitbad+=","+r0;
										fc=true;
										}
						
									if (cmd.compareTo("exitgood")==0) {
										
										Object[] o = Config.ParseLines(C,br,line,"Incomplete exitgood section");
										line=(int) o[0];
										String[] t0 = (String[]) o[1];
										String r0=",";
										int cx=t0.length;
										for (int ax=0;ax<cx;ax++) {
											String a = t0[ax].toLowerCase().trim();
											if (a.length()==0) continue;
											if (!a.matches("[a-z0-9\\.\\-\\_]{4,80}")) throw new Exception("Invalid domain `"+a+"`");
											a=a+",";
											if (!r0.contains(","+a)) r0+=a;
											}
										exitgood+=","+r0;
										fc=true;
										}
								
									if (cmd.compareTo("friendsgood")==0) { fc=true; feedIsGood=Config.parseY(tok[1]); }
								
								if (cmd.length()==0) fc=true;
								if (!fc) throw new Exception("Unknown parameter `"+cmd+"`");
							}
							
					F.close();
					br.close();
					
					StackPoint--;
					if (StackPoint<1) break;
					F = STKF[StackPoint];
					STKF[StackPoint]=null;
					CPath=Path[StackPoint];
					line = STKLine[StackPoint];
					br=STKbr[StackPoint];
					
					} //while
					
				///	try {	br.close(); } catch(Exception FQ) {}
				
				Friends=Friends.trim();
				C.FriendServer = Friends.split("\\n+");
				if (C.UseStatus && !C.UseKernel) {
					C.GlobalLog(Config.GLOG_All, "MAIN", "UseStatus without UseKernel: Wrong option, enabling UseKernel\n");
					C.UseKernel=true;
					}
				
				if (feedIsGood) exitgood+=","+J.Implode(",",C.FriendServer)+",";				
				int cx = C.SMPTServer.length;
				exitgood=exitgood.replace(',','\n').trim();
				exitbad=exitbad.replace(',','\n').trim();
				for (int ax=0;ax<cx;ax++) {
					if (C.UseStatus) try {
						String st = "StatusF:\tQ\n";
						Stdio.file_put_bytes(C.SMPTServer[ax].Maildir+"/status", st.getBytes());
						} catch(Exception Fe) { C.SMPTServer[ax].Log("Can't write status: "+Fe.getCause()); }
					
					String a = C.SMPTServer[ax].ExitGood!=null ? C.SMPTServer[ax].ExitGood.replace(',','\n') : "";
					String b = C.SMPTServer[ax].ExitBad!=null ? C.SMPTServer[ax].ExitBad.replace(',','\n') : "";
					a=Config.nlStringSum(a, exitgood);
					b=Config.nlStringSum(b, exitbad);
					a=a.replace('\n',',');
					b=b.replace('\n',',');
					if (a.length()>0 && a.compareTo(",,")!=0) C.SMPTServer[ax].ExitGood=a; else C.SMPTServer[ax].ExitGood=null;
					if (b.length()>0 && b.compareTo(",,")!=0) C.SMPTServer[ax].ExitBad=b; else C.SMPTServer[ax].ExitBad=null;
					}
								
				if (PGPRnd!=null) {
					PGPRnd=PGPRnd.trim();
					C.PGPSpoofVer=PGPRnd.split("\\n+");
					PGPRnd=null;
					}
				
					if (C.MaxHosts>C.LocalNetArea.getMask()) throw new Exception("MaxHosts is too big for the networkarea");
					if (C.MaxHosts>65535) throw new Exception("Too many MaxHost.\nSet another MaxHosts value!\n");
					if (C.MaxHosts==0) C.MaxHosts = C.LocalNetArea.getMask() - 2; 
					if (C.LocalFisrtIp==0) C.LocalFisrtIp=1;
					if (C.DNSServer==null) throw new Exception("DNSServer not set!");
					
					if (C.IANAPortFile==null || C.IANAPortFile.toLowerCase().compareTo("none")==0) {
						C.UsePortName=false;
						Main.echo("\nWarning:\n\tDefault port name list, use a portfile via portnames parameter!\n\n");
					} else {
						try {
							Main.echo("Load PortNames `"+C.IANAPortFile+"`");
							LoadPortList(C);
							C.UsePortName=true;
							Main.echo("\nNamed ports: "+C.PortName.size()+" Ok\n");
							
						} catch(Exception EP) {
							for (int ax=0;ax<8;ax++) try { if (STKF[ax]!=null) STKF[ax].close(); } catch(Exception I) {}
						
							echo(EP.getMessage());
							C.UsePortName=false;
							throw new Exception("Configuration aborted!");
						}
					}
					
					cx = C.NoPort.length;
					for (int ax=0;ax<cx;ax++) if (C.NoPort[ax]==C.DefaultPort) {
						Main.echo("\nWarning:\t\nDefault onion port "+C.DefaultPort+" blocked by NoPort!\n\n");
						break;
						}
					
					if (RunBanner!=null) {
						RunBanner=RunBanner.replace("\\t", "\t");
						RunBanner=RunBanner.replace("\\r", "\r");
						RunBanner=RunBanner.replace("\\n", "\n");
						RunBanner=RunBanner.replace("\\b",new String(new byte[] {7}));
						RunBanner=RunBanner.replace("\\\\", "\\");
						echo(RunBanner+"\n");
						}
					
					C.VMATErrorPolicy=null;										
					
					return C;
			} catch(Exception E) {
				try {	F.close(); } catch(Exception FQ) {}
				String em = E.getMessage();
				if (em==null) em="NULL";
				if (em.compareTo("1")==0) em="Syntax Error";
				//E.printStackTrace();
				if (em.startsWith("@")) throw E;
				throw new Exception("Line: "+line+" "+em+"\n\tFile: `"+CFile[StackPoint]+"`");
			}
		
		}
				
		private static InetAddress[] ParseIPList(String[] arr,boolean cannull,boolean canempty,String empty) throws Exception {
			int cx = arr.length;
			if (cx<1) {
					if (canempty) throw new Exception("Syntax error: set 1 or more ip address or `"+empty+"`"); else throw new Exception("Syntax error: set 1 or more ip address");
					}	
			
			if (cx==2 && empty.contains(arr[1].toLowerCase())) {
				if (!canempty) throw new Exception("This can't be empty or nothing!");
				if (cannull) return null; else return new InetAddress[0];
				}
			
			String last="???";
			try {
				
					InetAddress[] re = new InetAddress[arr.length-1];
							int t1 =re.length;
							for (int t2=0;t2<t1;t2++) {
								last=arr[t2+1];
								re[t2] = ParseIp(arr[t2+1]);
								}
							
					return re;	
			} catch(Exception E) { throw new Exception("Invalid IP address `"+last+"`"); }
			
		}
	
		
		static boolean parseY(String s) throws Exception {
			s=s.trim();
			s=s.toLowerCase();
			if (s.compareTo("y")==0) return true;
			if (s.compareTo("yes")==0) return true;
			if (s.compareTo("true")==0) return true;
			if (s.compareTo("enabled")==0) return true;
			if (s.compareTo("enable")==0) return true;
			if (s.compareTo("1")==0) return true;
			if (s.compareTo("n")==0) return false;
			if (s.compareTo("no")==0) return false;
			if (s.compareTo("false")==0) return false;
			if (s.compareTo("disabled")==0) return false;
			if (s.compareTo("disable")==0) return false;
			if (s.compareTo("0")==0) return false;
			throw new Exception("Invalid boolean parameter `"+s+"`");
		}
		
		Config()  {
			try {
				DNSServer =null;
				LocalNet = InetAddress.getByAddress(new byte[] { 127,0,0,0 });
				
				TorIP = InetAddress.getByAddress(new byte[] { 127,0,0,1 });
				
				NoIP = new InetAddress[] { 
										InetAddress.getByAddress(new byte[] { 127,0,0,1}),
										InetAddress.getByAddress(new byte[] { 127,0,0,2})
										};
				
				ControlIP = InetAddress.getByAddress(new byte[] { 127,0,0,1 });
				
				NoPort = new int[] { 53 };
				} catch(Exception E) { EXC(E,"Conmfig"); }
			}
		
		private static long ParseTMPF(String st,int min, int max) throws Exception {
			String[] Tok = st.trim().split("\\s+");
			int cx= Tok.length;
			long d = 0;
			for (int ax=0;ax<cx;ax++) d+=ParseTMP(Tok[ax],min,max);
			return d;
		}
		
		private static long ParseTMP(String st, int min,int max) throws Exception {
			long re=0;		
			st=st.toUpperCase().trim();
			if (st.contains("H"))
								re  = 3600000*Config.parseInt(st.replace("H","").trim(), "Hours", min/3600,max/3600);
								else if (st.contains("M")) re = 60000L*Config.parseInt(st.replace("M","").trim(), "Minutes", min/60,max/60);
								else if (st.contains("O")) re = 2628000000L*Config.parseInt(st.replace("O","").trim(), "Months", min/2628000,max/2628000);
								else if (st.contains("D")) re = 86400000L*Config.parseInt(st.replace("D","").trim(), "Days", min/86400,max/86400);
								else if (st.contains("Y")) re = 31536000000L*Config.parseInt(st.replace("Y","").trim(), "Years", min/31536000,max/31536000);
								else if (st.contains("I")) re = Config.parseInt(st.replace("I","").trim(), "Milliseconds", min*1000,max*1000);
								else if (st.contains("S")) re = 1000L* Config.parseInt(st.replace("S","").trim(), "Seconds", min,max);
								else if (st.contains("RND") || st.contains("RANDOM")) re = 1000L* ((Stdio.NewRndLong() % (max-min))+min);
								else re = 1000L*Config.parseInt(st, "Seconds", min,max);
			return re;
			}
		
		public  static InetAddress ParseIp(String st) throws Exception {
			try {
				String[] tok = st.split("\\.");
				if (tok.length!=4) throw new Exception();
				byte[] b = new byte[4];
				for (int ax=0;ax<4;ax++) {
					int c = Integer.parseInt(tok[ax]);
					if (c<0 || c>254) throw new Exception();
					b[ax]=(byte)(255&c);
				}
				return InetAddress.getByAddress(b);
				} catch(Exception E) {
					throw new Exception("Invalid IP Address `"+st+"`");
				}
		}
			
		
		public void EXC(Exception E,String Dove) {
			GlobalLog(Config.GLOG_Bad, Dove,E.getMessage()+"");
			if (!Debug) return; 
			StackTraceElement[] SP = E.getStackTrace();
			int cx = SP.length;
			String st="Exception: "+E.toString()+"\n";
			for (int ax=0;ax<cx;ax++) {
				StackTraceElement x = SP[ax];
				st+=x.getClassName()+"."+x.getMethodName()+" "+x.getFileName()+" "+x.getLineNumber()+"\n";
				}
			GlobalLog(Config.GLOG_Bad,Dove,st.trim());
			E.printStackTrace();
		}
		
		@SuppressWarnings("resource")
		private static void LoadPortList(Config C) throws Exception {
			String filepath = C.IANAPortFile;
			DataInputStream in=null;
			BufferedReader br=null;
			FileInputStream F=null;
			String li = null;
			int line=0;
	
			try {
				F = new FileInputStream(filepath);
				in = new DataInputStream(F);
				br = new BufferedReader(new InputStreamReader(in));
				} catch (Exception E) {
					try { br.close(); } catch(Exception Fg) {}
					try { in.close(); } catch(Exception Fg) {}
					try { F.close(); } catch(Exception Fg) {}
					throw new Exception("File error `"+filepath+"`");
				}
			
			try {	
				while((li=br.readLine())!=null) {
					line++;
					li = li.trim();
					if (li.length()==0) continue;
					if (li.charAt(0) =='#') continue;
					String[] tok = li.split("\\#",2);
					li = tok[0];
					li = li.trim();
					if (li.length()==0) continue;
					tok = li.split("\\s+");
					if (tok.length!=2) throw new Exception("Syntax error");
					String ports = tok[0].toLowerCase();
					String portn = tok[1];
					if (ports.length()<1 || ports.length()>8) throw new Exception("Invalid port name");
					int p =0;
					try {
						p = Integer.parseInt(portn);
						if (p<1 || p>65535) throw new Exception();
						} catch(Exception FG) {
							throw new Exception("Invalid port number `"+portn+"`");
							}
					if (C.PortName.containsKey(ports)) throw new Exception("Port arleady defined `"+ports+"`");
					C.PortName.put(ports,p);
					}
				} catch(Exception ER) {
					try { br.close(); } catch(Exception Fg) {}
					try { in.close(); } catch(Exception Fg) {}
					try { F.close(); } catch(Exception Fg) {}
					throw new Exception("Error in `"+filepath+"` Line "+line+": "+ER.toString());
				}
			
			br.close();
			in.close();
			F.close();
		}
	
		private SrvIdentity InitServer(SrvIdentity NewServer) throws Exception {
			
			if (Main.CmdRunBoot) {
				if (new File( NewServer.Maildir+"/head/boot").exists()) {
					if ( NewServer.Boot()) return NewServer;
					Main.echo(" Can't reboot `"+NewServer.Nick+"`\n");
				} else {
					Main.echo(" Can't reboot `"+NewServer.Nick+"` No boot files\n");
					}
			}
						
			String kbf = NewServer.Maildir+"/keyblock.txt";
			String kb="";
			String li;
			if (new File(kbf).exists()) kb = new String(Stdio.file_get_bytes(kbf)); else {
				if (new File( NewServer.Maildir+"/head/boot").exists()) {
					Main.echo("Try to boot `"+NewServer.Onion+"`\n");
					if ( NewServer.Boot()) return NewServer;
					}
				Main.echo("\nServer "+NewServer.Nick+" Requires a keyblock:\nEnter Keyblock sequence:\n");
				kb = J.ASCIISequenceReadI(System.in, "KEYBLOCK");
				
			}
			
			if (Main.SetPass!=null && NewServer.CVMF380TMP==null) NewServer.CVMF380TMP=Main.SetPass;
			
			if (NewServer.CVMF380TMP!=null) {
				li = NewServer.CVMF380TMP;
				NewServer.CVMF380TMP=null;
				} else {
					Main.echo("\nServer "+NewServer.Nick+" Requires password:\n");
					Main.echo("\nEnter Password: ");
					BufferedReader in = J.getLineReader(System.in);
					li = in.readLine();
					li=li.trim();
				}
			
			byte[][] KS = SrvIdentity.KSDecode(J.ASCIISequenceRead(kb, "KEYBLOCK"), li.getBytes());
			NewServer.Open(KS);
			return NewServer;
			
		}
			
		private SrvIdentity CreateServer(SrvIdentity NewServer) throws Exception {
			
				byte[][] InirS =SrvIdentity.CreateSK(NewServer.Onion);
				
				NewServer.Create(InirS.clone());
				NewServer.Open(InirS.clone());
				
				String p0 = J.GenPassword(PasswordSize,PasswordMaxStrangerChars);
				String p1 = J.GenPassword(PasswordSize,PasswordMaxStrangerChars);
				String p3 = J.GenPassword(80, 64);
				
				BufferedReader In = J.getLineReader(System.in);
				boolean bm = Main.ConfVars!=null;
				if (bm) bm = Main.ConfVars.containsKey(NewServer.Nick+"-pass");
				
				if (Main.SelPass || bm) {
					if (bm) {
						p3 = Main.ConfVars.get(NewServer.Nick+"-pass");
						} else {
						Main.echo("\nSet `"+NewServer.Nick+"` passwords\n");
						while(true) {
							if (Main.SetPass==null) {
								Main.echo("KeyBlock Password:> ");
								p3=In.readLine();
								} else {
								p3=Main.SetPass;
								Main.echo("KeyBlock Password is not required here!\n");
								}
							if (p3==null) System.exit(2);
							p3=p3.trim();
							if (p3.length()>7) break;
							Main.echo("\nInvalid password. Min 7 chars.\n");
							}
						}
					
					String xh = NewServer.Nick+"-sysop-smtp";
					
					if (bm && Main.ConfVars.containsKey(xh)) {
						p0 = Main.ConfVars.get(xh);
						} else {
							
							while(true) {
								Main.echo("SysOp SMTP Password:> ");
								p0=In.readLine();
								if (p0==null) System.exit(2);
								p0=p0.trim();
								if (p0.length()>7) break;
								Main.echo("\nInvalid password. Min 7 chars.\n");
								}
						}
					
					xh=NewServer.Nick+"-sysop-pop3";
					if (bm && Main.ConfVars.containsKey(xh)) {
						p1 = Main.ConfVars.get(xh);
						} else {
					
							while(true) {
								Main.echo("SysOp POP3 Password:> ");
								p1=In.readLine();
								if (p1==null) System.exit(2);
								p1=p1.trim();
								if (p1.length()>7) break;
								Main.echo("\nInvalid password. Min 7 chars.\n");
								}
						}
				}
				
				HashMap <String,String> P = new HashMap <String,String>();
				P.put("lang", NewServer.DefaultLang);
				P.put("flag", Const.USR_FLG_ADMIN);
				NewServer.UsrCreate("sysop", p0, p1, 0,P);
				
				String p2= NewServer.Maildir+"/sysop.txt";
				p0 = "Mail address: sysop@"+NewServer.Onion+"\r\n"+
						"SMTP Login: sysop\r\n"+
						"SMTP Password: "+p0+"\r\n"+
						"SMTP Base64 encoded Password: "+J.Base64Encode(p0.getBytes())+"\r\n"+
						"SMTP Base64 encoded Login: "+J.Base64Encode("sysop".getBytes())+"\r\n"+
						"--\r\nPOP3 Login: sysop\r\n"+
						"POP3 Password: "+p1+"\r\n"+
						"--\r\nServer "+NewServer.Nick+":\r\n"+
						"SMTP SERVER LISTEN ADDRESS: "+J.IP2String(NewServer.LocalIP)+" port "+NewServer.LocalPort+"\r\n"+
						"POP3 SERVER LISTEN ADDRESS: "+J.IP2String(NewServer.LocalIP)+" port "+NewServer.LocalPOP3Port+"\r\n"+
						"Tor address: "+NewServer.Onion+"\r\n";
				 p0+="KeyBlock password: "+p3+"\r\n";

				if (bm && (!Main.PGPRootMessages || NewServer.Config.PGPRootUserPKeyFile==null)) {
					if (Main.ConfVars.containsKey(NewServer.Nick+"-pgp-root")) {
						NewServer.Config.PGPRootUserPKeyFile =Main.ConfVars.get(NewServer.Nick+"-pgp-root"); 
						} else bm=false;
					} else bm=false;
				 
				if (bm || (Main.PGPRootMessages && NewServer.Config.PGPRootUserPKeyFile!=null)) try {
					
					byte[] original = p0.getBytes();
					String pgpkf=NewServer.Config.PGPRootUserPKeyFile;
					if (Main.ConfVars!=null && Main.ConfVars.containsKey(NewServer.Nick+"-pgp-root")) pgpkf =Main.ConfVars.get(NewServer.Nick+"-pgp-root");
					FileInputStream pubKey = new FileInputStream(pgpkf);
					byte[] encrypted = PGP.encrypt(original, PGP.readPublicKey(pubKey), null, true, true,new Date(),NewServer.Config.PGPEncryptedDataAlgo);
					p0 = new String(encrypted);
					
					if (NewServer.Config.PGPSpoofVer!=null) try {
						int cx = NewServer.Config.PGPSpoofVer.length;
						if (cx!=0) {
							int r = 1;
							if (cx>1) r = (int) ((0x7FFFFFFFFFFFFFFFL & Stdio.NewRndLong()) % cx);
							String spoof = NewServer.Config.PGPSpoofVer[r];
							p0 = PGP.FilterPGPNSAsMarker(p0, spoof);
							}
						} catch(Exception E) { NewServer.Config.EXC(E, "PGP:SpoofNSA:2"); }
					
				} catch(Exception E) { NewServer.Config.EXC(E, "PGP:Config.CreateServer"); }
				 
				Stdio.file_put_bytes(p2,p0.getBytes());
				byte[] t2 =SrvIdentity.KSEncode(InirS, p3.getBytes());
				p2 = J.ASCIISequenceCreate(t2, "KEYBLOCK");
				
				Stdio.file_put_bytes(NewServer.Maildir+"/keyblock.txt",p2.getBytes());
				NewServer.CVMF380TMP = p3;
													
				p0=J.RandomString(32);
				p1=J.RandomString(32);
				p2=J.RandomString(32);
				p3=J.RandomString(32);
				p0=null;
				p1=null;
				p2=null;
				p3=null;
				System.gc();
								
				return NewServer;
		}
		
		public static Application parseApplicationFile(String file) throws Exception {
			FileInputStream F = new FileInputStream(file);
			BufferedReader br = new BufferedReader(new InputStreamReader(new DataInputStream(F)));
			Application a = new Application();
			try {
				int line=0;
				String li;
				while((li=br.readLine())!=null) {
					String tok[]=li.split("\\#",2);
					tok[0]=tok[0].trim();
					if (tok[0].length()==0) continue;
					tok=tok[0].split("\\s+",2);
					String cmd = tok[0].toLowerCase();
					line++;
					int tl = tok.length;
					
					if (cmd.compareTo("name")==0 && tl==2) {
						if (!tok[1].matches("[a-z0-9]{1,30}\\.app")) throw new Exception("Invalid application name");
						if (a.localPart!=null) throw new Exception("Application name arledy defined, second definition in line "+line+" into the file `"+file+"` defined in");
						a.localPart=tok[1].toLowerCase().trim();
						continue;
						}
					
					if (cmd.compareTo("charset")==0 && tl==2) {
						a.charSet=tok[1].toUpperCase().trim();
						continue;
						}
					
					if (cmd.compareTo("cmd")==0 && tl==2) {
						a.commandLine=tok[1];
						continue;
						}
					
					if (cmd.compareTo("maxmsglength")==0 && tl==2) {
						a.maxMsgLength= Config.parseInt(tok[1], "Chachters", 1, 256000); 
						continue;
						}
					
					if (cmd.compareTo("maxrelength")==0 && tl==2) {
						a.maxReLength= Config.parseInt(tok[1], "Chachters", 1, 256000); 
						continue;
						}
					
					if (cmd.compareTo("base64")==0 && tl==2) {
						a.encode=Config.parseY(tok[1]);
						continue;
						}
							
					if (cmd.compareTo("accessmode")==0 && tl==2) {
						tok[1]=tok[1].toLowerCase().trim();
						if (tok[1].contains("tor"))	a.accessMode|=Application.ACCESS_TOR;
						if (tok[1].contains("inet"))	a.accessMode|=Application.ACCESS_INET;
						if (tok[1].contains("sysop"))	a.accessMode|=Application.ACCESS_SYSOP;
						if (tok[1].contains("user"))	a.accessMode|=Application.ACCESS_USER;
						continue;
						}
				
					if (cmd.compareTo("runmode")==0 && tl==2) {
						if (a.runMode!=0) throw new Exception("RunMode arledy defined, second definition in line "+line+" into the file `"+file+"` defined in");
						tok[1]=tok[1].toLowerCase().trim();
						if (tok[1].compareTo("smtp")==0) a.runMode=Application.RUN_SMTP;
						if (tok[1].compareTo("batch")==0) a.runMode=Application.RUN_BATCH;
						if (tok[1].compareTo("app")==0) a.runMode=Application.RUN_APP;
						continue;
						}
				
					if (cmd.compareTo("req")==0 && tl==2) {
						String p = J.GetPath(file);
						p+="/"+tok[1];
						if (!new File(p).exists()) throw new Exception("Require file `"+p+"` not found. (definition in line "+line+" into the file `"+file+"`) defined in");
						continue;
						}
				
				throw new Exception("Invalid command `"+cmd+"` in line of file `"+file+"` defined in");
				}	
				
				F.close();
				try { br.close(); } catch(Exception i) {}
				
				if (a.accessMode==0) throw new Exception("Access mode not defined in application `"+file+"` defined in");
				if (a.runMode==0) throw new Exception("RunMode not defined in application `"+file+"` defined in");
				if (a.commandLine==null) throw new Exception("Cmd not defined in application `"+file+"` defined in");
				if (a.localPart==null) throw new Exception("Application name not defined in file `"+file+"` defined in");
			} catch(Exception E) {
				try { F.close(); } catch(Exception i) {}
				try { br.close(); } catch(Exception i) {}
				throw E;
			}
			
			return a;	
		}
		
		/*
		private String GetCertFile(String CN) {
			String t0 = CN.toLowerCase()+"\n"+CN.toUpperCase()+"\n"+this.RootPass+"\n"+this.RootPathConfig;
			return this.RootPathConfig+"/"+J.md2st( t0.getBytes())+".ctx";
		}
		
		public void CreateUserCert(String CN,String pass) throws Exception {
			KeyPair SrvCertKey = Stdio.RSAKeyGen(2048);
			String info="";
			long from=1;
			long to = 0x7FFFFFFFFFFFFFL;
			
			for(String K:this.SSLCtrl.keySet()) {
				String v = this.SSLCtrl.get(K);
				if (K.compareTo("from")==0) from =J.parseLong(v);
				if (K.compareTo("to")==0) to =J.parseLong(v);
				info+=K.toLowerCase()+": "+v+"\n";
				}
			
			info=info.trim();
			X509Certificate C = LibSTLS.CreateCert(SrvCertKey, CN, from, to, info);
			byte[] Sale = new byte[32];
			Stdio.NewRnd(Sale);
			byte[] Key = Stdio.sha256a(new byte[][] {CN.getBytes() , Sale , pass.getBytes() });
			byte[] IV = Stdio.md5a( new byte[][] {Key,Sale,pass.getBytes()} );
			
			byte[] b = Stdio.MxAccuShifter(new  byte[][]{
					"ACCESS".getBytes()	,
					C.getEncoded()	}, 0xf380) ;
			
			b = Stdio.AES2Enc(Key, IV, b);
			b = Stdio.MxAccuShifter(new byte[][] { Sale ,  b } ,0xf380);
			Stdio.file_put_bytes(GetCertFile(CN),b);
			}
		
		public X509Certificate LoadUserCert(String CN,String pass) throws Exception {
			byte[] b = Stdio.file_get_bytes(GetCertFile(CN));
			byte[][] f = Stdio.MxDaccuShifter(b, 0xf380);
			byte[] Sale = f[0];
			byte[] Key = Stdio.sha256a(new byte[][] {CN.getBytes() , Sale , pass.getBytes() });
			byte[] IV = Stdio.md5a( new byte[][] {Key,Sale,pass.getBytes()} );
			b = Stdio.AES2Dec(Key, IV,f[1]);
			f = Stdio.MxDaccuShifter(b, 0xf380);
			if (new String(f[0]).compareTo("ACCESS")!=0) throw new Exception("Access denied");
			CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
			X509Certificate cert2 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(f[1]));
			return cert2;			
		}
	*/
		public static final int GLOG_All 				= 1;
		public static final int GLOG_Server 		= 2;
		public static final int GLOG_Event			= 4;
		public static final int GLOG_Bad				= 8;
		public static final int GLOG_Spam			= 16;
				
		@SuppressWarnings("deprecation")
		public void GlobalLog(int type, String zone,String st) { 
			st=st.trim();
			if (RLOG!=null) try {
				RLOG.write(System.currentTimeMillis() + TimeSpoof, (int)Thread.currentThread().getId(), type, zone,st.trim());
				return;
				} catch(Exception E) {
				Main.echo("RSALog Error: "+E.toString()+"\n");	
				}
			
			String[] stl=st.split("\\n+");
			int cx= stl.length;
			st="";
			for (int ax=0;ax<cx;ax++) st+="\n\t"+stl[ax];
			st=st.trim();
			if (cx>1) st+="\n";
			
			
			
			/*
			Meglio un'istanza ed una funzione o due istanze??
			*/
			Date D = new Date(System.currentTimeMillis() + TimeSpoof);
			String h = (D.getYear()+1900)+"-"+
							J.Int2Str(D.getMonth()+1,2)+"-"+
							J.Int2Str(D.getDate(),2)+" "+
							J.Int2Str(D.getHours(),2)+":"+
							J.Int2Str(D.getMinutes(),2)+":"+
							J.Int2Str(D.getSeconds(),2)+"."+
							J.Int2Str((int)(System.currentTimeMillis() % 1000),4);
			
			String t;
			if ((type>>6)==0) {
				t="";
				if ((type&Config.GLOG_All)!=0) t+="A"; else t+="-";
				if ((type&Config.GLOG_Server)!=0) t+="S";  else t+="-";
				if ((type&Config.GLOG_Event)!=0) t+="E";  else t+="-";
				if ((type&Config.GLOG_Bad)!=0) t+="B";  else t+="-";
				if ((type&Config.GLOG_Spam)!=0) t+="S";  else t+="-";
				} else t = "X"+Long.toHexString(0x10000L | type).substring(1);
	
			String tid = Long.toHexString(Thread.currentThread().getId());
			String l = h+" "+J.Spaced(J.Limited(tid,8), 8)+" "+J.Spaced(t, 5)+" "+J.Spaced(zone, 32)+" "+st+"\n";
			
			if (LogFile==null) echo(l); else try {
						LogInPlain(l);
						} catch(Exception E) {
							Main.echo("Log Error: "+E.toString()+"\n");
							Main.echo(l);
							}
		}
					
		private synchronized void LogInPlain(String l) throws Exception {
			l=l.trim();
			PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(LogFile, true)));
			try {
				out.println(l);
				try { out.close(); } catch (Exception ignore) { }
				} catch(Exception E) {
				try { out.close(); } catch (Exception ignore) { }
				throw E;
				}
			
		}
				
		public static String nlStringSum(String a,String b) {
				a=a.toLowerCase().trim();
				b=b.toLowerCase().trim();
				a="\n"+a+"\n";
				String[] t = b.split("\\n+");
				int cx=t.length;
				for (int ax=0;ax<cx;ax++) if (t[ax].length()>0 && !a.contains("\n"+t[ax]+"\n")) a+=t[ax]+"\n";
				a=a.trim();
				t = a.split("\\n+");
				a = J.Implode("\n", t);
				return "\n"+a+"\n";
				}
		
		public static String AddToStringList(String lst,String element) {
			if (lst==null) lst=new String();
			element=element.trim();
			element=element.replace("\n", "");
			lst+=element+"\n";
			return lst;
			}
		
		public static String[] StringList(String st) {
			st=st.trim();
			return st.split("\\n+");
			}
		
		protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
	}