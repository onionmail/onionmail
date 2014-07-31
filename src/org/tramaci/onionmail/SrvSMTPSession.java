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
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.PublicKey;
import java.util.HashMap;

import javax.net.ssl.SSLSocket;

import org.tramaci.onionmail.DBCrypt.DBCryptIterator;
import org.tramaci.onionmail.MailBox.Message;
import org.tramaci.onionmail.MailingList.ListThread;
import org.tramaci.onionmail.MailingList.MLUserInfo;

public class SrvSMTPSession extends Thread {
	public SrvIdentity Mid = null;
	private SMTPServer ParentServer=null;
	protected Socket con = null;
	protected OutputStream O = null;
	protected BufferedReader I = null;
	
	protected String HelloData = "";
	protected int HelloMode=0;
	private int MessageSize=-1;
	private int MessageBytes=0;
	
	private String MailFrom = null;
	private String MailTo = null;
	
	private int RouteFrom  = 0;
	private int RouteTo = 0;
	private int TypeFrom = 0;
	private int TypeTo=0;
	private boolean TLSON = false;
	
	private Config Config = null;
	public long EndTime = 0;	
	
	public static final int MaxHeaderLine = 512;
	//public static final String ServerUser="server";
	
	private static final int XRouteLocal=1;
	private static final int XRouteRemote=2;
	private static final int XRouteServer=3;
	private static final int XRouteList=4;
	private static final int XRouteMulti=5;
	private static final int XRouteApp=6;
	
	private static final int XTypeOnion = 1;
	private static final int XTypeInet = 2;
	private static final int XTypeServer = 3;
	
	private static final int XE_Normal=0;
	private static final int XE_Exit=1;
	private static final int XE_Entry=2;
	
	private int ExitMode=0;
	
	private String Login = null;
	private String Password = null;
		
	private String SessionKUKI = null;
	public InetAddress RemoteIP =null; 
	public InputStream IS=null;
	
	public boolean IPisLocal=false;
	public boolean isDismissed=false;
	
	public boolean KUKIAuth=false;
	public String FromAliasUser=null;
	public String ToAliasUser=null;
	public String TormVmatTo=null;
	public String VmatedBy=null;
	
	public boolean PGPSession=false;
	public String[] MultiRCPTTo = null;
	public int MultiRCPTToLength=0;
	
	public int serverMode = 0;
	public int tryLogin=0;
	public boolean falseLogin=false;
	
	SrvSMTPSession(Config C,SrvIdentity id,Socket s,SMTPServer Pae) throws Exception {
		super();
		ParentServer=Pae;
		Config=C;
		con=s;
		Mid=id;
		O = s.getOutputStream();
		IS = s.getInputStream();
		I = getInputLineJavaDelirio(IS);
		EndTime = System.currentTimeMillis() + Config.MaxSMTPSessionInitTTL;
		RemoteIP = s.getInetAddress();
		MultiRCPTTo=new String[Mid.MultiDeliverMaxRCPTTo];
		byte[] b = RemoteIP.getAddress();
		if (b[0]==127) IPisLocal=true;
		serverMode=Pae.serverMode;
		start();
		}
	
	public void ExtraSpam(int p) {
		InetAddress sp = con.getInetAddress();
					if (sp.getAddress()[0]!=127) try {
						if (Mid.BlackList!=null) Mid.BlackList.setIP(sp, p);
						Log("Extra SPAM Points "+p+" for: `"+J.IP2String(sp)+"` HELO  `"+HelloData+"`\n");
						} catch(Exception I) { Config.EXC(I, "AddSpamPoint "+Mid.Nick); }
	}
	
	public void run() {
		
		try {
			
			BeginSMTPSession();
			Log("Complete");
			if (con.isConnected()) {
				if (!con.isClosed()) Send("421 CRDM 1");
				closeh();
				}
			
		} catch(Exception E) {
			isDismissed=true;
						
			if (E instanceof PException || E instanceof SocketException) {
					InetAddress sp = con.getInetAddress();
					if (sp.getAddress()[0]!=127) try {
						if (Mid.BlackList!=null) Mid.BlackList.setIP(sp, 1);
						Log("Some SPAM Points for: `"+J.IP2String(sp)+"` HELO  `"+HelloData+"`\n");
						} catch(Exception I) { Config.EXC(I, "AddSpamPoint "+Mid.Nick); }
					Mid.StatSpam++;
					}
			
			String msg = E.getMessage();
			if (msg==null) msg="Exception.Null";
			
			if (E instanceof SocketException) {
				msg="@550 Network Error: "+E.getMessage();
				} 
			
			if (Config.Debug) E.printStackTrace();
			
			if (msg.startsWith("@")) {
				msg=msg.substring(1);
				if (con.isConnected()) try {Send(msg); } catch (Exception F)  {}
				Mid.StatError++;
				Log(Config.GLOG_Event,msg);
				} else {
				Config.EXC(E, "SmtpSession "+Mid.Nick);
				Mid.StatException++;
				}
			if (con.isConnected()) closeh();
			try { con.close(); } catch(Exception I) {}
			}
		
	isDismissed=true;
	try { con.close(); } catch(Exception I) {}
	Mid.Garbage();
	try { ParentServer.Garbage(); } catch(Exception E) { Config.EXC(E, Mid.Nick+".ParentGarbage"); }
	}
	
	public boolean isConnected() { 
			if (isDismissed) return false;
			return con.isConnected();
			}
	
	private void Send(String str) throws Exception { 
			str+="\r\n";
			O.write(str.getBytes());
			}
	
	private BufferedReader getInputLineJavaDelirio(InputStream i) {
		DataInputStream in = new DataInputStream(i);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		return br;
		}
	
	private void closeh() {
		try {	con.close();	} catch(Exception I) {}
		try {	I.close();	} catch(Exception I) {}
		try {	O.close();	} catch(Exception I) {}
	}
	
	private void checkRelay() throws Exception {
		if (MailFrom==null || MailTo==null || Mid==null || Mid.Onion==null ) return;
		String df =J.getDomain(MailFrom);
		String dt =J.getDomain(MailTo);
		boolean mf = J.isMailMat(MailFrom);
		boolean mt = J.isMailMat(MailTo);

		if (Mid.EnterRoute) {
			if (mf && mt) throw new Exception("@501 Relaying in MAT mode is not permitted");
			if (!mf && mt) return;
			if (mf && !mt) return;
			
			boolean of = df.endsWith(".onion");
			boolean ot = dt.endsWith(".onion");
			if (!of && ot) return; 
			if (of && !ot) return;
			
			} else {
			if (mf || mt) throw new Exception("@501 This is not an Exit/Enter OnionMail server");	
			}
				
		if (df.compareTo(Mid.Onion)!=0 && dt.compareTo(Mid.Onion)!=0) throw new Exception("@501 Relay not permitted");
	}
		
	private boolean SMTP_TKIM() throws Exception {

		if (!HelloData.matches("[a-z0-9]{16}\\.onion") && !HelloData.matches("[a-zA-Z0-9\\_\\-\\.]{2,64}\\.[a-zA-Z]{2,6}")) throw new PException("@550 Invalid HELO/EHLO Data for TKIM");
		PublicKey P = null;
			try {
			P = Mid.LoadRSAKeys(HelloData);
			if (P==null) {
				Mid.DoFriend(HelloData);
				P = Mid.LoadRSAKeys(HelloData);
				}
			} catch(Exception E) {
				String err="550 TKIM for `"+HelloData+"` Error: "+E.getMessage();
				Log(Config.GLOG_Event,err);
				Send(err);
				return false;
			}
			
		if (P==null) {
				String err="550 TKIM for `"+HelloData+"` Error: No public RSA KEY available"; 
				Log(Config.GLOG_Event,err);
				Send(err);
				return false;
			}
			
		byte[] bst = new byte[256];
		Stdio.NewRnd(bst);
		SMTPReply rp = new SMTPReply(334, bst,"TKIM/1.0");
		rp.Send(O);
		rp = new SMTPReply(I);
		byte[] sig = rp.getData();
		rp=null;
		
		if (sig.length==0) {
			Send("535 Empty signature");
			Log(Config.GLOG_Event,"Empty TKIM signature for `"+HelloData+"`");
			return false;			
			}
		
		boolean bit=false;
		try {
			if (Stdio.RSAVerify(bst, sig,P)) {
					bit=true;
					Send("250 Ok, Hello `"+HelloData+"`");
				} else {
					bit=false;
					Send("535 Invalid signature");
					Log(Config.GLOG_Event,"Invalid TKIM signature for `"+HelloData+"`");
				}
			} catch(Exception E) {
				Config.EXC(E, "SMT_TKIM(`"+HelloData+"`)");
				Send("535 Invalid signature");
				return false;
				}
		
		if (Config.Debug) Log("TKIM Sign OK for `"+HelloData+"`");
		return bit;
		}
	
	private void addRCPTTo(String t0) throws Exception {
		MultiRCPTTo[MultiRCPTToLength]=t0;
		if (MultiRCPTToLength>0) RouteTo=SrvSMTPSession.XRouteMulti;
		MultiRCPTToLength++;
		if (MultiRCPTToLength>Mid.MultiDeliverMaxRCPTTo) throw new PException("@503 Too many RCPT TO");
		}
	
	private void  BeginSMTPSession() throws Exception {			//XXX <- Se non la trovi eccola qua!
		boolean AuthEd=false;
		KUKIAuth=false;
		
		if (Config.Debug) Log(Config.GLOG_Event, "New session for `"+J.IP2String(RemoteIP)+"`");
		
		SessionKUKI = J.RandomString(32);
		
		String t0 = Mid.Banner;
		if (Config.SMTPPreHelloWait>0) {
			Thread.sleep(Config.SMTPPreHelloWait);
			int ist = IS.available();
			if (ist!=0) throw new PException("@500 SMTP Sync error. I must talk first!");
			}
		
		if (Mid.EnterRoute && !IPisLocal) t0=t0.replace("${SERVER}", Mid.MXDomain==null ? Mid.ExitRouteDomain :  Mid.MXDomain); else t0=t0.replace("${SERVER}", Mid.Onion);
		t0=t0.replace("${NICK}", Mid.Nick);
		t0=t0.replace("${SOFTWARE}", "OnionMail "+( Mid.NoVersion ? "1.0.0 10010000"  : Main.getVersion()));
		t0=t0.replace("${DATE}",Mid.TimeString());
			
		Send("220 "+t0);
		t0=null;
		if (Config.SMTPPreHelloWait>0) {
			int ist = IS.available();
			if (ist!=0) throw new PException("@500 SMTP Sync error. I must talk first!");
			}
		
		String[] Tok = null;
		////////				-- HELO state --
		HelloMode=0;
		for (int ax=0;ax<2;ax++) {
			Tok = GetSMTPCommands(3,new String[] { "HELO" , "EHLO" , "QUIT" },"503 Why not say hello?",null);
			if (Tok==null) continue;
			
			if (Tok[0].compareTo("QUIT")==0) {
					BeginClose();
					return;
					}
			
			if (Tok.length!=2) {
					Log("Fuck Off session, cmd=`"+J.Implode("|", Tok)+"`");
					BeginClose("500 FUCK OFF");
					return;
					}
			
			if (Tok[0].compareTo("HELO")==0) { HelloMode=1; KUKIAuth=false; break; }
			if (Tok[0].compareTo("EHLO")==0) { HelloMode=2; KUKIAuth=false; break; }
			}
		
		if (HelloMode==0) {
					BeginClose("500 FUCK OFF");
					Log("SMTP: Command before EHLO `"+((Tok[0]!=null) ? Tok[0] : "")+"`");
					return;
					}
		
		HelloData = Tok[1];
		
		if (HelloMode==1) Send("250 "+(Mid.EnterRoute&& !IPisLocal ? Mid.ExitRouteDomain : Mid.Onion)+" Hello "+HelloData+" [0.0.0.0]");
		if (HelloMode==2) {
				
				SessionKUKI = J.RandomString(32);
				
				SMTPReply.Send(this, 250, new String[] {
						"<"+(Mid.EnterRoute&& !IPisLocal ? Mid.ExitRouteDomain : Mid.Onion)+"> Hello "+HelloData+" [0.0.0.0]"	,
						"STARTTLS"														,
						"SIZE "+Mid.MaxMsgSize									,
						"AUTH PLAIN LOGIN"										,
						"TKIM"																,
						"TORM V="+Const.TormVer							})
						;
			}
		
	/////////			-- Header state --
	
	int mtr=8;
	int ax=0;
	while(true) {
			Tok = GetSMTPCommands(3,new String[] { 
							"MAIL FROM:" , "RCPT TO:" ,"TORM VMAT TO:", "AUTH LOGIN","AUTH PLAIN","TORM K","TORM IAM",
							"TORM WHO","TORM DERK","TORM PUSH","TORM MX","TORM VMAT", "DATA","STARTTLS","QUIT",
							"HELO","EHLO","TKIM" },"503 WTF???",null)
							;
			
			if (Tok==null) {
				ax++;
				if (ax>=mtr) throw new PException("@500 Too many errors in Header State");
				continue;
				}
			if (Config.Debug) Log("Server cmd `"+Tok[0]+"`");
			
			int tle = Tok.length;
			ax++;
			if (Tok[0].compareTo("QUIT")==0) {
					BeginClose();
					return;
					}
			
			if (Tok[0].compareTo("STARTTLS")==0) {
				if (TLSON) {
					Send("454 TLS not available due to temporary reason: TLS already active");
					continue;
					}				
				Send("220 Go ahead");
				SSLSocket SL;
				try {
						SL = LibSTLS.AcceptSSL(con, Mid.SSLServer, Mid.Onion);
					} catch(Exception E) {
						if (Config.Debug) {
							Log(Config.GLOG_Bad,"LibSTLS: "+E.getMessage());
							E.printStackTrace();
							}
						throw new Exception("@500 Invalid SSL Session: "+E.toString());
						}
				con=SL;
				O=null;
				O = SL.getOutputStream();
				I =null;
				I = J.getLineReader(SL.getInputStream());
				TLSON=true;
				continue;
				}
			
			if (Tok[0].compareTo("TORM WHO")==0 && Tok.length>1) {
				String t2 = Tok[1].toLowerCase().trim();
				
				byte[] rs = Mid.SSLReqHash(t2);
				
				if (rs==null) {
					Send("550 I don't know `"+t2+"`");
					Log(Config.GLOG_Event,"Unknown server WHO request `"+t2+"` by `"+HelloData+"`");
				} else {
					SMTPReply rp = new SMTPReply(250,rs,t2+" SHA-1");
					rp.Send(O);
					Log(Config.GLOG_Event,"WHO request `"+t2+"` by `"+HelloData+"`");
				}
				
				continue;
			}
			
			if (Tok[0].compareTo("TORM MX")==0 && Tok.length==2) {
				if (Config.Debug) Log("NSLOOKUP `"+Tok[1]+"`");
				SMTPReply rp = Mid.checkRemoteServer(Tok[1]);
				rp.Send(O);
				rp=null;
				continue;
			}
									
			if (Tok[0].compareTo("TORM PUSH")==0 && Tok.length>1) try {
				if (!HelloData.matches("[a-z0-9]{16}\\.onion") && !HelloData.matches("[a-zA-Z0-9\\_\\-\\.]{2,64}\\.[a-zA-Z]{2,6}")) throw new PException("@550 Invalid HELO/EHLO Data for PUSH");
				RemoteDerK RK =null;
				if (Tok.length>1) {
					t0 = Tok[1].toLowerCase().trim();
					if (t0.compareTo("new")==0) {
						if (!KUKIAuth) {
							Send("550 TKIM Required");
							Log(Config.GLOG_Event,"Bad PUSH NEW for `"+HelloData+"`");
							continue;
							}
						RK = new RemoteDerK(Mid,HelloData.toLowerCase().trim());
						RK.Save();
						Send("220-"+RK.Password);
						Send("220 "+RK.getDesConf());
						RK=null;
						continue;
						}}
	
				if (Tok.length<3) {
					Send("500 PUSH WTF???");
					continue;
					}
			
				t0 = Tok[1].toLowerCase().trim();
				String pw = Tok[2].trim();
				RK= RemoteDerK.Load(Mid, HelloData.toLowerCase().trim());
				
				if (RK==null) {
					Send("550 No such PUSH");
					continue;
					}
				
				if (pw.startsWith("#")) {
					
						String s8 = pw.substring(1);
						if (!RK.LogonSec(s8)) {
							RK=null;
							Send("550 Access Denied");
							continue;
							}
					} else {
				
						if (!RK.Logon(pw)) {
							RK=null;
							Send("550 Access Denied");
							continue;
							}
					}
				
				if (RK!=null && t0.compareTo("set")==0 && Tok.length==4) {
					RK.setCredit(J.parseInt(Tok[3]));
					RK.Save();
					RK=null;
					Send("220 Ok");
					continue;
					}
				
				if (RK!=null && t0.compareTo("gets")==0) {
					if (!TLSON || !KUKIAuth) {
						Send("550 Only width TKIM and STARTTLS");
						Log("Try to get DERK secret data in not auth mode by `"+HelloData+"`");
						RK=null;
						continue;
						}
					Send("220 "+RK.getInternal()); 
					RK=null;
					continue;
					} 
				
				if (RK!=null && t0.compareTo("max")==0 && Tok.length==4) {
					RK.setMaxCredit(J.parseInt(Tok[3]));
					RK.Save();
					RK=null;
					Send("220 Ok");
					continue;
					}
				
				if (RK!=null && t0.compareTo("gmax")==0) {
					int x =RK.getMaxCredit();
					RK=null;
					Send("220 "+x+" Ok");
					continue;
					}
				
				if (RK!=null && t0.compareTo("get")==0) {
					int x =RK.getCredit();
					RK=null;
					Send("220 "+x+" Ok");
					continue;
					}
				
				if (RK!=null && t0.compareTo("start")==0) {
					RK.Restart();
					int x =RK.getCredit();
					RK.Save();
					RK=null;
					Send("220 "+x+" Ok");
					continue;
					}
				
				if (RK!=null && t0.compareTo("gstatus")==0) {
					int x =RK.getStatus();
					RK=null;
					Send("220 "+x+" Ok");
					continue;
					}
				
				if (RK!=null && t0.compareTo("sstatus")==0 && Tok.length==4) {
					int x = J.parseInt(Tok[3]);
					if (x<0) x=0;
					if (x>1) x=1;
					RK.setStatus(x);
					RK.Save();
					RK=null;
					Send("220 Ok");
					continue;
					}
				
				if (RK!=null && t0.compareTo("cnf")==0) {
					String s = RK.getDesConf();
					RK=null;
					Send("220 "+s);
					continue;
					}
				
				if (RK!=null && t0.compareTo("del")==0) {
					String s = RK.getDesConf();
					RK.Destroy();
					RK=null;
					Send("220 "+s);
					continue;
					}
								
				RK=null;
				Send("500 Wrong PUSH operation");
				continue;
				/*PUSH*/	} catch(Exception EX) {
					String ms = EX.getMessage()+"";
					if (ms.startsWith("@")) {
						ms=ms.substring(1);
						Send(ms);
						Log(Config.GLOG_Event,ms+" (`"+HelloData+"`)");
						} else {
							Config.EXC(EX, "PUSH(`"+HelloData+"`)");
							Log(Config.GLOG_Event,"PUSH_EXC `"+ms+"` (`"+HelloData+"`)");
						}
				} //push/exc
			
			
			if (Tok[0].compareTo("TORM DERK")==0) {
					if (!HelloData.matches("[a-z0-9]{16}\\.onion") && !HelloData.matches("[a-zA-Z0-9\\_\\-\\.]{2,64}\\.[a-zA-Z]{2,6}")) throw new PException("@550 Invalid HELO/EHLO Data for DERK");
					SMTPReply rp = new SMTPReply(334, "Begin your FUFFA!");
					rp.Send(O);
					rp = new SMTPReply(I);
					rp = Mid.SrvDer(rp,HelloData);
					rp.Send(O);
					continue;
				}
			
			if (Tok[0].compareTo("TORM VMAT")==0 && Tok.length>1) {
								
				if (Tok[1].compareToIgnoreCase("REGISTER")==0 && Tok.length==4) {
					if (!TLSON || !KUKIAuth) throw new PException("@500 Invalid state for VMAT REGISTER from `"+HelloData+"`");
					
					if (!Mid.EnterRoute) {
						Send("550 This is not an Exit/Enter router");
						continue;
						}
					
					if (!CanVMATOp(HelloData)) throw new PException("@500 Your server can't use VMAT to this exit router `"+HelloData+"`");
					
					if (Tok[2].contains("@") || Tok[3].contains("@")) throw new PException("@500 Invalid mail address for VMAT");
					
					String vmata = Tok[2].toLowerCase().trim();
					
					if(
							vmata.endsWith(".onion")	||
							vmata.endsWith(".sys")		||
							vmata.compareTo("server")==0 
							) throw new PException("@500 Invalid VMAT mail address `"+vmata+"`") ;
							
					Tok[3] = Tok[3].toLowerCase().trim();				
					
					if(
							Tok[3].endsWith(".onion")	||
							Tok[3].endsWith(".sys")		||
							Tok[3].compareTo("server")==0 
							) throw new PException("@500 Invalid mail address `"+Tok[3]+"`") ;
					
					Tok[3] = Tok[3]+"@"+HelloData.toLowerCase().trim();
					String vmail = J.getMail(Tok[3], true);
					if (vmail==null) throw new PException("@500 Invalid mail address for VMAT");
					
					if (Tok[3].contains(".")) {
						String[] x0 = Tok[3].split("\\.");
						String ext = x0[x0.length-1];
						ext="."+ext;
						if (!Tok[2].endsWith(ext)) Tok[2]+=ext;
						} else if (Tok[2].contains(".")) throw new PException("@500 Invalid vmat address for this address type");
																			
					String passwd =  J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
					VirtualMatEntry M = Mid.VMAT.subscribe(vmata, vmail,passwd);
					if (M==null) {
						Send("550 Can't create this VMAT, change VMAT address");
						continue;
						}
					
					M.localPart+="@"+Mid.ExitRouteDomain;
					byte[] sig = Mid.VMAT.Sign(M.localPart, M.onionMail, Mid.SSK);
					String[] sis = new String[] { J.Base64Encode(sig) };
					sig=null;
					sis = J.WordWrap(sis[0], 64);
					String[] rsa = new String[sis.length+3];
					rsa[0] = M.localPart;
					rsa[1] = M.onionMail;
					rsa[2] = passwd;
					System.arraycopy(sis, 0, rsa, 3, sis.length);
					sis=null;
					SMTPReply.Send(O, 250, rsa)	;
					rsa=null;
					continue;
				}
				
		
				if (Tok[1].compareToIgnoreCase("CHG")==0) { 
					if (Tok.length<5) {
						Send("550 Parser error");
						continue;
						}
					//TORM VMAT|CHG|local|pwl|set
					if (!TLSON || !KUKIAuth) throw new PException("@500 Invalid state for VMAT REGISTER from `"+HelloData+"`");
								
					if (!Mid.EnterRoute) {
						Send("550 This is not an Exit/Enter router");
						continue;
						}
					
					if (!CanVMATOp(HelloData)) throw new PException("@500 Your server can't use VMAT to this exit router `"+HelloData+"`");
					
					VirtualMatEntry M = Mid.VMAT.loadVmat(Tok[2], false);
					if (M==null) {
						Send("500 No such VMAT address");
						continue;
						}
					
					String dom = J.getDomain(M.onionMail);
					if (dom.compareTo(HelloData)!=0) throw new PException("@500 Invalid server `"+HelloData+"` for this mat `"+M.localPart+"@"+Mid.ExitRouteDomain+"`");
					
					if (!Mid.VMAT.logon(M, Tok[3])) {
						Send("550 Access denied to `"+Tok[2]+"@"+Mid.ExitRouteDomain+"` `"+Tok[3]+"`"); 
						M=null;
						continue;
						}
					
					if (Tok[4].compareToIgnoreCase("DELETE")==0) {
						Mid.VMAT.delete(M);						
						Send("250 OK");
						M=null;
						continue;
						}
					
					if (Tok[4].compareToIgnoreCase("LOOKUP")==0) {
						Send("220 "+(M.enabled ? "TRUE":"FALSE")+" OK");
						M=null;
						continue;
						}
					
					M.enabled = Config.parseY(Tok[4]);
					Mid.VMAT.saveVMAT(M);
					Send("250 OK");
					M=null;
					continue;
					}
				
				if (Tok[1].compareToIgnoreCase("LOOKUP")==0 && Tok.length==2) {
					if (!Mid.EnterRoute) throw new PException("@500 This is not an exit node!");
					if (MailTo==null) throw new PException("@550 Invalid command sequence S3");
					if (VmatedBy==null) Send("500 No VMAT info availabled"); else Send("250 "+MailTo);
					continue;
					}
				
				if (Tok[1].compareToIgnoreCase("LOOKUP")==0 && Tok.length==3) {
					if (!Mid.EnterRoute) throw new PException("@500 This is not an exit node!");
					String mdo = J.getMail(Tok[2], false);
					if (mdo==null) throw new PException("@550 Invalid mail address");
					String mlp = J.getLocalPart(mdo);
					mdo = J.getDomain(mdo);
					if (mdo.compareTo(Mid.ExitRouteDomain)!=0) throw new PException("@550 Not for me");
					VirtualMatEntry M = Mid.VMAT.loadVmat(mlp, false);
					String rs = null;
					if (M!=null) rs = M.onionMail;
					if (rs==null) Send("500 No VMAT info availabled"); else Send("250 "+rs);
					continue;
					}
				
				Send("503 Unknown VMAT Option");
				continue;
			}
			
			if (Tok[0].compareTo("TORM IAM")==0 && Tok.length>1) {
				
				String remo = XOnionParser.getKey(Tok[1].toLowerCase());
					if (remo==null) {
						Send("503 Onion error");
						continue;
						}
					
					if (remo.compareToIgnoreCase("iam")!=0) {
						remo+=".onion";
						Log("Require IAM `"+remo+"` by `"+HelloData+"`\n");
						try { Mid.TORM_IAM(remo); } catch(Exception E) { throw new Exception(E.getMessage()+" From `"+HelloData+"`"); }
						} else Log("Reply IAM `"+HelloData+"`\n");
					
					boolean newManifest=false;
					if (Tok.length>2 && Config.parseIntS(Tok[2])>1) newManifest=true;
					Log("Sending Manifest ver "+newManifest+" to `"+remo+"`");
					
					String s = Mid.CreateManifest(newManifest);
					s=s.replace("\r", "");
					SMTPReply rp = new SMTPReply(250, s.split("\\n"),Mid.Onion+" Manifest");
					rp.Send(O);
					continue;
				}
			
			if (TLSON) {

				if (Tok[0].compareTo("HELO")==0) { 
						Send("250 "+Mid.Onion+" Hello "+HelloData+" [0.0.0.0]");
						KUKIAuth=false;
						continue;
						}	
				
				if (Tok[0].compareTo("EHLO")==0) { 
					SessionKUKI = J.RandomString(32);
					KUKIAuth=false;
					
				SMTPReply.Send(this, 250, new String[] {
						"<"+Mid.Onion+"> Hello "+HelloData+" [0.0.0.0]"	,
						"SIZE "+Mid.MaxMsgSize									,
						"AUTH PLAIN"													,
						"TKIM"																,
						"TORM V="+Const.TormVer							})
						;
				continue;
				}
				
			}  //TLSON
						
			if (Tok[0].compareTo("TORM K")==0) {
				SMTPReply rp = new SMTPReply(250, Stdio.Public2Arr(Mid.SPK),Mid.Onion+" "+Mid.SPK.getAlgorithm()+" "+Mid.SPK.getFormat());
				rp.Send(O);
				continue;
				}
			
			if (Tok[0].compareTo("TKIM")==0) {
				KUKIAuth = SMTP_TKIM();
				continue;
				}
					
			if (/*!TLSON &&*/ Tok[0].compareTo("AUTH LOGIN")==0) {
				tryLogin++;
				if (tryLogin>3) ExtraSpam(1);
				if (tryLogin>5) {
					ExtraSpam(50);
					falseLogin=true;
					Send("334 VXNlcm5hbWU6");
					Login = I.readLine();
					Send("334 UGFzc3dvcmQ6");
					Password = I.readLine();
					Login=null;
					Send("235 ok, go ahead, it is important to be convinced!"); 
					continue;
					}
				if (AuthEd) {
					Send("503 Why!");
					continue;
					}
				
				if (serverMode != SMTPServer.SM_TorServer) {
					Send("503 Can't login to an EXIT/ENTER server.");
					continue;
					}
				
				if (!TLSON) {
					Send("503 Authentication too weak, use STARTTLS!");
					continue;
					}
				
				Send("334 VXNlcm5hbWU6");
				Login = I.readLine();

				Login = new String(J.Base64Decode(Login.trim()));
				Login = Login.trim();
				if (!Mid.UsrExists(Login)) {

					Send("535 Authentication credentials invalid");
					continue;
					}
				Send("334 UGFzc3dvcmQ6");
				Password = I.readLine();
				Password = new String(J.Base64Decode(Password.trim()));
				Password = Password.trim();
				if (!Mid.UsrLogonSend(Login, Password)) {
					Password=null;
					Send("535 authorization failed");
					continue;
					}
				
				AuthEd=true;
				
				if (Mid.MaxMsgXUserXHour>0 && Login!=null) try {
					HashMap <String,String> cnt = Mid.UsrGetConfig(Login);
					if (cnt!=null) {
						String cd = cnt.get("hcode");
						if (cd.compareTo(Mid.HourCode(Login))==0) {
							if (cnt.containsKey("msgxhour")) {
								int nm = J.parseInt(cnt.get("msgxhour"));
								if (nm>=Mid.MaxMsgXUserXHour) AuthEd=false;
								}
							}
						}
					} catch(Exception E) { 
							Config.EXC(E, Mid.Nick+".UsrCntR `"+Long.toString(Login.hashCode(),36)+"`");
							}
				
				if (AuthEd) Send("235 ok, go ahead"); else throw new PException("@451 Too many messages sent. Your limit is "+Mid.MaxMsgXUserXHour+" messages x hour!");
				
				continue;
			}
			
			if (Tok[0].compareTo("AUTH PLAIN")==0) {
				
				tryLogin++;
				if (tryLogin>3) ExtraSpam(1);
				if (tryLogin>5) {
					ExtraSpam(50);
					falseLogin=true;
					Login=null;
					Send("235 ok, go ahead, it is important to be convinced!"); 
					continue;
					}
				
				if (AuthEd) {
					Send("503 Why!");
					continue;
					}
				if (Tok.length!=2) {
					Send("500 Syntax Error");
					continue;
					}
												
				if (serverMode != SMTPServer.SM_TorServer) {
					Send("503 Can't login to an EXIT/ENTER server.");
					continue;
					}
				
				if (!TLSON) {
					Send("503 Authentication too weak, use STARTTLS!");
					continue;
					}
				
				String s0 = new String(J.Base64Decode(Tok[1]),"UTF-8");
				String[] Tk = s0.split("\\00",3);
				if (Tk.length!=3) {
					Send("500 Syntax Error in AUTH");
					continue;
					}
				Login = Tk[1];
				Password = Tk[2];
				if (!Mid.UsrLogonSend(Login, Password)) {
					Password=null;
					Send("535 authorization failed");
					continue;
					}
				
				AuthEd=true;
				if (Mid.MaxMsgXUserXHour>0) try {
					HashMap <String,String> cnt = Mid.UsrGetConfig(Login);
					if (cnt!=null) {
						String cd = cnt.get("hcode");
						if (cd.compareTo(Mid.HourCode(Login))==0) {
							if (cnt.containsKey("msgxhour")) {
								int nm = J.parseInt(cnt.get("msgxhour"));
								if (nm>=Mid.MaxMsgXUserXHour) AuthEd=false;
								}
							}
						}
					} catch(Exception E) { Config.EXC(E, Mid.Nick+".UsrCntR `"+Long.toString(Login.hashCode(),36)+"`"); }
				if (AuthEd) Send("235 ok, go ahead"); else throw new PException("@451 Too many messages sent. Your limit is "+Mid.MaxMsgXUserXHour+" messages x hour!");
				continue;
			}
			
			if (Tok[0].compareTo("DATA")==0) break;

			if (tle>=2) {
				
				if (Tok[0].compareTo("MAIL FROM")==0) {
						if (MailFrom!=null) throw new PException("@503 Too many MAIL FROM");
						t0= J.getMail(Tok[1].toLowerCase(),Mid.OnlyOnion | Mid.OnlyOnionFrom);
						if (t0==null) {
								Send("503 Invalid address");
								continue;
								} else MailFrom=t0;
						
						if (MailFrom.compareTo("server@"+Mid.Onion)==0) throw new PException(503,"WTF???");
						
						if (!Mid.CanRelay) checkRelay();
						
						String mlp = J.getLocalPart(MailFrom);
						String mdo= J.getDomain(MailFrom);
												
						if (Mid.EnterRoute) {
							if (!mdo.endsWith(".onion") && !Mid.CanEnterExit(MailFrom, true)) throw new PException(501,"Address rejected by the enter policy");
							}
												
						if (Login!=null && mlp.compareTo(Login)!=0) {
								String al = Mid.UsrAlias(mlp);
								if (al==null || al.compareTo(Login)!=0) throw new PException(503,"Access denied!");
								FromAliasUser=Login;
								mlp=al;
								MailFrom = Login+"@"+mdo;
								}
						if (Login==null && mdo.compareTo(Mid.Onion)==0) throw new PException(503,"Logon required!");  //Verificato FIX
						
						if (Config.SMTPVerifySender && mdo.compareTo(Mid.Onion)!=0 &&  !VerifySMTPServer(mdo)) {
								Send("503 Can't verify sender");
								if (Config.Debug) Log("Can't verify `"+mdo+"`\n");
								continue;
								}
						
						if (mdo.compareTo(Mid.Onion)==0) RouteFrom=XRouteLocal; else RouteFrom = XRouteRemote;		
						
						if (mdo.endsWith(".onion")) {
								if (mlp.compareTo("server")==0) TypeFrom = XTypeServer; else 	TypeFrom = XTypeOnion; 
								} else TypeFrom = XTypeInet;
												
						if (RouteFrom==XRouteLocal) {
							if (
										Login==null || 
										Password==null || 
										(Login!=null && Login.compareTo(J.getLocalPart(MailFrom))!=0)
										) {
										Send("530 Authentication required");
										RouteFrom=0;
										continue;
								}
							}
						
						Send("250 OK");
						
						if (HelloMode==2) {
							if (tle>2) {
								String t1="";
								for (int al=2;al<tle;al++) t1+=Tok[al]+" ";
								HashMap <String,String> h1 = J.ParsePair(t1,"\\s+");
								if (h1.containsKey("size")) MessageSize = J.parseInt(h1.get("size"));
								} else MessageSize=-1;
							}
						
						continue;
						}
				
				if (Tok[0].compareTo("TORM VMAT TO")==0) {
						if (TormVmatTo!=null) throw new PException("@503 Too many TORM VMAT TO");
						if (MailTo==null || RouteTo==0 || RouteFrom==0) throw new PException("@503 Invalid command sequence S2");
						String ml = J.getMail(Tok[1], false);
						if (ml==null || ml.endsWith(".onion")) {
							Send("503 Invalid VMAT TO address");
							continue;
							}
						TormVmatTo=ml;
											
						if  (RouteTo == XRouteLocal) {
							//Verifica VMAT =null
							String mlp = J.getLocalPart(MailTo);
							if (Mid.VMAT.recipientCheckRVMAT(mlp, TormVmatTo)) {
								Send("250 OK");
								continue;
								} else {
								Send("503 No such VMAT to this address");
								RouteTo=0;
								TormVmatTo=null;
								continue;
								}
							}
						Send("200 Forwarded ok");
						continue;
						}
				
				if (Tok[0].compareTo("RCPT TO")==0) {
						t0= J.getMail(Tok[1].toLowerCase(),Mid.OnlyOnion | Mid.OnlyOnionTo);
						if (t0==null) {
								Send("503 Invalid address");
								continue;
								} else MailTo=t0;
						
						MultiRCPTTo[MultiRCPTToLength]=t0;
						if (MultiRCPTToLength>0) RouteTo=SrvSMTPSession.XRouteMulti;
						MultiRCPTToLength++;
						if (MultiRCPTToLength>Mid.MultiDeliverMaxRCPTTo) throw new PException("@503 Too many RCPT TO");
						
						if (RouteTo==SrvSMTPSession.XRouteMulti) {
							Send("250 Ok");
							continue;
							}
						
						String mlp = J.getLocalPart(MailTo);
						String mdo= J.getDomain(MailTo);
						String old= MailTo;
						VmatedBy=null;
						
						if (mlp.endsWith(".app")) {
							if (mdo.compareTo(Mid.Onion)==0 || (Mid.EnterRoute && mdo.compareTo(Mid.ExitRouteDomain)==0)) {
								if (Mid.Applications==null || !Mid.Applications.containsKey(mlp)) {
									Send("503 No such application");
									RouteTo=0;
									continue;
									}								
								
								MailTo = t0;
								RouteTo=SrvSMTPSession.XRouteApp;
								Send("250 Ok");
								continue;
								}							
							}
						
						if (Mid.EnterRoute) { 
							boolean vmated=false;
								if (mdo.compareTo(Mid.ExitRouteDomain)==0 && !mlp.endsWith(".onion")) try {
									VirtualMatEntry M=null;
									
									if (mlp.compareTo("server")==0) {
										M = new VirtualMatEntry();
										M.enabled=true;
										M.onionMail="server@"+Mid.Onion;
										}
									
									if (mlp.compareTo("sysop")==0) {
										M = new VirtualMatEntry();
										M.enabled=true;
										M.onionMail="sysop@"+Mid.Onion;	
										}
									
									if (M==null) M = Mid.VMAT.loadVmat(mlp, false);
									
									if (M!=null && M.enabled) {
										MailTo = M.onionMail.replace('@', '.')+"@"+Mid.ExitRouteDomain;
										mlp = J.getLocalPart(MailTo);
										mdo= J.getDomain(MailTo);
										vmated=true;
										} else {
										if (mdo.compareTo(Mid.ExitRouteDomain)==0) {
											Send("503 No such user or VMAT/RVMAT/MAT not resolved");
											RouteTo=0;
											continue;
											}	
										} 
																		
									} catch(Exception E) { Config.EXC(E, "VMAT "+Mid.Nick); }
								
					/*		if (!vmated && mdo.compareTo(Mid.ExitRouteDomain)!=0) {
								Send("503 No such user `"+MailTo+"`"+Mid.ExitRouteDomain);
								RouteTo=0;
								continue;
								} */
							if (vmated) VmatedBy=old;
							}
						
						if (!Mid.CanRelay) checkRelay();
						
						if (Mid.EnterRoute) {
							if (mdo.compareTo(Mid.ExitRouteDomain)==0) {
								MailTo = J.MailInet2Onion(MailTo);
								mlp = J.getLocalPart(MailTo);
								mdo= J.getDomain(MailTo);
								ExitMode=SrvSMTPSession.XE_Entry;
								} else if (mdo.compareTo(Mid.Onion)!=0 && mlp.endsWith(".onion")) {
									Send("503 Can't relay to `"+MailTo+"`");
									RouteTo=0;
									continue;	
								}  							
							}
						
						if (mdo.endsWith(".onion")) {
								if (mlp.compareTo("server")==0) TypeTo = XTypeServer; else 	TypeTo = XTypeOnion; 
								} else TypeTo = XTypeInet;
						
						if (mdo.compareTo(Mid.Onion)==0) {
								if (mlp.compareTo("server")==0) RouteTo = XRouteServer; else RouteTo=XRouteLocal;
								} else RouteTo = XRouteRemote;
						
						if (RouteTo == XRouteLocal) {
							if (mlp.endsWith(".list")) {
								if (!Mid.CheckMailingList(mlp)) {
									RouteTo=0;
									Send("503 No such mailing list");
									}
								RouteTo = XRouteList;
								} else {
								if (!Mid.UsrExists(mlp)) {
									String al = Mid.UsrAlias(mlp);
									if (al==null ||!Mid.UsrExists(al)) {
										Send("503 No such user 2");
										if (Config.Debug) Log("No such user 2 `"+Long.toString(mlp.hashCode(),36)+"`");
										RouteTo=0;
										continue;
										}
									ToAliasUser=mlp;
									mlp=al;
									MailTo = mlp+"@"+mdo;
									}
								}
							}

						Send("250 OK");
						continue;
						}
				}
			
			if (ax!=mtr) Send("503 Invalid command sequence S1"); else throw new PException("@500 Too many wrong operations"); 			
			}
		
	///////// 		-- Transport --
	
	if (falseLogin) throw new PException("@999 FUCK OFF");
			
	if (MailTo==null || MailFrom==null) throw new PException("@503 valid RCPT command must precede DATA");
			
	if (RouteFrom == XRouteLocal) {
		if (Login==null || Password == null) throw new PException("@500 AUTH Required");
		if (Login!=null && Login.compareTo(J.getLocalPart(MailFrom))!=0) throw new PException("@500 Invalid credentials");
		}
	
	if (RouteTo == 0 || RouteFrom==0 ) throw new PException("@554 Transaction failed");
	
	
	if (Mid.Spam.isSpam(J.getLocalPart(MailTo.toLowerCase()), MailFrom.toLowerCase())) {
			Mid.StatSpam++;
			throw new PException("@503 FUCK OFF SPAMMER, YOU ARE BANNED!");
			}
	if (Mid.Spam.isSpam(SrvIdentity.SpamList, MailFrom.toLowerCase())) {
			Mid.StatSpam++;
			throw new PException("@503 FUCK OFF SPAMMER, YOU ARE BANNED BY THE ENTIRE SERVER!"); 
			}
		
	if (Mid.EnterRoute && Config.EnableDNSBL && !KUKIAuth && Login==null && !IPisLocal) try {
			String ips = J.IP2String(RemoteIP);
			int ipst=0;
			boolean chk = true;
			if (Config.IPSpec!=null && Config.IPSpec.containsKey(ips)) ipst = Config.IPSpec.get(ips);
			if ((ipst&Config.IPS_NoDNSBL)!=0) chk=false;
			if ((ipst&Config.IPS_SPAM)!=0) {
					Mid.StatSpam++;
					throw new Exception("@421 FUCK YOU SPAMMER");
					}
			if (Config.LocalNetArea.isInNet(RemoteIP)) chk=false;
			if (Config.DNSBLNoCheck!=null && Config.DNSBLNoCheck.isInNet(RemoteIP)) chk=false;
			if (Config.Debug) Log(chk ? "DNSBL `"+ips+"`" : "NO DNSBL `"+ips+"`");
			if (chk){ 
							String srv =Main.DNSCheck.DNSBL(ips);
							if (srv!=null) {
								Log("SPAM Server Blocked `"+ips+"` by `"+srv+"`");
								Mid.StatSpam++;
								throw new Exception("@421 Your IP `"+ips+"` is listed in DNSBL: "+srv);
								}
							}
			} catch(Exception E) { Config.EXC(E, Mid.Nick+".DNSBL"); }
	
	if (TypeFrom==XTypeInet) Mid.StatMsgInet++; 
			
	if (RouteTo == XRouteLocal)	BeginLocalDelivery();
	if (RouteTo == XRouteServer) BeginServerDelivery();
	if (RouteTo == XRouteRemote) BeginRemoteDelivery();
	if (RouteTo == XRouteList) BeginListDelivery();
	if (RouteTo == XRouteMulti) BeginMultiDelivery();
	if (RouteTo == XRouteApp) BeginAppDelivery();
	
	if (Login!=null && Mid.MaxMsgXUserXHour!=0) try {
		HashMap <String,String> cnt = Mid.UsrGetConfig(Login);
		if (cnt==null) cnt = new HashMap <String,String> ();
		String dc = Mid.HourCode(Login);
		if (cnt.containsKey("hcode")) {
			String md = cnt.get("hcode");
			if (md.compareTo(dc)!=0) {
				cnt.put("hcode", dc);
				cnt.put("msgxhour", "0");
				}
			} else cnt.put("hcode", dc);
		String md = cnt.get("msgxhour");
		if (md==null) md="0";
		int cax = J.parseInt(md)+1;
		cnt.put("msgxhour", Integer.toString(cax));
		Mid.UsrSetConfig(Login,cnt);
		} catch(Exception E) { Config.EXC(E,Mid.Nick+".UsrCntW `"+Long.toString(Login.hashCode(),36)+"`"); }
			
	Tok = GetSMTPCommands(1,new String[] { "QUIT" },null,null);	
	if (Tok==null) throw new PException(500,"Only one session per connection!");
	BeginClose();
	}
	
	private void TORVMATPassage(final HashMap <String,String> Hldr) {
		String err=null;
						
		try {
			String f = Hldr.get("from");
			if (f==null) {
				Log("Missing: From Header!");
				Hldr.put("from", MailFrom);
				return;
				}
			
			f=J.getMailEx(f);
			if (f==null) {
				Log("Invalid from" + (Config.Debug ? " `"+Hldr.get("from")+"`" : ""));
				return;
				}
			
			String vmatsrv=null;
			if (f.compareTo(MailFrom)==0) return; 
			
			if (f.contains(".onion@") || MailFrom.contains(".onion@") || MailTo.startsWith("server@") || MailTo.contains(".app@")) return;
			if (Hldr.containsKey("list-post") || Hldr.containsKey("list-id") || Hldr.containsKey("reply-to")) return;
						
			if (Hldr.containsKey("x-vmat-server")) {
				vmatsrv=Hldr.get("x-vmat-server").trim().toLowerCase();
				}
			
			String fdo = J.getDomain(f);		
			if (fdo!=null && !fdo.endsWith(".onion")) {
				ExitRouteList EL = Mid.GetExitList();
				ExitRouterInfo EI = EL.getByDomain(fdo);
				if (EI==null && Mid.EnterRoute && fdo.compareTo(Mid.ExitRouteDomain)==0) {
					EI = new ExitRouterInfo();
					EI.domain=Mid.ExitRouteDomain;
					EI.onion=Mid.Onion;
					}
				
				if (EI==null && vmatsrv==null) return;
				if (EI!=null && vmatsrv!=null && EI.onion.compareTo(vmatsrv)!=0) err="SRV_ERR1";
				if (EI!=null && vmatsrv==null) err="N_VMAT";
				}
			
			if (vmatsrv!=null && Hldr.containsKey("x-vmat-sign")) {
				if (Config.Debug) Log("Verify SIGN"); 
				String rsa = Hldr.get("x-vmat-sign");
				rsa=rsa.replace(" ", "");
				rsa=rsa.trim();
				byte[] sig = J.Base64Decode(rsa);
				rsa=null;
				if (sig.length>0) {
					PublicKey pk = null;
					if (vmatsrv.compareTo(Mid.Onion)==0) pk=Mid.SPK; else try {
						pk = Mid.LoadRSAKeys(vmatsrv);
						} catch(Exception EK) {
							Log("Error loading Key for `"+vmatsrv+"` "+EK.getMessage());
							if (Config.Debug) EK.printStackTrace();
						}
					if (pk!=null) {
						if (Config.Debug) Log("Verify SIGN:RSA");
						if (Mid.VMAT.VirtualRVMATVerify(f, MailFrom, sig, pk)) {
							Hldr.put("x-tor-vmat-verified", "sign");
							return;
							} else {
								err="FALSE_VMAT";
								if (!Hldr.containsKey("subject")) Hldr.put("subject", "");
								String sub = Hldr.get("subject");
								if (sub==null) sub="";
								sub = "***"+err+"*** "+sub;
								Hldr.put("x-tor-vmat-error", err);
								Hldr.put("subject", sub);
								Log("False VMAT in tor by `"+Long.toString(MailFrom.hashCode(),36)+"`");
								return;
							}
						} else if (Config.Debug) Log("TormPassage: No public key for `"+vmatsrv+"`");  
					}
				}
			
			VirtualRVMATEntry vm = Mid.LookupVMAT(f, false);
			
			if (vm!=null) {
				if (vm.mail.compareTo(f)!=0) err="FALSE_SENDER1";
				if (vm.onionMail.compareTo(MailFrom)!=0) err="FALSE_SENDER2";
				} ///else err="NO_VMAT_ADDR";
			
		} catch(Exception E) {
			err="NOT_VER";
			String ms = E.getMessage();
			if (ms==null || ms.startsWith("@")) ms="500 GenericError"; else ms=ms.substring(1);
			Hldr.put("x-vmat-error", ms);
			}
		
		if (err!=null) {
			int bits=3;
			if (Mid.VMATErrorPolicy.containsKey(err)) bits =  Mid.VMATErrorPolicy.get(err); else if (Mid.VMATErrorPolicy.containsKey("*")) Mid.VMATErrorPolicy.get("*");
					
			if (!Hldr.containsKey("subject")) Hldr.put("subject", "");
			String sub = Hldr.get("subject");
			if (sub==null) sub="";
			if (bits>2) 
					sub = "***"+err+"*** "+sub; 
					else if (bits>1) 
					sub ="** "+sub;
			
			Hldr.put("x-tor-vmat-error", err);
			Hldr.put("subject", sub);
			} else Hldr.put("x-tor-vmat-verified", "lookup");
		
	}
	
	private HashMap<String,String> ParseHeaders(BufferedReader I) throws Exception {
		String in="";
		for (int ax=0;ax<MaxHeaderLine;ax++) {
			String li = I.readLine();
			if (li==null) throw new PException(421,"Connection lost");
			if (li.compareTo(".")==0) throw new PException(500,"Invalid headers");
			MessageBytes+=li.length()+2;
			li=li.replace("\r", "");
			li=li.replace("\n", "");
			in+=li+"\n";
			if (li.length()==0) return J.ParseHeaders(in.split("\\n"));
		}
		throw new PException("@421 Too many mail headers");
	} 	
		
	private HashMap<String,String> BeginDataHeaders() throws Exception {
		Send("354 Enter message, ending with \".\" on a line by itself");
		HashMap<String,String> Hldr = ParseHeaders(I);
		Hldr = J.FilterHeader(Hldr);
		Hldr.put("received", "from "+J.IPFilter(HelloData)+" by "+Mid.Onion+" ("+Mid.Nick+") [0.0.0.0] "+Mid.TimeString());
		Hldr.put("x-hellotype", HelloMode==1 ? "HELO" : "EHLO");
		Hldr.put("sender", MailFrom);
		Hldr.put("envelope-to", MailTo);
		Hldr.put("delivery-date", Mid.TimeString());
		if (KUKIAuth) Hldr.put("tkim-server-auth", HelloData);
		if (!Hldr.containsKey("date")) Hldr.put("date", Mid.TimeString());
		if (!Hldr.containsKey("delivery-date")) Hldr.put("delivery-date", Mid.TimeString());
		return Hldr;
	}
	
	private void BeginAppDelivery() throws Exception {
		String alpf = J.getLocalPart(MailFrom);
		String aldf = J.getDomain(MailFrom);
		String alpt = J.getLocalPart(MailTo);
		String aldt = J.getDomain(MailTo);
		
		if (aldt.compareTo(Mid.Onion)!=0) throw new PException("@550 Unknown application");
		Application a = Mid.Applications.get(alpt);
		if (a==null) throw new PException("@550 Unknown application");
		
		if ((a.accessMode&Application.ACCESS_SYSOP)!=0) {
			if (aldf.compareTo(Mid.Onion)!=0 || alpf.compareTo("sysop")!=0 || Login==null && Login.compareTo("sysop")!=0 ) throw new Exception("@550 Access denied (R1)");
			}
		
		if ((a.accessMode&Application.ACCESS_SYSOP)!=0) {
			if (aldf.compareTo(Mid.Onion)!=0 || Login==null && Login.compareTo(alpf)!=0 ) throw new Exception("@550 Access denied (R2)");
			}
		
		if ((a.accessMode&Application.ACCESS_TOR)!=0 && !IPisLocal) throw new Exception("@550 Access denied (R3)");
		if ((a.accessMode&Application.ACCESS_INET)!=0 && IPisLocal) throw new Exception("@550 Access denied (R4)");
		
		Send("354 Enter message, ending with \".\" on a line by itself");
		HashMap<String,String> Hldr = ParseHeaders(I);
		
		String msg="";
		
		while(true) {
			String li = I.readLine();
			if (li==null) break;
			li=li.trim();
			if (MessageBytes>256000) throw new PException("@452 Message too long");
			if (isOld()) throw new PException("@452 Timeout");
			MessageBytes+=li.length()+2;
			if (li.compareTo(".")==0) break;
			msg+=li+"\n";
			}
		
		if (isDSN(Hldr) || isList(Hldr)) {
			Log("Ignore Message: `"+Long.toString(MailFrom.hashCode(),36)+"` to app `"+MailTo+"`");
			Send("250 Id=Ignore");
			return;
			}
		
		String ctyp = "7bit";
		if (Hldr.containsKey("content-transfer-encoding")) ctyp=Hldr.get("content-transfer-encoding").toLowerCase();
		if (ctyp.compareTo("quoted-printable")==0) msg=J.MQuotedDecode(msg);
		if (ctyp.compareTo("base64")==0) msg=J.MBase64Decode(msg);
		
		a.Run(Mid, MailFrom, Hldr, msg);
		Send("250 OK id="+J.RandomString(6)+"-"+J.RandomString(6)+"-"+J.RandomString(2));
		}
	
	private void BeginMultiDelivery() throws Exception {
		String alpf = J.getLocalPart(MailFrom);
		String aldf = J.getDomain(MailFrom);
		String alp;
		String ald;
				
		Mid.StatMsgIn++;
		String st="";
		boolean allForMe=true;
		
		if (Mid.EnterRoute) for (int ax=0;ax<MultiRCPTToLength;ax++) { ///Inet>Onion MAT conversion.
					alp = J.getLocalPart(MultiRCPTTo[ax]);
					ald = J.getDomain(MultiRCPTTo[ax]);
					
					if (Mid.EnterRoute && ald.compareTo(Mid.ExitRouteDomain)==0 && alp.endsWith(".onion")) {
						MultiRCPTTo[ax]=J.MailInet2Onion(MultiRCPTTo[ax]);
						alp = J.getLocalPart(MultiRCPTTo[ax]);
						ald = J.getDomain(MultiRCPTTo[ax]);
						} 
					
					if (ald.compareTo(Mid.Onion)!=0 && ald.compareTo(Mid.ExitRouteDomain)!=0) allForMe=false; 
					
		} else for (int ax=0;ax<MultiRCPTToLength;ax++) { 
					alp = J.getLocalPart(MultiRCPTTo[ax]);
					if (alp.endsWith(".onion")) {
							MultiRCPTTo[ax]=J.MailInet2Onion(MultiRCPTTo[ax]);
							alp = J.getLocalPart(MultiRCPTTo[ax]);
							}
					ald = J.getDomain(MultiRCPTTo[ax]);
					if (ald.compareTo(Mid.Onion)!=0) allForMe=false;
					}
		
		st="\n";
		for (int ax=0;ax<MultiRCPTToLength;ax++) {
				alp = J.getLocalPart(MultiRCPTTo[ax]);
				if (
							alp.compareTo("server")==0	||
							alp.endsWith(".onion")			||
							alp.endsWith(".list")				||
							alp.endsWith(".sys") 				||
							alp.endsWith(".app") 				)  throw new PException("@550 You can not include servers, applications, mailing list addresses in messages with multiple recipients but only normal addresses.");
				
				if (!st.contains("\n"+MultiRCPTTo[ax]+"\n")) st+=MultiRCPTTo[ax]+"\n";			
				}
		
		st=st.trim();
		String stA[] = st.split("\\n+");
		if (stA.length==1) throw new PException("@550 Invalid multi delivery message.");
				
		boolean fromMy=false;
		if (Login!=null) {
			if (Login.compareTo(alpf)!=0) throw new PException("@550 Invalid user ceredentials.");
			fromMy=true;
			} else if (aldf.compareTo(Mid.Onion)==0 || aldf.compareTo(Mid.ExitRouteDomain)==0) throw new PException("@550 Authorization required."); 
		
		
		if (!fromMy) {
			//Inet > Onion *
			if (Mid.EnterRoute) { 
				if (Mid.ExitNotMultipleServerDelivery && allForMe==false) throw new PException("@550 On this server is forbidden sending mails with multiple recipients on other servers.");
				} else {
					if (allForMe==false) throw new PException("@550 Only authenticated local users can send messages to multiple recipients with other server delivery.");
				} 
			} // else  Local_Onion > *
								
		int cx = Main.MultiTthread.length;
		int fi=-1;
		long tcr = System.currentTimeMillis();
		
		for (int ax=0;ax<cx;ax++) {
			if (Main.MultiTthread[ax]==null) { fi=ax; break; }
			if ((tcr - Main.MultiTthread[ax].Started)>Config.ListThreadsTTL) {
				fi=ax;
				Main.MultiTthread[ax].End();
				}
			if (Main.MultiTthread[ax].running==false) { fi=ax; break; }
			if (!Main.MultiTthread[ax].isAlive()) { fi=ax; break; } 
		}
		if (fi==-1) throw new PException(500,"Server too busy, try later!");
		
		Send("354 Enter message, ending with \".\" on a line by itself");
		
		HashMap<String,String> Hldr = ParseHeaders(I);
		
		if (isDSN(Hldr)) throw new PException("@550 DSN Ignored message");
		
		Hldr = J.FilterHeader(Hldr);
		Hldr.put("x-y-count", Long.toString(Mid.Time(),36)+"-"+Long.toString(MailFrom.hashCode(),36));
		Hldr.put("date",Mid.TimeString());
		if (TormVmatTo==null) TORVMATPassage(Hldr);
		
		st=st.trim();
		if (Main.MultiTthread[fi]!=null && Main.MultiTthread[fi].running) Main.MultiTthread[fi].End();
		MultiDeliverThread MT = new MultiDeliverThread(Mid,MailFrom,stA,Hldr,I);
		Main.MultiTthread[fi]=MT;
		Send("250 OK id="+J.RandomString(6)+"-"+J.RandomString(6)+"-"+J.RandomString(2));
		}
	
	private void BeginListDelivery() throws Exception {
		Mid.StatMsgIn++;
		
		int cx = Main.ListThreads.length;
		int fi=-1;
		long tcr = System.currentTimeMillis();
		
		for (int ax=0;ax<cx;ax++) {
			if (Main.ListThreads[ax]==null) { fi=ax; break; }
			if ((tcr - Main.ListThreads[ax].Started)>Config.ListThreadsTTL) {
				fi=ax;
				Main.ListThreads[ax].End();
				}
			if (Main.ListThreads[ax].running==false) { fi=ax; break; }
			if (!Main.ListThreads[ax].isAlive()) { fi=ax; break; } 
		}
		if (fi==-1) throw new PException(500,"List too busy, try later!");
		
		String lst = J.getLocalPart(MailTo);
		MailingList M = Mid.OpenMailingList(lst);
		MLUserInfo U = M.GetUsr(MailFrom);
		if (U==null) {
			M.Close();
			throw new PException(503,"You are not subscribed to this list");
			}
		HashMap<String,String> Hldr = BeginDataHeaders();
		
		if (isDSN(Hldr)) throw new PException("@550 Ignored DSN Message");
		Hldr = J.FilterHeader(Hldr);
		Hldr.put("x-y-count", Long.toString(Mid.Time(),36)+"-"+Long.toString(MailFrom.hashCode(),36));
		if (TormVmatTo==null) TORVMATPassage(Hldr);
		
		M.ReceiveMessage(I);
		ListThread LT = M.SendMessage(MailFrom, Hldr);
		if (Main.ListThreads[fi]!=null && Main.ListThreads[fi].running) Main.ListThreads[fi].End();
		Main.ListThreads[fi]=LT;
		Send("250 OK id="+J.RandomString(6)+"-"+J.RandomString(6)+"-"+J.RandomString(2));
	}
	
	private void BeginLocalDelivery() throws Exception {
		Mid.StatMsgIn++;
		
		String usr = J.getLocalPart(MailTo);
		MailBox M = Mid.UsrOpenW(Config,usr);
		int mi = M.Index.GetFree();
		if (mi==-1) {
			Send("452  Mailbox full!");
			M.Close();
			return;
			}
		
		Message MS = M.MsgCreate();
		HashMap<String,String> Hldr = BeginDataHeaders();
		if (TormVmatTo==null) TORVMATPassage(Hldr);
		
		if (ToAliasUser!=null) {
			Hldr.put("envelope-to", ToAliasUser);
			Hldr.put("x-alias", ToAliasUser);
			}		
		MS.SetHeaders(Hldr);
		while(true) {
			String li = I.readLine();
		
			MessageBytes+=li.length()+2;
			if (MessageBytes>Mid.MaxMsgSize) {
				MS.Close();
				throw new PException("@452 Message too big");
				}
			if (li.compareTo(".")==0) break;
			MS.WriteLn(li);
			}
		MS.End();
		
		Send("250 OK id="+J.RandomString(6)+"-"+J.RandomString(6)+"-"+J.RandomString(2));
		
	}
	
	private void BeginRemoteDelivery() throws Exception {
		HashMap <String,String> H = new HashMap <String,String>();
		try {
			Mid.SendRemoteSession(MailTo, MailFrom, H, I, O,TormVmatTo); 
			} catch(Exception E) {
				if (
						Mid.hasQueue 						&& 
						E instanceof RetryUevent 	&&
						TormVmatTo==null				&&
						!MailTo.endsWith(".onion")		) {
					
					RetryUevent rt = (RetryUevent) E;
					Log("Message queue: "+rt.SMTPError);
					O.write("354 Enter message, ending with \".\" on a line by itself\r\n".getBytes());
					HashMap <String,String> rh = ParseHeaders(I);
					rh = J.FilterHeader(rh);
					rh.put("x-queued", Mid.TimeString());
					rh.put("x-remote-grey", rt.SMTPError);
					Mid.Queue.Enqueue(MailFrom, MailTo, TormVmatTo, rh, I);
					
					Send("250 OK id="+J.RandomString(6)+"-"+J.RandomString(6)+"-"+J.RandomString(2));
					
				} else throw E;
			} 
		}
			
	private boolean VerifySMTPServer(String Server) {
		if (Config.Debug) Log("Verify `"+Server+"`\n");
		
		Server=Server.toLowerCase();
		boolean isTor=Server.endsWith(".onion");
		
		try { 
				if (Mid.Spam!=null && Mid.Spam.isSpam(SrvIdentity.SpamList, "*@"+Server)) { //TODO Verificat
						Log(Config.GLOG_Event,"SpamServer `"+Server+"`");
						Mid.StatSpam++;
						return false; 
						}// server is spam
		} catch(Exception I) { Config.EXC(I, Mid.Nick+".Spam(`"+Server+"`)"); 	}
		
		if (KUKIAuth) return true;
		
		MXRecord[] MX=null;
		
		if (!isTor) {
			if (Mid.EnterRoute) {
				if (Config.Debug) Log("NsLookup `"+Server+"`");
				MX = Main.DNSCheck.getMX(Server);
				if (MX==null || MX.length==0) return false;
				} else try {
					if (Config.Debug) Log("RemoteMX `"+Server+"`");
					return Mid.VerifySMTPInetTest(Server);
				} catch(Exception E) {
					Config.EXC(E, Mid.Nick+".RemoteMX(`"+Server+"`)"); 
				}
			return true;
			}
		
		try { if (Mid.SSLHasHash(Server)) return true; } catch(Exception E) { Config.EXC(E, Mid.Nick+".VerifySRV"); }
				
		if (!Config.VerfySenderViaSimulation) return true;
		if (!Server.endsWith(".onion")) return true;

		int i = Mid.RMXCacheGet("*"+Server);
		if (i!=0) {
			if (Config.Debug) Log("VerSimSend by RMX cache");
			return (i&1)!=0;
			}
		
		return VerifyViaSimulationSender(Server);
			
	}
	
	public boolean VerifyViaSimulationSender(String Server) {
	
		final boolean debug= Config.Debug;
		try {
			SrvAction A = new SrvAction(Mid,Server,"VerSimSend") {
				public void OnSession(BufferedReader RI,OutputStream RO) throws Exception {
					this.Mid.RMXCacheSet("*"+Server, true);
					if (debug) this.Mid.Log("Server `"+this.Server+"` OK");
					}
				};
			A.DoInSSL=false;
			A.DoInTKIM=false;
			A.ForceSSL=false;
			A.RES = (Object[]) new Boolean[] { false };
			A.Do();
			return true;
			} catch(Exception VE) {
				String msg = VE.getMessage();
				if (Config.Debug) Log("VerSimSend: "+VE.getMessage());
				if (msg==null) msg="NULL";
				if (msg.startsWith("@")) Log("Verify `"+Server+"` "+msg.substring(1)); else Log("Verify `"+Server+"` "+msg);
				}
		
		Mid.RMXCacheSet("*"+Server, false);
		return false;
	}
	
	public static SMTPReply RemoteCmd(OutputStream ro,BufferedReader ri,String send) throws Exception {
		ro.write((send+"\r\n").getBytes());
		return new SMTPReply(ri);
	}
	
	
	private void BeginServerDelivery() throws Exception {
			
		Send("354 Enter message, ending with \".\" on a line by itself");
		HashMap<String,String> Hldr = ParseHeaders(I);
		
		String msg="";
		
		if (!Hldr.containsKey("subject")) throw new PException("@500 Subject required");
		
		//Ignore RE: RE: ....
		
		String st=Hldr.get("subject");
		String[] dv = st.split("\\:");
		int cx=dv.length;
		int bx=-1;
		for (int ax=0;ax<cx;ax++) {
			dv[ax]=dv[ax].trim().toUpperCase();
			if (dv[ax].compareTo("RE")==0 && dv.length>=(ax+1)) bx=ax+1;
			}
		
		if (bx!=-1 && bx==cx-1) Hldr.put("subject", dv[bx].trim());
		
		
		while(true) {
			String li = I.readLine();
			if (li==null) break;
			li=li.trim();
			if (MessageBytes>256000) throw new PException("@452 Message too long");
			if (isOld()) throw new PException("@452 Timeout");
			MessageBytes+=li.length()+2;
			if (li.compareTo(".")==0) break;
			msg+=li+"\n";
			}
		
		String ctyp = "7bit";
		if (Hldr.containsKey("content-transfer-encoding")) ctyp=Hldr.get("content-transfer-encoding").toLowerCase();
		if (ctyp.compareTo("quoted-printable")==0) msg=J.MQuotedDecode(msg);
		if (ctyp.compareTo("base64")==0) msg=J.MBase64Decode(msg);
		
		//TODO Multipart Boundary
		
		st=Hldr.get("subject");
		if (st.compareToIgnoreCase("PGP")==0) try {
			String mykey = Mid.UserGetPGPKey(Const.SRV_PRIV);
			if (mykey==null) throw new PException("@550 PGP Encrypted sessions are not supported");
			Log("Begin PGP ServerAction");
			PGPSession=true;
			msg=J.ParsePGPMessage(msg);
			msg=msg.trim();
			
			byte[] msb = PGP.decrypt(msg.getBytes(),(InputStream) new ByteArrayInputStream( mykey.getBytes()) , Mid.GetPassPhrase().toCharArray());
			msg=new String(msb);
			msb=null;
			mykey=null;
			String[] li = msg.split("\\n");
			st=li[0].trim();
			msg="";
			cx=li.length;
			for (int ax=1;ax<cx;ax++) msg+=li[ax]+"\n";
			Hldr.put("subject", st.trim());
			} catch(Exception E) {
				String ms = E.getMessage()+"";
				if (ms.startsWith("@")) {
					ms=ms.substring(1);
					throw new PException(550,ms);
					}
				Config.EXC(E, "PGP(`"+Mid.Nick+"`)");
				throw new PException(550,"PGP Error");
			}
		
	
		if (isDSN(Hldr) || isList(Hldr)) {
			Log("Ignore Message: `"+Long.toString(MailFrom.hashCode(),36)+"` to server");
			Send("250 Id=Ignore");
			return;
			}
		
		
		ServerAction(MailFrom,Hldr,msg.trim());		
	}
	
	private boolean isDSN(HashMap <String,String> Hldr) throws Exception {
		
		boolean drop=false;
		if (
				Hldr.containsKey("x-failed-recipients") ||
				Hldr.containsKey("auto-submitted") ) drop=true; 
		
		if (Hldr.containsKey("content-type")) {
			String t8 = Hldr.get("content-type");
			t8=t8.trim().toLowerCase();
			t8=t8.replace(" ", "");
			if (t8.contains("report-type=delivery-status")) drop=true;
			if (t8.contains("report-type=disposition-notification")) drop=true;
			
			}
		return drop;
	}

	private boolean isList(HashMap <String,String> Hldr) throws Exception {
		String lst="|mailing-list|list-id|list-post|list-help|list-unsubscribe|list-subscribe|";
		for (String k:Hldr.keySet()) if (lst.contains("|"+k+"|")) return true;
		return false;
	}
	
	private void SA_MYKEY(String user,String msg) throws Exception {
		if (user.compareTo("server")==0 || user.compareTo(Const.SRV_PRIV)==0) throw new PException(500,"KEY Operation not permitted");

		if (Config.PGPStrictKeys && !J.PGPVerifyKey(msg, user)) throw new PException(550,"The key is not for `"+user+"`");
		
		Mid.UserSetPGPKey(msg, user,false);
		msg = msg.replace("\r\n", "\n");
		msg = Mid.UserGetPGPKey("server");
		msg = Mid.PGPSpoofNSA(msg,false);
		msg = msg.replace("\r\n", "\n");
		if (msg!=null) {
			HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, user);
			H.put("subject", Mid.Nick+"'s PGP Public Key");
			Mid.SendMessage(user, H, msg);
			}
		
		Send("250 Id=Nothing");
		
	}
	
	private void SA_VMATLookup(String MailFrom,String[] Tok) throws Exception {
		if (Tok.length<2) throw new PException("@550 Syntax error");
		String addr = J.getMail(Tok[1], false);
		if (addr==null) throw new PException("@550 Invalid mail address");
		if (addr.endsWith(".onion")) throw new PException("@550 Use a VMAT address, don't use onion address.");
		
		VirtualRVMATEntry VM = Mid.VMAT.SenderVirtualRVMATEntryLoad(addr);
		
		String msg="";
		HashMap <String,String> Hldr = ClassicHeaders("server@"+Mid.Onion, MailFrom);
				Hldr.put("subject", "Re: RVMAT Lookup");
				if (VM==null) {
					msg="No RVMAT record to `"+addr+"`\n\t"+Mid.Nick+"\n";
					
					} else {
					msg=
							"RVMAT record to `"+addr+"`\n\t"+
							"Mail:     \t"+VM.mail+"\n\t"+
							"OnionMail:\t"+VM.onionMail+"\n\t"+
							"Server:   \t"+VM.server+"\n\n " +Mid.Nick+"\n";
					}
				if (PGPSession) msg=Mid.SrvPGPMessage(MailFrom,Hldr,msg);	
				Mid.SendMessage(MailFrom, Hldr, msg);	 
				Send("250 Id=nothing");
		}
	
	private void ServerAction(String MailFrom,HashMap<String,String> Hldr,String msg) throws Exception {
		
		if (!MailFrom.startsWith("sysop@") && J.isReserved(MailFrom, 0,true)) throw new PException(500,"SA6001 Operation not permitted");
		
		String[] Tok = GetFuckedTokens(Hldr.get("subject").trim(),new String[] {
				"NETWORK","NEWUSER TO", "NEWUSER", "IDENT","REBOUND HEADER", "LIST","RULEZ", "SET IS SPAM","SPAM LIST",
				"EXIT","SETTINGS","SHOW W","STAT","PUSH", "SPAM","MYKEY","VMAT LOOKUP","VMAT",
				"VOUCHER LIST","VOUCHER DELETE","VOUCHER","CONFIG"
				});
		if (Tok==null) throw new PException(503,"Unknown server action `"+Hldr.get("subject").trim()+"`");
		
		//////////////// All User Actions ////////////////////////////////
	
		int pa = Tok.length;
		
		if (Tok[0].compareTo("REBOUND HEADER")==0) { 
				SA_REBHEAD(MailFrom,Hldr);
				return;
				}
		
		Hldr = J.FilterHeader(Hldr);

		if (Tok[0].compareTo("NEWUSER")==0) {
				if (pa<2) throw new PException("@550 Parameter number error in subject");
				SA_NEWUSER(Tok,msg,false);
				return;
				}
		
		if (Tok[0].compareTo("IDENT")==0) {
				if (pa!=1) throw new PException("@550 Parameter number error in subject");
				SA_IDENT(MailFrom);
				return;
				}
				
		if (Tok[0].compareTo("CONFIG")==0) {
				if (pa!=1) throw new PException("@550 Parameter number error in subject");
				SA_CONFIG(MailFrom);
				return;
				}
		
		if (Tok[0].compareTo("RULEZ")==0) {
				if (pa!=1) throw new PException("@550 Parameter number error in subject");
				SA_RULEZ(MailFrom,null);
				return;
				}
		
		if (Tok[0].compareTo("LIST")==0) {
				SA_List(Tok,MailFrom,Hldr,msg);
				return;
				}
					
		if (Tok[0].compareTo("SHOW W")==0) {
				Hldr = ClassicHeaders("server@"+Mid.Onion, MailFrom);
				Hldr.put("subject", "OnionMail "+Main.getVersion()+" license info");
				msg="";
				InputStream i = Main.class.getResourceAsStream("/resources/show-w");
				BufferedReader h = J.getLineReader(i);
				
				while(true) try {
					String li=h.readLine();
					if (li==null) break;
					li=li.replace("\r", "");
					msg+=li+"\n";
					} catch(Exception E) { Config.EXC(E, "SHOW W");  break; }
					try {		h.close(); } catch(Exception I) {}
					try {		i.close(); } catch(Exception I) {}
				
				msg=msg.replace("%%VER%%", Main.getVersion());
				if (PGPSession) msg=Mid.SrvPGPMessage(MailFrom,Hldr,msg);	
				Mid.SendMessage(MailFrom, Hldr, msg);	 
				Send("250 Id=nothing");
				return;
				}
		
		if (Tok[0].compareTo("STAT")==0) {
			Hldr = ClassicHeaders("server@"+Mid.Onion, MailFrom);
				Hldr.put("subject", "OnionMail Statistics");
				msg="OnionMail Statistics\n"+
				"\nMessages-In: "+Mid.StatMsgIn +
					"\nMessages-Out: "+Mid.StatMsgOut +
					"\nMessages-Inet: "+Mid.StatMsgInet +
					"\nPOP3-Sessions: "+Mid.StatPop3 +
					"\nSpam-Blocked: "+Mid.StatSpam +
					"\nErrors: "+Mid.StatError +
					"\nExceptions: "+Mid.StatException +
					"\nUpTime: "+Mid.StatHcount+"\n";
			if (PGPSession) msg=Mid.SrvPGPMessage(MailFrom,Hldr,msg);	
			Mid.SendMessage(MailFrom, Hldr, msg);	 
			Send("250 Id=nothing");
			return;
			}
		
		
		
		
		//////////////////////////// Local User Actions ////////////////////////////////
		ChechkLocalSOper(MailFrom);
				
		if (Tok[0].compareTo("EXIT")==0) SA_Exit(Tok,MailFrom,msg);
		if (Tok[0].compareTo("SET IS SPAM")==0 && pa==2) SA_AddSpam(Tok[1].trim().toLowerCase(),MailFrom);
		if (Tok[0].compareTo("SPAM LIST")==0) SA_SPAMLIST(MailFrom,Tok);
		if (Tok[0].compareTo("SPAM")==0) SA_SPAMOPT(MailFrom,Tok,msg);	
		if (Tok[0].compareTo("SETTINGS")==0) SA_SETTINGS(MailFrom,Tok,msg);
		if (Tok[0].compareTo("MYKEY")==0) SA_MYKEY(MailFrom,msg);

		if (Tok[0].compareTo("VMAT")==0) {
				SA_VMAT(MailFrom,msg);
				return;
				}
						
		String loc = J.getLocalPart(MailFrom);
		if (loc.compareTo("sysop")!=0) throw new PException("@550 Access denied to SysOp command");
		///////////////////////// SYSOP USER /////////////////////////////
		
		if (Tok[0].compareTo("PUSH")==0) {
				String rs = Mid.SvcDoRemotePushArray(msg);
				HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, MailFrom);
				H.put("subject", "Remote PUSH operations");
				rs=rs.replace("\n", "\r\n");
				rs=rs.trim();
				rs+="\r\n";
				if (PGPSession) rs=Mid.SrvPGPMessage(MailFrom,H,rs);	
				Mid.SendMessage(MailFrom, H, rs);
				Send("250 Id=nothing");
				return;
			}	
				
		if (Tok[0].compareTo("VMAT LOOKUP")==0) {
				SA_VMATLookup(MailFrom,Tok);
				return;
				}
		
		if (Tok[0].compareTo("NETWORK")==0) {
			HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, MailFrom);
			H.put("subject", "Server network info");
			String re=Mid.Nick+"`s network info:\n";
			re+="Onion:\t"+Mid.Onion+"\n";
			re+="Is Exit:\t"+(Mid.EnterRoute ? "YES":"NO")+"\n";
			if (Mid.EnterRoute) re+="Domain:\t"+Mid.ExitRouteDomain+"\n";
			
			re+="\n"+Mid.Nick+"`s firends:\n";
			String[] FriendServer = Mid.RequildFriendsList();
			re+=J.Implode("\n", FriendServer);
			re+="\n\nOnionMail Enter/Exit servers:\n";
			ExitRouteList EL  = Mid.GetExitList();
			ExitRouterInfo[] al = EL.getAll();
			int cx = al.length;
			if (cx==0) re+="N/A\n"; else for (int ax=0;ax<cx;ax++) re+=al[ax].toInfoString()+"\n";

			al=ExitRouteList.queryFLTArray(al,ExitRouteList.FLT_DOWN);
			re+="\nServers down:\n";
			cx = al.length;
			if (cx==0) re+="N/A\n"; else for (int ax=0;ax<cx;ax++) re+=al[ax].toInfoString()+"\n";
			
			ExitRouterInfo r = EL.selectBestExit();
			re+="\nBest Exit:\n\t"+ ((r!=null) ? r.toInfoString() : "N/A");
					
			re+="\n"+Mid.Nick+"\n";
			
			Mid.SendMessage(MailFrom, H, re);
			Send("250 Id=nothing");
			return;
			}
		
		if (Tok[0].compareTo("VOUCHER")==0) {
			HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, MailFrom);
			int ts=Mid.VoucherLength;
			
			if (Tok.length>1) {
				Log("TOK "+Tok[1]);
				if (Tok[1].contains("M") || Tok[1].contains("m")) ts=Config.parseIntS(Tok[1]);
				if (Tok[1].contains("H") || Tok[1].contains("h")) ts=Config.parseIntS(Tok[1])*60;
				if (Tok[1].contains("D") || Tok[1].contains("d")) ts=Config.parseIntS(Tok[1])*1440;
				if (Tok[1].contains("O") || Tok[1].contains("o")) ts=Config.parseIntS(Tok[1])*43200;
				}
			String rs="Voucher:\n"+Mid.VoucherCreate(ts)+"\n";
				if (ts!=0) {
					rs+="Expire date: "+J.TimeStandard(System.currentTimeMillis()+Config.TimeSpoof, Config.TimeSpoofFus);
					rs+="\nMinute Length: "+ts+"\n\t"+Mid.Nick;
					}
				H.put("subject", "New Voucher");
				rs=rs.replace("\n", "\r\n");
				rs=rs.trim();
				rs+="\r\n";
				if (PGPSession) rs=Mid.SrvPGPMessage(MailFrom,H,rs);	
				Mid.SendMessage(MailFrom, H, rs);
				Send("250 Id=nothing");
				return;
				}
	
			if (Tok[0].compareTo("VOUCHER DELETE")==0 && Tok.length>1) {
				Mid.VoucherTest(Tok[1], true);
				
				String rs="Voucher:\n"+Tok[1]+"\nIs now DISABLED\n\t"+Mid.Nick;
				HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, MailFrom);
				H.put("subject", "Voucher Deleted");
				rs=rs.replace("\n", "\r\n");
				rs=rs.trim();
				rs+="\r\n";
				if (PGPSession) rs=Mid.SrvPGPMessage(MailFrom,H,rs);	
				Mid.SendMessage(MailFrom, H, rs);
				Send("250 Id=nothing");
				return;
				}
			
			if (Tok[0].compareTo("NEWUSER TO")==0) {
				if (pa<3) throw new PException("@550 Parameter number error in subject");
				MailFrom = J.getMail(Tok[2], false);
				if (MailFrom==null) throw new Exception("@550 Invalid mail address `"+Tok[2]+"`");
				SA_NEWUSER(new String[] {"NEWUSER" , Tok[1]} ,msg,true);
				return;
				}
			
			if (Tok[0].compareTo("VOUCHER LIST")==0) {
				boolean ce=new File(Mid.LogVoucherTo).exists();
				String rs;
				if (Mid.LogVoucherTo==null) rs="VOUCHER LIST UNAVAILABLE:\n\tEnvable VoucherListTo paremeter in config and restart OnionMail"; else {
					if (!ce) {
						rs = "<<LIST EMPTY>>";
						} else try {
							byte[] b = Stdio.file_get_bytes(Mid.LogVoucherTo);
							rs = new String(b);
							b=null;
							rs=rs.replace("\r\n", "\n");
							rs=rs.trim();
							} catch(Exception E) {
							rs = "<<ERROR>>";
							Config.EXC(E, Mid.Nick+".VoucherList");
							}
					rs="Voucher list:\n"+rs+"\n\n\t"+Mid.Nick;
					} 
				
				HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, MailFrom);
				H.put("subject", "Voucher List");
				rs=rs.replace("\n", "\r\n");
				rs=rs.trim();
				rs+="\r\n";
				if (PGPSession) rs=Mid.SrvPGPMessage(MailFrom,H,rs);	
				Mid.SendMessage(MailFrom, H, rs);
				if (ce && Tok.length>1 && Tok[1].compareToIgnoreCase("DELETE")==0) J.Wipe(Mid.LogVoucherTo, Config.MailWipeFast);
				Send("250 Id=nothing");
				return;
				}
		//// Only when modify code throw new PException("@550 Extended command not available");
	}

	private void SA_NEWUSER(String[] tok,String msg,boolean overridePermissions) throws Exception {
		String vc="";
		
		boolean vca=overridePermissions;
		if (tok.length>2) {
			vc = tok[2].trim();
			if (Mid.VoucherTest(vc, true)==1) vca=true;
			}
		
		if (!vca) Mid.CanAndCountCreateNewUser();
		
		if (tok[1].compareTo("ANONYMOUS")==0) tok[1]=J.RandomString(8); else {
			tok[1]=tok[1].trim().toLowerCase();
			if (!tok[1].matches("[a-z0-9\\_\\-\\.]{3,40}")) throw new PException("@550 Invalid username in the subject of message");
			}
		
		String q="";
		String[] li = msg.split("\\n");
		int cx = li.length;
		int pgp = 0;
		for (int ax=0;ax<cx;ax++) {
			String s = li[ax].trim();
			if (s.contains("---BEGIN PGP PUBLIC KEY BLOCK---")) {
				if (pgp!=0) throw new PException("@550 Invalid PGP KEY block");
				pgp=1;
				}
			if (pgp==1) q+=s+"\r\n";
			if (s.contains("---END PGP PUBLIC KEY BLOCK---")) {
				if (pgp!=1) throw new PException("@550 Invalid PGP KEY block"); else pgp=2;
				} 
		}
	if (pgp!=2) throw new PException("@550 Can't read PGP KEY block correctly");
	
	DynaRes RE = Mid.CreaNewUserViaPGP(q, tok[1]);
	
	if (vca){
			if (Mid.LogVoucherTo!=null) try {
				if (Config.Debug) Log("New user `"+tok[1]+"` Voucher `"+vc+"`");
				Stdio.LogFile(tok[1]+"@"+Mid.Onion+"\tmail\t"+vc, Mid.LogVoucherTo, Config);
				} catch(Exception E) { Config.EXC(E, Mid.Nick+".CreateUser"); }
			}
	
	
	HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, MailFrom);
	
		for (String k:new String[] { "subject", "content-type","content-transfer-encoding" }) if (RE.Head.containsKey(k)) H.put(k, RE.Head.get(k));
			 
	RE.Res=RE.Res.replace("\r\n", "\n");
	Mid.SendMessage(MailFrom, H, RE.Res);
	RE=null;
	Send("250 Id=nothing");
	}
	
	public boolean isOld() { return System.currentTimeMillis()> EndTime; }

	public void End() {
		if (con.isConnected()) closeh();
		try {this.interrupt(); } catch(Exception I) {}
	}

	private String[] GetSMTPCommands(int maxtry,String[] cmds,String err,String lasterr) throws Exception {
		String[] Tok = null;
		if (lasterr==null) lasterr="500 FUCK OFF";
		if (err==null) err="500 Error";
		maxtry--;
		String li="";
		
		for (int tr = 0 ;tr<=maxtry;tr++) { ////////////TODO ??? Delirio
			li = I.readLine();
			if (li==null || !con.isConnected()) Log("Remote connection close!");
			if (!con.isConnected()) throw new PException("@500 Connection lost");
			if (li==null)  throw new PException("@500 Connection lost");
			li=li.trim();
			
			Tok = GetFuckedTokens(li,cmds);
			if (Tok==null) {
				if (tr==maxtry) break;
				Send(err);
				} //else???
			return Tok;
		}
		if (maxtry!=0) {
				if (Config.Debug) Log("Too many commands. Last: `"+li+"`");
				throw new Exception("@"+lasterr); 
				} else throw new Exception("@"+err);
	}
	
	public static String[] GetFuckedTokens(String in,String[] cmds) {
		in=in.trim();
		String ino=in.toUpperCase();
		int cx = cmds.length;
		for(int ax=0;ax<cx;ax++) {
			int i = ino.indexOf(cmds[ax]);
			if (i==0) {
				int lz=cmds[ax].length();
				String cmd = in.substring(0,lz).trim();
				String par  = in.substring(lz);
				cmd=cmd.replace(":","");
				cmd.trim();
				cmd=cmd.toUpperCase();
				par=par.trim();
				par=cmd+"\n"+par.replace(" ", "\n");
				return par.split("\\n+");
				}
			}
	return null;
	}
	
	private String[] GetSMTPCommand(String RGSep,int maxcmd) throws Exception {
		String li = I.readLine();
		li=li.trim();
		String[] Tok = null;
		if (maxcmd>0) Tok = li.split(RGSep,maxcmd); else  Tok = li.split(RGSep);  
		Tok[0]=Tok[0].toLowerCase();
		int cx = Tok.length;
		for (int ax=0;ax<cx;ax++) Tok[ax]=Tok[ax].trim();
		return Tok;		
	}
	
	private SMTPReply RemoteCommand(OutputStream ou,BufferedReader in,String line) throws Exception {
		ou.write((line.trim()+"\r\n").getBytes());
		return new SMTPReply(in);
		}
	
	private void BeginClose() throws Exception {
		Send("221 "+((Mid.EnterRoute&&!IPisLocal) ? ( Mid.MXDomain==null ? Mid.ExitRouteDomain :  Mid.MXDomain) : Mid.Onion)+" closing connection");
		closeh();
		}

	private void BeginClose(String st) throws Exception {
		Send(st);
		closeh();
		} 
	
	public static boolean CheckCapab(SMTPReply re,String cap) {
		int cx=re.Msg.length;
		cap=cap.toUpperCase();
		for (int ax=0;ax<cx;ax++) {
			re.Msg[ax].trim().toUpperCase();
			if (re.Msg[ax].startsWith(cap+" ") || re.Msg[ax].compareTo(cap)==0) return true;
			}
		return false;
	}
	/*
	public static boolean CheckTormCapab(SMTPReply re,String cap) {
		int cx=re.Msg.length;
		cap=cap.toUpperCase();
		for (int ax=0;ax<cx;ax++) {
			re.Msg[ax].trim().toUpperCase();
			if (re.Msg[ax].startsWith("TORM ")) {
					String[] t0 = re.Msg[ax].split("\\,+");
					if (t0.length<2) continue;
					t0[1]=" "+t0[1].toUpperCase().trim()+" ";
					return t0[1].contains(" "+cap+" ");
					}
			}
		return false;
	}
	*/
	
	public static boolean CheckTormCapab(SMTPReply re,String cap) {
		int cx=re.Msg.length;
		cap=cap.toUpperCase();
		for (int ax=0;ax<cx;ax++) {
			re.Msg[ax].trim().toUpperCase();
			if (re.Msg[ax].startsWith("TORM ")) return CheckTormCapab(re.Msg[ax],cap);
			}
		return false;
	}
	public static boolean CheckTormCapab(String re,String cap) {
		re=re.toUpperCase();
		re=re.trim();
			if (re.startsWith("TORM ")) {
					re=re.replace(" ", "")+",";
					return re.contains(","+cap.toUpperCase()+",");
					}
		return false;
	}
	
	private void ChechkLocalSOper(String mail) throws Exception {
		if (!IPisLocal) throw new PException(500,"This operation is allowed only via Tor network");
		if (Login==null) throw new PException(503,"Need authentication");
		String mlp = J.getLocalPart(mail);
		String dom = J.getDomain(mail);
		if (!dom.endsWith(".onion") || dom.compareTo(Mid.Onion)!=0) throw new PException(500,"SA6002 Operation not permitted");
		if (mlp.compareTo(Login)!=0) throw new PException(503,"Invalid user credentials");
		if (!Mid.UsrExists(mlp)) throw new PException(500,"No such user 3");
		
	}
	
	private void SA_SETTINGS(String from,String[] Tok,String msgi) throws Exception {
		String mlp = J.getLocalPart(from);
		HashMap<String,String> H = Mid.UsrGetProp(mlp);
		String txt=""; 
		//if (H==null || H.isEmpty()) txt+="<Empty>"; else for (String K:H.keySet()) txt+=J.Spaced(K+":", 40)+J.Limited(H.get(K), 80)+"\n";
		//txt+="\nUser parameters:\n";
		H = Mid.UsrGetConfig(mlp);
		

		try {
			msgi=msgi.replace("\r\n", "\n");
			msgi=msgi.trim();
			if (msgi.length()!=0 && msgi.contains(":")) {
				String[] li = msgi.split("\\n+");
				HashMap<String,String> Hn = J.ParseHeaders(li);
				li=null;
				msgi=null;
				H = Mid.UserSetParamG(mlp, Hn);
				msgi=H.get("_error");
				H.remove("_error_");
				if (msgi!=null && msgi.length()>0) txt+=msgi;
				msgi=null;
				}
			} catch (Exception E) {
				Log("Param error "+E.getMessage());
				txt+="Parameter error: "+E.getMessage()+"\n";
				E.printStackTrace();
			}
		
		if (H==null || H.isEmpty()) txt+="<Default>"; else for (String K:H.keySet()) txt+=J.Spaced(K+":", 40)+J.Limited(H.get(K), 80)+"\n";
		H = ClassicHeaders("server@"+Mid.Onion, from);
		txt+="\n";
		
		H.put("subject","Re: SETTINGS");
		if (PGPSession) txt=Mid.SrvPGPMessage(mlp+"@"+Mid.Onion,H,txt);	
		Mid.SendLocalMessage(mlp, H, txt);
		Send("250 Id=nothing");
	}
	
	private void SA_REBHEAD(String from ,HashMap<String,String> Hldr) throws Exception {
		
		String msg="Rebounding your mail client headers:\n";
		msg=msg+J.CreateHeaders(Hldr).replace("\r", "");
		
		Hldr=J.FilterHeader(Hldr);
		msg+="\nFiltered Header:\n";
		msg+=J.CreateHeaders(Hldr).replace("\r", "");
		
		HashMap<String,String> h = ClassicHeaders("server@"+Mid.Onion, from);
		h.put("subject", "Headers rebound");
		Mid.SendMessage(from, h, msg);
		Send("250 Id=nothing");
		
	}
	
	private void SA_AddSpam(String chi,String fromuser) throws Exception {
		String spam = J.getLtGt(chi);
		if (fromuser!=null && fromuser.compareTo(SrvIdentity.SpamList)==0) throw new PException("@500 FUCK OFF");
		if (fromuser==null) fromuser=SrvIdentity.SpamList;
		
		if (spam==null) throw new Exception("@500 Invalid mail address");
		String lp = J.getLocalPart(spam);
		if (lp.compareTo("server")==0) throw new Exception("@500 Can't ban a server. use *@"+J.getDomain(spam));
		MailBox MB = Mid.UsrOpenW(Config,J.getLocalPart(fromuser));
		MB.Spam.ProcList(MB.LocalPart, new String[] { chi }, null);
		if (Config.Debug) Log("spam add ["+chi+"]");
		Log(Config.GLOG_Event,"SetSpam "+chi);
		MB.Close();
		Send("250 Id=nothing");
	}
	
	private void  SA_SPAMLIST(String MailFrom,String[] Tok) throws Exception {
		String local=J.getLocalPart(MailFrom);
		int del=-1;
		if (Tok.length>1) del = J.parseInt(Tok[1]);
		String txt = Mid.Spam.UsrProcList(local, del);
	
		HashMap<String,String> H = new HashMap<String,String> ();
		H.put("from", "server@"+Mid.Onion);
		H.put("to",MailFrom);
		H.put("subject", "Spam List ("+Mid.TimeString()+")");
		H.put("x-generated", "server cmd");
		H.put("mime-version", "1.0");
		H.put("date", Mid.TimeString());
		H.put("content-type", "text/plain; charset=iso-8859-1");
		H.put("content-transfer-encoding", "8bit");
		if (PGPSession) txt=Mid.SrvPGPMessage(local+"@"+Mid.Onion,H,txt);	
		Mid.SendLocalMessage(local, H, txt);
		Send("250 Id=nothing");
		
	}
	
	private void SA_SPAMOPT(String usr,String[] Tok, String msg) throws Exception {
		String local = J.getLocalPart(usr);
		if (local==null || local.compareTo(SrvIdentity.SpamList)==0 || Tok.length==1) throw new PException("@550 Syntax error");
		String cmd = Tok[1].trim().toLowerCase();
		String rs=null;
				
		if (cmd.compareTo("del")==0 && Tok.length==3) {
			if (!Mid.Spam.isValid(Tok[2])) throw new PException("@550 Invalid spammer address");
			Mid.Spam.ProcList(local, null , new String[] { Tok[2] });
			rs="The address `"+Tok[2]+"` is now removed from Spam list\n"+Mid.Nick+"\n";
			}
		
		if (cmd.compareTo("set")==0) {
			msg=msg.trim();
			msg=msg.replace("\r\n", "\n");
			String[] li = msg.split("\\n+");
			rs="Parsing your SPAM List commands:\n";
			int cx = li.length;
			int dx=0;
			String Add="";
			String Del="";
			for (int ax=0;ax<cx;ax++) {
				String s = li[ax].trim();
				String[] t = s.split("\\s+");
				if (t.length==2) {
					t[0]=t[0].trim();
					t[1]=t[1].toLowerCase().trim();
					s = t[0].toLowerCase();
					if (s.compareTo("add")==0) {
						if (!Spam.isValid(t[1])) {
							rs+="Invalid Spammer address `"+t[1]+"`\n";
							continue;
							}
						Add+=t[1]+"\n";
						dx++;
						}
					
					if (s.compareTo("del")==0) {
						if (!Spam.isValid(t[1])) {
							rs+="Invalid Spammer address `"+t[1]+"`\n";
							continue;
							}
						Del+=t[1]+"\n";
						dx++;
						}		
					}
			}
			
		rs+="\n";
		String[] AddA = null;
		String[] DelA=null;
		Add=Add.trim();
		Del=Del.trim();
		if (Add.length()>0) AddA=Add.split("\\n+");
		if (Del.length()>0) DelA=Del.split("\\n+");
		String[] lst = Mid.Spam.ProcList(local, AddA,DelA);
		
		rs+=dx+" Commands execued, ";
		if (AddA!=null) rs+=AddA.length+" addresses added, ";
		if (DelA!=null) rs+=DelA.length+" addresses removed, ";
		cx = lst.length;
		rs+=cx+" addresses in spam list.\n\nSpam List:\n";
		for (int ax=0;ax<cx;ax++) rs+=lst[ax]+"\n";
		rs+="\n";
		}//set
		
		if (cmd.compareTo("clear")==0) {
			Mid.Spam.UsrCreateList(local);
			rs="Your spam list is now empty!\n"+Mid.Nick+"\n";
		}
		
		if (rs==null) throw new PException("@550 Invalid anti SPAM operation");
		HashMap <String,String> H =  ClassicHeaders("server@"+Mid.Onion,usr);
		H.put("subject", "AntiSpam operation");
		if (PGPSession) rs=Mid.SrvPGPMessage(local+"@"+Mid.Onion,H,rs);	
		Mid.SendLocalMessage(local, H, rs);
		
		Send("250 Id=nothing");
	}
	
	private String TMPPWL(byte[][] I) throws Exception {
		byte[] b = Stdio.md5a(I);
		long H[] = Stdio.Lodsx(b, 8);
		H[0] &=0x7FFFFFFFFFFFFFFFL;
		return Long.toString(H[0],36);
		}

	private void ConfirmMsg(String to,String Tmpp,String subject,String title,String verb) throws Exception {
		HashMap <String,String> H =  ClassicHeaders("server@"+Mid.Onion,to);
		
		H.put("subject", title);
		Mid.SendMessage(to, H, 
							"I'm receving your request to "+verb+"\n"+
							"To complete the request you must send an email message\n"+
							"to the server `server@"+Mid.Onion+"` with this subject:\n"+
							subject+"\n"+
							"To verify your request, put this password in the body of the message:\n"+
							Tmpp+"\nIt is valid for 24 hour.\nThank you\n\t"+Mid.Nick) ;
	}
	
	public static HashMap <String,String> ClassicHeaders(String From,String To) {
	
		HashMap <String,String> H = new HashMap <String,String>();
				H.put("from",From);
				H.put("to", To);
				H.put("errors-to", "<>");
				H.put("x-generated", "server cmd");
				H.put("mime-version", "1.0");
				H.put("content-type", "text/plain; charset=iso-8859-1");
				H.put("content-transfer-encoding", "8bit");
			
	return H;
	}
	
	
	private void SA_Exit(String[] Tok, String from,String msg) throws Exception {
		
		String mlp = J.getLocalPart(from);
		String mld = J.getDomain(from);
		if (mld.compareTo(Mid.Onion)!=0) throw new PException(500,"This action is enabled only for local user");
		if (!Mid.UsrExists(mlp)) throw new PException(500,"So such user");
		
		int cx = Tok.length;
		if (cx<2) throw new PException(503,"Syntax error");
		ExitRouteList RL = Mid.GetExitList();
		
		HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion, from);

		if (Tok[1].compareToIgnoreCase("VMAT")==0) {
			
		if (RL.isEmpty()) {
					H.put("subject", "No exit route");
					String qq="No SMTP Exit/Enter route available for VMAT";
					if (PGPSession) qq=Mid.SrvPGPMessage(mlp+"@"+Mid.Onion,H,qq);	
					Mid.SendLocalMessage(mlp, H,qq);
					Send("250 Id=Nothing");
					return;
					}
		
			H.put("subject", "Exit/Enter Route list + VMAT");
			String qq="Exit/Enter Route list + VMAT Protocol:\n";
			ExitRouterInfo[] el = RL.getAll();
			el = ExitRouteList.queryFLTArray(el, ExitRouteList.FLT_VMAT);
			cx=el.length;
			for (int ax=0;ax<cx;ax++) qq+=el[ax].toInfoString()+"\n";				
				
			if (PGPSession) qq=Mid.SrvPGPMessage(mlp+"@"+Mid.Onion,H,qq);	
			Mid.SendLocalMessage(mlp, H,qq);
			Send("250 Id=Nothing");
			return;
			}
		
		if (Tok[1].compareToIgnoreCase("LIST")==0) {
			
		if (RL.isEmpty()) {
					H.put("subject", "No exit route");
					String qq="No SMTP Exit/Enter route available";
					if (PGPSession) qq=Mid.SrvPGPMessage(mlp+"@"+Mid.Onion,H,qq);	
					Mid.SendLocalMessage(mlp, H,qq);
					Send("250 Id=Nothing");
					return;
					}
		
			H.put("subject", "Exit/Enter Route list");
			String qq="Exit/Enter Route list:\n"+RL.toString();
			if (PGPSession) qq=Mid.SrvPGPMessage(mlp+"@"+Mid.Onion,H,qq);	
			Mid.SendLocalMessage(mlp, H,qq);
			Send("250 Id=Nothing");
			return;
			}
		
		if (Tok[1].compareToIgnoreCase("SET")==0 && cx>2) {
			String dom = Tok[2].toLowerCase().trim();
			ExitRouterInfo ex = RL.selectExitByDomain(dom, false);
			String oni = ex.onion;
			dom = ex.domain;
			
			HashMap <String,String> Ho = new HashMap <String,String>();
			Ho.put("exitonion", oni);
			Ho.put("exitdomain", dom);
			
			Mid.UsrSetConfig(mlp,Ho);
			H.put("subject", "Set Exit/Enter route");
			String txt="Now your exit/enter mail address is "+J.MailOnion2Inet(Config, from,dom)+"\n";
			txt+="\nAvailable Exit/Enter route:\n"+RL.toString()+"\n";
			if (PGPSession) txt=Mid.SrvPGPMessage(mlp+"@"+Mid.Onion,H,txt);	
			Mid.SendLocalMessage(mlp, H,txt);
			Send("250 Id=Nothing");
			RL=null;
			System.gc();
			return;
			}
		
		throw new PException(503,"Unknown parameter");
		
	}
	
	
	private void SA_IDENT(String from) throws Exception {
		HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion,from);
		H.put("subject", "I am "+Mid.Nick+" ("+Mid.Onion+")");
		String txt="Identification request:\n";
		txt+="Onion: "+Mid.Onion+"\n";
		txt+="Nick: "+Mid.Nick+"\n";
		txt+="Server Sofrware: OnionMail Ver. "+Main.getVersion()+"\n";
		txt+="Software source id: "+Main.CompiledBy+"\n";
		txt+="RunString: "+Mid.GetRunString()+"\n";
		txt+="VMAT Support: "+( (Mid.VMAT==null) ? "Disabled" : "Enabled")+"\n";
		txt+="\nCertificate SHA-1: "+LibSTLS.GetCertHash(Mid.MyCert)+"\n";
		
		if (Mid.IdentText!=null) {
			txt+="\nServer comment:\n";
			try {
				byte[] b = Stdio.file_get_bytes(Mid.IdentText);
				String st = new String(b);
				st=st.replace("\r\n", "\n");
				st=st.replace("\r", "\n");
				txt+=st;
				} catch(Exception E) {
					Log("Can't read server comment `"+Mid.IdentText+"` "+E.getMessage());
					txt+="<MISSING>\n";
				}
			txt+="\n\n";
			}
		
		String mykey = Mid.UserGetPGPKey("server");
		if (mykey!=null) {
			mykey=Mid.PGPSpoofNSA(mykey,false);
			mykey=mykey.replace("\r\n", "\n");
			txt+="\nThis is my PGP Public Key:\n"+mykey+"\n";
			mykey=null;
		} else txt+="\nNO PGP KEY\n";
		
		txt+="---- Certificate dump ----\n";
		String[] t0=Mid.MyCert.toString().split("\n");
		String t2="";
		for (String t1:t0) {
			t1=t1.trim();
			t2+=t1+"\n";
			}
		t0=J.WordWrapNT(t2, 75);
		for(String dc:t0) txt+=dc+"\n";
		t2=null;
		txt+="---- END ----\n";
		if (PGPSession) txt=Mid.SrvPGPMessage(from,H,txt);	
		Mid.SendMessage(from, H, txt);
		txt=null;
		Send("250 Id=Nothing");
	}
	
	private void SA_List(String[] Tok,String from, HashMap<String,String> Hldr,String msg) throws Exception {
		// 0 x 1 list 2 cmd 3 subj
		String OpErr="";
		
		int le = Tok.length;
		if (le<3) throw new PException(500,"Syntax error, see rulez!");
		
		String list = J.getMail(Tok[1], false);
		if (list==null) throw new PException(500,"Invalid list address!");
		
		String domain = J.getDomain(Tok[1]);
		list = J.getLocalPart(list);
		if (domain.compareTo(Mid.Onion.toLowerCase())!=0) {
			if (J.isMailOnionized(Tok[1])) {
				Tok[1] = J.MailInet2Onion(Tok[1]);
				domain = J.getDomain(Tok[1]);
				if (domain.compareTo(Mid.Onion.toLowerCase())!=0) throw new PException(500,"Invalid list \"onioned\" for me!");
				list = J.getLocalPart(Tok[1]);
				} else  throw new PException(500,"Invalid list for me!");
		}
						
		if (!list.endsWith(".list") || list.length()<8) throw new PException(500,"Invalid list name, see rulez!");
		String cmd=Tok[2].toLowerCase();
		if (!" subscribe unsubscribe rulez create destroy invite remove list token ".contains(" "+cmd+" ")) throw new PException(500,"Invalid list option");
		if (" invite remove ".contains(" "+cmd+" ") && Tok.length<4 ) throw new PException(550,"Too few parameters");
				
		HashMap <String,String> Par = new HashMap <String,String>();
		
		if (Config.Debug) Log("ListOption `"+cmd+"`");
				
		if (cmd.compareTo("rulez")==0) {
			if (!Mid.CheckMailingList(list)) throw new PException(503,"Unknown Mailing list!");
			MailingList ML = Mid.OpenMailingList(list);
			String fr = ML.GetRulezFile();
			ML.Close();
			SA_RULEZ(from,fr);
			Send("250 Id=nothing");
			return;
			}
		String Tmpp=null;
		
		//create
		if (cmd.compareTo("create")==0) {
			
			if (Mid.CheckMailingList(list)) throw new PException(550,"List arleady exists");
			
			Tmpp = TMPPWL(new byte[][] { Mid.Sale ,list.getBytes(), Long.toString((int)(System.currentTimeMillis()/86400000L),36).getBytes()}) ;
			boolean isLogged =  msg.contains(Tmpp);
			
			if (Login!=null) {
				if (J.getDomain(from).compareTo(Mid.Onion)==0 && J.getLocalPart(from).compareTo(Login)==0) isLogged=true;
				}
			
			String act= isLogged ? "do" : "req";
			act="list-"+act+"-create";
			
			Par.put("token", Tmpp);
			Par.put("nick", Mid.Nick);
			Par.put("onion", Mid.Onion);
			
			Par.put("listmail",list+"@"+Mid.Onion);
			String rs="";
			
			if (isLogged) {
				if (from.compareTo("sysop@"+Mid.Onion)!=0 || Login==null || Login.compareTo("sysop")!=0 ) Mid.CanAndCountCreateNewList();
				String Pwl = J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
				String title="";
				if (Tok.length>4) title = Tok[4].trim();
				MailingList ML = Mid.CreateMailingList(
						list, title, from,
						Pwl,
						true,
						false)
						;
				
				Par.put("title",ML.Title);
				Par.put("password",Pwl);
				String[] li = msg.split("\\n+");
				int cx = li.length;
				int dx=0;
				int ex=0;
				for (int ax=0;ax<cx;ax++) {
					String u = li[ax].trim().toLowerCase();
					if (u.length()==0) continue;
							
					int typ = 0;
					
					String[] tm = u.split("\\s+");
					if (tm.length!=2) {
						ex++;
						continue;
						}
					
					if (tm[0].startsWith("user")) typ=MailingList.TYP_Usr;
					if (tm[0].startsWith("admin")) typ=MailingList.TYP_Admin;
					if (tm[0].startsWith("token")) continue;
					
					if (typ==0) {
							rs="Unknown Keyword: `"+tm[0]+"`\n";
							continue;
							}
					
					tm[1]=tm[1].trim();
					u= J.getMail(tm[1], false);
					if (u.compareTo(from)==0) continue;
					
					if (u!=null) {
							if (!u.startsWith("sysop@") && J.isReserved(u, 0,false)) {
								Log("Try reserved mailinglist `"+from+"` -> `"+u+"` List `"+list+"`");
								ex++;
								continue;
								}
							String Pass = J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
							boolean bit = ML.SetUsr(ML.NewInfo(typ, u, Pass));
							if (!bit) OpErr+="Can't subscribe: `"+u+"`\n";
							rs+= (typ==MailingList.TYP_Admin ? "ADMIN" : "USER")+"\t "+u+"\n";
							dx++;
							} 
					}
				
				String Pass = J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
				boolean bit = ML.SetUsr(ML.NewInfo(MailingList.TYP_Admin, from, Pass));
				if (!bit) if (!bit) OpErr+="Error on user: `"+from+"`\n";
				
				Par.put("admin", from);
				Par.put("admin-password", Pass);
				ML.Save();
				ML.Close();
				ML=null;
				Par.put("users",Integer.toString(dx));
				Par.put("error",Integer.toString(ex));
				Log("New Mailinglist `"+list+"` by `"+from+"` User="+dx);
				
			}
		
			HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion,from);
			DynaRes Re = DynaRes.GetHinstance(Config, act, Mid.DefaultLang);
			Re.Par=Par;
			Re.Par.put("errors", OpErr);
			Re.Res+="\n"+rs;
			Re = Re.GetH(H);
			if (PGPSession) Re.Res=Mid.SrvPGPMessage(from,Re.Head,Re.Res);	
			Mid.SendMessage(from, Re.Head,Re.Res);
			
			Send("250 Id=Nothing");
			return;
		}
		
		if (!Mid.CheckMailingList(list))  throw new PException(503,"Unknown Mailing list!");
		//subscribe check
		MailingList ML = Mid.OpenMailingList(list);
		MLUserInfo U = ML.GetUsr(from);
		String Added="";
		
		if (U==null && !ML.isOpen) {
			ML.Close();
			throw new PException(503,"Unknown Mailing list!");
			}
		
		String tmpus=from.toLowerCase();
		if (U!=null) tmpus=U.Address.toLowerCase();
				
		Tmpp = TMPPWL(new byte[][] { Mid.Sale ,tmpus.toLowerCase().getBytes() , Long.toString((int)(System.currentTimeMillis()/86400000L),36).getBytes()}) ;
				
		Par.put("token", Tmpp);
		Par.put("nick", Mid.Nick);
		Par.put("onion", Mid.Onion);
		Par.put("title",ML.Title);
		Par.put("usermail",tmpus);
		Par.put("listmail",list+"@"+Mid.Onion);
		
		if (cmd.compareTo("token")==0) {
			ML.Close();
			try {
							HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion,from);
							DynaRes Re = DynaRes.GetHinstance(Config, "req-list-token", Mid.DefaultLang);
							Re.Par=Par;
							Re.Par.put("errors", OpErr);
							Re = Re.GetH(H);
							if (PGPSession) Re.Res=Mid.SrvPGPMessage(from,Re.Head,Re.Res);	
							Mid.SendMessage(from, Re.Head,Re.Res);
					} catch(Exception E) { 
							Log("List token `"+list+"@"+Mid.Onion+"` ("+from+") "+E.getMessage().replace("@", "")); 
							throw new PException("@550 List message error");
					}
			Send("250 Id=nothing");
			return;	
		}
		
		boolean isLogged =  msg.contains(Tmpp);
		
		if (!isLogged) {
			String act="req-list";  //+cmd;
			try {
							HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion,from);
							DynaRes Re = DynaRes.GetHinstance(Config, act, Mid.DefaultLang);
							Re.Par=Par;
							Re.Par.put("errors", OpErr);
							Re = Re.GetH(H);
							if (PGPSession) Re.Res=Mid.SrvPGPMessage(from,Re.Head,Re.Res);	
							Re.Head.put("subject","Re: "+Hldr.get("subject"));
							Mid.SendMessage(from, Re.Head,Re.Res);	
					} catch(Exception E) { 
							Log("List req `"+list+"@"+Mid.Onion+"` ("+from+") "+E.getMessage().replace("@", "")); 
							throw new PException("@550 List message error");
					}
			Send("250 Id=nothing");
			return;	
			}
		
		String act="do-list-"+cmd;
		DynaRes Re = null;
		HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion,from);
		
		if (cmd.compareTo("unsubscribe")==0) {
			ML.DelUsr(from);
			ML.Save();
			ML.Close();
			Re = DynaRes.GetHinstance(Config, act, Mid.DefaultLang);
			Re.Par=Par;
			Re = Re.GetH(H);
		}
		
		if (cmd.compareTo("subscribe")==0) {
			if (J.isReserved(from,0,true)) throw new PException(500,"Invalid user");
			String pal = J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
			boolean bit = ML.SetUsr(ML.NewInfo(MailingList.TYP_Usr, from.toLowerCase(), pal));
			if (!bit) OpErr+="Can't subscribe: `"+from+"`\n";
			ML.Save();
			ML.Close();
			Par.put("password", pal);
			Re = DynaRes.GetHinstance(Config, act, Mid.DefaultLang);
			Re.Par=Par;
			Re.Par.put("errors", OpErr);
			Re = Re.GetH(H);
		}
		
	if (" destroy invite remove list ".contains(" "+cmd+" ")) {
		if (U==null || U.Type != MailingList.TYP_Admin) throw new PException(500,"RL6001 Operation not permitted");
		}	
	
	MLUserInfo RU=null;
	
	if (" invite remove ".contains(" "+cmd+" ")) {
		Par.put("usersub",Tok[3]);
		
		if (cmd.compareTo("remove")==0) {
			RU = ML.GetUsr(Tok[3]);
			if (RU==null) throw new Exception("@550 User not found in list");
			ML.DelUsr(Tok[3]);
			ML.Save();
			ML.Close();
			}
		
		if (cmd.compareTo("invite")==0) {
			if (J.isReserved(Tok[3],0,true)) throw new PException(500,"Invalid user");
			RU = ML.GetUsr(Tok[3]);
			if (RU!=null) throw new Exception("@550 User arleady in list");
			String pwl = J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
			RU = ML.NewInfo(MailingList.TYP_Usr, Tok[3], pwl);
			Par.put("password",pwl);
			Par.put("from", from);
			try {
				from = Tok[3];
				H = ClassicHeaders("server@"+Mid.Onion,from);
				Re = DynaRes.GetHinstance(Config, act, Mid.DefaultLang);
				Re.Par=Par;
				Re.Par.put("errors", OpErr);
				Re = Re.GetH(H);
				if (PGPSession) Re.Res=Mid.SrvPGPMessage(from,Re.Head,Re.Res);	
				Mid.SendMessage(from, Re.Head,Re.Res);
			} catch(Exception E) {
				ML.DelUsr(Tok[3]);
				ML.Save();
				ML.Close();
				
				throw E;
				}
			ML.Save();
			ML.Close();
			Send("250 Id=Nothing");
			return;
			}
		}
		
	if (cmd.compareTo("destroy")==0) {
		ML.Destroy();
		try { ML.Close(); } catch(Exception E) {}
		}
	
	if (cmd.compareTo("list")==0) {
		String st="";
		DBCryptIterator Iter = ML.List.GetIterator();
						int ecx= Iter.Length();						
						for (int eax=0;eax<ecx;eax++) {
							byte[] by = Iter.Next();
							if (by==null) break;
							U = ML.UnPackUser(by);
							if (U==null) break;
							if (U.Type==0) continue;
						st+=U.Address+"\n";
						}	
		ML.Close(); 
		Added+="\n"+st;
		}

	Re = DynaRes.GetHinstance(Config, act, Mid.DefaultLang);
	Re.Par=Par;
	Re = Re.GetH(H);
	Re.Res+=Added;
	if (OpErr!=null && OpErr.length()>0) {
		if (Re.Res.contains("%errors%")) Re.Res=Re.Res.replace("%errors%", OpErr); else Re.Res+="\r\nError:\r\n"+OpErr+"\r\n";
		} else if (Re.Res.contains("%errors%")) Re.Res=Re.Res.replace("%errors%", "");
	
	if (PGPSession) Re.Res=Mid.SrvPGPMessage(from,Re.Head,Re.Res);	
	Mid.SendMessage(from, Re.Head,Re.Res);

	Send("250 Id=Nothing");	
	}
	
	private void SA_CONFIG(String from) throws Exception {
	HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion,from);	
	DynaRes Re = DynaRes.GetHinstance(Config, "config-req", Mid.DefaultLang);
	Re.Par.put("maxmsgxusr", Long.toString(Mid.MaxMsgXuser));
	Re.Par.put("maxmsgsize", Long.toString(Mid.MaxMsgSize/1024));
	Re.Par.put("boxsize", Long.toString((Mid.MaxMsgSize*Mid.MaxMsgXuser)/1024));
	Re.Par.put("maxmlsize", Long.toString(Mid.MaxMailingListSize));
	Re.Par.put("maxmultimsg", Long.toString(Mid.MultiDeliverMaxRCPTTo));
	Re.Par.put("maxspam", Long.toString(Mid.MaxSpamEntryXUser));
	Re.Par.put("debug", Re.Par.get( Mid.Config.Debug ? "yes":"no"));
	Re.Par.put("autodelete", Re.Par.get( Mid.AutoDeleteReadedMessages ? "yes":"no"));
	Re.Par.put("exitroute", Re.Par.get( Mid.EnterRoute ? "yes":"no"));
	Re.Par.put("exitnotice", Re.Par.get( Mid.ExitNoticeE ? "yes":"no"));
	Re.Par.put("logvoucher", Re.Par.get( Mid.LogVoucherTo!=null ? "yes":"no"));
	Re.Par.put("vmat", Re.Par.get("yes"));
	Re.Par.put("msgxhour", Mid.MaxMsgXUserXHour==0 ? Re.Par.get("nomsgxhour") : 	Integer.toString(Mid.MaxMsgXUserXHour));
	Re.Par.put("nick",Mid.Nick);
	
	Re = Re.GetH(H);
	if (PGPSession) Re.Res=Mid.SrvPGPMessage(from,Re.Head,Re.Res);	
	Mid.SendMessage(from, Re.Head,Re.Res);
	Send("250 Id=Nothing");	
	} 
	
	private void SA_RULEZ(String da,String per) throws Exception {
		String rul="";
		if (per!=null) { rul=per+"\n";	 }
		rul+=Mid.Maildir+"/rulez.eml\n";
		rul+=Mid.Maildir+"/rulez.txt\n";
		rul+=Mid.Maildir+"/rulez.rul\n";
		rul+=Config.RootPathConfig+"rulez.eml\n";
		rul+=Config.RootPathConfig+"rulez.rul\n";
		rul+=Config.RootPathConfig+"rulez.txt";
		rul=rul.trim();

		for(String tr: rul.split("\\n+")) {
			
					if (new File(tr).exists()) {
						boolean isr = tr.endsWith(".rul");
						
						FileInputStream r=null;
						BufferedReader l=null;
						MailBoxFile  ru=null;
						HashMap <String,String> H=null;
						if (isr) {
							ru = new MailBoxFile();
							ru.OpenAES(tr, Mid.Sale, false);
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
						H.put("from", "server@"+Mid.Onion);
						if (!H.containsKey("subject")) H.put("subject", Mid.Nick+" RULEZ ("+Mid.Onion+")");
						H.put("to", da);
						H.put("date", Mid.TimeString());
						String msg="";
						while(true) {
							String s;
							if (isr) s= ru.ReadLn(); else s = l.readLine();
							
							if (s==null) break;
							s=s.replace("\r", "");
							s=s.replace("\n", "");
							msg+=s+"\n";
							}
						if (isr) ru.Close(); else {
							l.close();
							r.close();
							}
						
						if (PGPSession) msg=Mid.SrvPGPMessage(da,H,msg);	
						Mid.SendMessage(da, H, msg);
						msg=null;
						Send("250 Id=nothing");
						return;
					}
			}
		
		Log(Config.GLOG_Event,"No rulez set in[] "+rul);
		
		HashMap <String,String> H = new HashMap <String,String>();
		H.put("x-generated", "server cmd");
		H.put("from", "server@"+Mid.Onion);
		H.put("subject", Mid.Nick+" RULEZ ("+Mid.Onion+")");
		H.put("to", da);
		H.put("date", Mid.TimeString());
		Mid.SendMessage(da, H, "NO RULEZ SET\n");
		
		Send("250 Id=nothing");
	}
	
	private void SA_VMAT(String from,String msg) throws Exception {
		HashMap <String,String> H = ClassicHeaders("server@"+Mid.Onion,from);
		DynaRes Re =null;
		
		String[] li = msg.split("\\n+");
		int cx = li.length;
		String rmsg="";
		ExitRouteList RL = Mid.GetExitList();
		for (int ax=0;ax<cx;ax++) {
			li[ax]=li[ax].trim();
					
			if (li[ax].contains("register")) {
				String[] v0 = li[ax].split("\\s+");
				
				Re= DynaRes.GetHinstance(Config, "rvmat-req", Mid.DefaultLang);
		
				String vmata =null;
				int cl=v0.length;
				for (int al=0;al<cl;al++) {
						vmata =J.getMail(v0[al], false);
						if (vmata!=null) break;
						}
												
				if (vmata==null || vmata.endsWith(".onion")) {
						rmsg+="Line "+(ax+1)+" Invalid mail address: "+li[ax]+"\n";
						continue;
						}
				String vmatad = J.getDomain(vmata);
				if (!RL.containsDomain(vmatad)) {
						rmsg+="Line "+(ax+1)+" Unknown exit domain: "+li[ax]+"\n";
						continue;
						}
				try {
					 VirtualRVMATEntry RVM = Mid.VMATRegister(vmata,J.getLocalPart(from));
					 rmsg+="\nAddress `"+RVM.mail+"` OK\n\tPassword: "+RVM.passwd+"\n";
					 	 } catch(Exception E) {
						 String ms = E.getMessage();
						 if (ms==null) ms="NULL";
						 if (ms.startsWith("@")) {
							ms=ms.substring(1);
							rmsg+="Line "+(ax+1)+" Remote Error: "+ms+"\n";
							continue;
						 	} else {
						 	rmsg+="Line "+(ax+1)+" Error: "+li[ax]+"\n";
						 	Config.EXC(E, "RVMAT_REG `"+vmata+"`");
						 	continue;
						 	}
					 }
				break;
				} // register
			
			if (li[ax].contains("delete") || li[ax].contains("enable") || li[ax].contains("disable")) {
				Re= DynaRes.GetHinstance(Config, "rvmat-stat", Mid.DefaultLang);
				String[] v0 = li[ax].split("\\s+");
				String vmata =null;
				String pasw=null;
				int cl=v0.length-1;
				for (int al=0;al<cl;al++) {
						vmata =J.getMail(v0[al], false);
						pasw=v0[al+1];
						if (vmata!=null) break;
						}
				
				if (vmata==null || vmata.endsWith(".onion")) {
						rmsg+="Line "+(ax+1)+" Invalid mail address: "+li[ax]+"\n";
						continue;
						}
			
				if (pasw==null) {
						rmsg+="Line "+(ax+1)+" No password in line: "+li[ax]+"\n";
						continue;
						}
				
				String vmatad = J.getDomain(vmata);
				if (!RL.containsDomain(vmatad)) {
						rmsg+="Line "+(ax+1)+" Unknown exit domain: "+li[ax]+"\n";
						continue;
						}
				
					try {
						String stat="?";
						if (li[ax].contains("delete")) { Mid.VMATDelete(vmata, J.getLocalPart(from), pasw); stat=Re.Par.get("deleted"); }
						if (li[ax].contains("enable")) { Mid.VMATEnable(vmata, J.getLocalPart(from),pasw, true);  stat=Re.Par.get("enabled"); }
						if (li[ax].contains("disable")) { Mid.VMATEnable(vmata, J.getLocalPart(from),pasw, false);  stat=Re.Par.get("disabled"); }	
						Re.Par.put("status", stat);
						Re.Par.put("vmata", vmata);
					 	} catch(Exception E) {
						 String ms = E.getMessage();
						 if (ms.startsWith("@")) {
							ms=ms.substring(1);
							rmsg+="Line "+(ax+1)+" Remote Error: "+ms+"\n";
							continue;
						 	} else {
						 	rmsg+="Line "+(ax+1)+" Error: "+li[ax]+"\n";
						 	Config.EXC(E, "RVMAT_REG `"+vmata+"`");
						 	continue;
						 	}
					 }
				break;
				}
			}
	
	if (Re==null) throw new PException("@500 Unknown VMAT operation");
	
	Re.Par.put("MSG", rmsg);
	Re.Par.put("nick", Mid.Nick);
	Re = Re.GetH(H);
	if (PGPSession) Re.Res=Mid.SrvPGPMessage(from,Re.Head,Re.Res);	
	Mid.SendMessage(from, Re.Head,Re.Res);
	Send("250 Id=nothing");
	
	}
	
	public boolean CanVMATOp(String from) {
		boolean can=false;
		if (Mid.DisabledVMAT!=null && Mid.EnabledVMAT!=null) {
			can = Mid.EnabledVMAT.contains("\n*\n");
			if (Mid.DisabledVMAT.contains("\n*\n")) can=false;
			String dom = J.getDomain(from);
			if (Mid.DisabledVMAT.contains("\n"+dom+"\n")) can=false;
			if (Mid.EnabledVMAT!=null && Mid.EnabledVMAT.contains("\n"+dom+"\n")) can=true;
			}
		return can;
		}
	
		private String LogPart() {
			String re="SMTPS/";
			if (serverMode==SMTPServer.SM_InetServer) re+="I";
			if (serverMode==SMTPServer.SM_InetAlt) re+="A";
			if (serverMode==SMTPServer.SM_TorServer) re+="T";
			re+=" "+Mid.Nick;
			if (MailFrom!=null) re+="/A_"+Long.toString(MailFrom.hashCode(),36);
			return re;
		}
		public void Log(String st) { Config.GlobalLog(Config.GLOG_Server|Config.GLOG_Event,LogPart(), st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server|Config.GLOG_Event,LogPart(), st); 	}
		
		protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
