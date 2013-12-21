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
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import javax.crypto.SecretKey;

public class Main {
	Config Config = new Config();
	
	public static final long VersionID = 0x0000_0001_002F_00A1L;
	public static final String Version="0.2.47B";
	public static final String VersionExtra="dev~rc0.3";
	
	public static DNSServer DNSServer=null;
	public static OnionRouter Router = null;
	public static SMTPServer[] SMTPS = null;
	public static POP3Server[] POP3S = null;
	public static org.tramaci.onionmail.MailingList.ListThread[] ListThreads = null;
	
	public static ControlService CS = null;
	public static ControlService[] CSP = null; 
	
	protected static PublicKey FSK = null;
	protected static KeyPair IDK = null;
	protected static SecretKey FSKA = null;
	protected static byte[] FSKIV= null;
	
	protected static DNSCheck DNSCheck = null;
	
	protected static HashMap <String,String> ConfVars=null;
	
	public static String getVersion() { return (Main.Version+" "+Long.toHexString(Main.VersionID)+" "+VersionExtra).trim(); }
	public static boolean NoDelKeys = false;
	
	public static  int Oper = 0;	
	public static final int Oper_Gen_ServerS=1;
	public static final int Oper_Stop=2;
	public static final int Oper_Del_Keys=3;
	public static final int Oper_KCTL = 4;
	
	public static boolean OnlyLoad=false;
	
	public static boolean SelPass=false;
	public static boolean PGPRootMessages=false;
	
	public static String SetPass=null;
	public static boolean CmdRunBoot=false;
	public static boolean CmdDaemon=false;
	
	private static PrintWriter out=null;
	private static String OutFile="onionstart.log";
	
	public static String CompiledBy = null;
	
	public void SelfTest() throws Exception {
		int cx= SMTPS.length;
		if (!Config.LogStdout) Main.echo("Self server test:\n");
		
		Socket	RS=null;
		OutputStream RO=null;
		BufferedReader RI=null;
		SMTPReply Re=null;
		int fun=0;
		
		for (int ax=0;ax<cx;ax++) {
			if (!Config.LogStdout) Main.echo("\tTest: "+J.Spaced(SMTPS[ax].Identity.Nick, 25)+"... SMTP ");
				try {
					RS=null;
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, SMTPS[ax].Identity.Onion,25);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
					Re = new SMTPReply(RI);
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim()); 
					Re = SrvSMTPSession.RemoteCmd(RO,RI,"EHLO iam.onion");
					if (Re.Code<200 || Re.Code>299) throw new Exception("@"+Re.toString().trim());
					if (!Re.Msg[0].toLowerCase().contains(SMTPS[ax].Identity.Onion)) throw new Exception("Fatal error: The server at `"+J.IP2String(SMTPS[ax].Identity.LocalIP)+":25` is not `"+SMTPS[ax].Identity.Nick+"`");
					try { Re = SrvSMTPSession.RemoteCmd(RO,RI,"QUIT"); } catch(Exception I) {}
					try { if (RS!=null) RS.close(); } catch(Exception I) {}
					try { if (RO!=null) RO.close(); } catch(Exception I) {}
					try { if (RI!=null) RI.close(); } catch(Exception I) {}
					} catch(Exception E) {
						try { if (RS!=null) RS.close(); } catch(Exception I) {}
						try { if (RO!=null) RO.close(); } catch(Exception I) {}
						try { if (RI!=null) RI.close(); } catch(Exception I) {}
						String mx = E.getMessage();
						if (mx.startsWith("@")) {
								mx=mx.substring(1);
								Main.echo("Error: "+mx+"\n");
								Config.GlobalLog(Config.GLOG_Server, SMTPS[ax].Identity.Nick, "Server SMTP test error: "+mx);
								} else {
								Main.echo("Exception: "+mx+"\n");
								Config.EXC(E, "TEST `"+ SMTPS[ax].Identity.Nick+"`");
								} 
					}
				
				if (!Config.LogStdout) Main.echo("POP3 ");
				
				try {
					RS=null;
					RS = J.IncapsulateSOCKS(Config.TorIP, Config.TorPort, SMTPS[ax].Identity.Onion,110);
					RO = RS.getOutputStream();
					RI  =J.getLineReader(RS.getInputStream());
					RS.setSoTimeout(Config.MaxSMTPSessionInitTTL);
					String in = RI.readLine();
					if (!in.toLowerCase().contains(SMTPS[ax].Identity.Onion)) throw new Exception("Fatal error: POP3 The server at `"+J.IP2String(SMTPS[ax].Identity.LocalIP)+":"+SMTPS[ax].Identity.LocalPOP3Port+"` is not `"+SMTPS[ax].Identity.Nick+"`");
				
					try { 
						RO.write("quit\r\n".getBytes());
						in = RI.readLine();
						} catch(Exception I) {}
					
					try { if (RS!=null) RS.close(); } catch(Exception I) {}
					try { if (RO!=null) RO.close(); } catch(Exception I) {}
					try { if (RI!=null) RI.close(); } catch(Exception I) {}
					} catch(Exception E) {
						try { if (RS!=null) RS.close(); } catch(Exception I) {}
						try { if (RO!=null) RO.close(); } catch(Exception I) {}
						try { if (RI!=null) RI.close(); } catch(Exception I) {}
						String mx = E.getMessage();
						if (mx.startsWith("@")) {
								mx=mx.substring(1);
								Main.echo("Error: "+mx+"\n");
								Config.GlobalLog(Config.GLOG_Server, SMTPS[ax].Identity.Nick, "Server POP3 test error: "+mx);
								} else {
								Main.echo("Exception: "+mx+"\n");
								Config.EXC(E, "TEST `"+ SMTPS[ax].Identity.Nick+"`");
								System.exit(2);
								} 
					}
				
				if (!Config.LogStdout) Main.echo("Ok\n");
				fun++;
			}
		
		if (!Config.LogStdout) Main.echo("\nTest complete: "+cx+" Servers "+(cx-fun)+" Errors "+fun+" Ok\n\n");
		if (cx==fun) Config.GlobalLog(Config.GLOG_All, "MAIN.TEST", "OnionMail "+fun+" servers, running Ok");
		
		}
	
	private static void RedirectOut() throws Exception {
		try {
			out = new PrintWriter(new BufferedWriter(new FileWriter(Main.OutFile, true)));
		} catch(Exception E) {
			out=null;
			echo("Can't daemonize\n");
		}
	}
	
	private boolean TermCmd()   {
		boolean stat1=false;
		try {
			echo("Closing previous hinstances:\t");
			Socket s = new Socket(Config.ControlIP,Config.ControlPort);
			s.setSoTimeout(5000);
			BufferedReader i = J.getLineReader(s.getInputStream());
			OutputStream o = s.getOutputStream();
			String Rns="";
			
			String t0 = i.readLine();
			if (t0==null || t0.length()==0) {
				echo("Error 1\n");
				try { s.close(); } catch(Exception I) {}
				return true;
				}
			stat1=true;	
			
			if (t0.indexOf('+')!=0) {
				echo("Error 2: `"+t0.trim()+"`\n");
				try { s.close(); } catch(Exception I) {}
				return true;
				} else {
					int a= t0.indexOf('<');
					int b= t0.indexOf('>');
					if (b>a) Rns = t0.substring(a+1, b);
				}
			
			o.write(("sux "+Stdio.Dump(Stdio.md5a(new byte[][] { Rns.getBytes() ,Config.RootPass.getBytes()}))+"\r\n").getBytes());
			t0 = i.readLine();
			if (t0==null || t0.length()==0) {
					echo("Error 3\n");
					try { s.close(); } catch(Exception I) {}
					return true;
					}
			
			if (t0.indexOf('+')!=0) {
					echo("Error 4: `"+t0.trim()+"`\n");
					try { s.close(); } catch(Exception I) {}
					return true;
				}
			
			o.write("stop now\r\n".getBytes());
			t0 = i.readLine();
			if (t0==null || t0.length()==0) {
					echo("Error 5\n");
					try { s.close(); } catch(Exception I) {}
					return true;
					}
			
			if (t0.indexOf('+')!=0) {
					echo("Error 6: `"+t0.trim()+"`\n");
					try { s.close(); } catch(Exception I) {}
					return true;
				}
			try { s.close(); } catch(Exception I) {}
			echo("Ok\n");
		} catch(Exception E) {
			if (stat1) {
				echo("Error: `"+E.getMessage()+"`\n"); 
				return true;
			} else {
				echo("Ok\n");
				return false;
				}
			
		}
		return false;
	}
	
	
	@SuppressWarnings("static-access")
	public void Start(String fc) throws Exception {
		try {
			Config = Config.LoadFromFile(fc);
			
			if (Oper==Main.Oper_KCTL) {
				echo("Remote KCTL operation\nPaste here the KCTL Sequence:\n");
				String kctl = J.ASCIISequenceReadI(System.in, Const.ASC_KB_KCTL);
				echo("\nEnter Onion address: ");
				BufferedReader br = J.getLineReader(System.in);
				String oni;
				while(true) {
					echo(">");
					oni= br.readLine();
					if (oni==null) System.exit(2);
					oni=oni.toLowerCase().trim();
					if (oni.matches("[a-z0-9]{16}\\.onion")) break;
					}
				echo("Enter password: ");
				String pwl = br.readLine();
				if (pwl==null) System.exit(2);
				pwl=pwl.trim();
				if (pwl.length()<4) System.exit(2);
				Config.LogStdout=true;
				SrvIdentity S = new SrvIdentity(Config);
				S.Onion = oni.toLowerCase().trim();
				
				while(true) {
					echo("Remote DERK options for `"+oni+"`\n");
					echo("Choose action:\n\t(0) Quit\n\t(1) Unlock/Reset Credit\n\t(2) Lock\n\t(3) Destroy\n\t>");
					int act = Config.parseInt(br.readLine().trim());
					if (act==0 || act> 3) System.exit(0);
					String acts="";
					if (act==1) acts="start";
					if (act==2) acts="set 0";
					if (act==3) acts="del";
					echo("Running remote KCTL\n");
					RemoteKSeedInfo[] xy = S.RemoteDoKCTLAction(acts,kctl ,oni,pwl);
					int cx= xy.length;
					for (int ax=0;ax<cx;ax++) {
						echo(J.Spaced(Integer.toString(cx), 4)+J.Spaced(xy[ax].Onion, 24)+J.Spaced(xy[ax].Ok ? "Ok":"Error", 6)+xy[ax].Confirm+"\n");
						}
					}
				
				// 
			}
			
			if (Oper==Main.Oper_Del_Keys) {
					DelKeys();
					System.exit(0);
				}
			
			if(Oper==Main.Oper_Stop) {
					TermCmd();
					System.exit(0);
				}
			
			} catch(Exception E) {
			String st = E.getMessage()+"";
			if (st.startsWith("@")) {
			echo(st.substring(1)+"\n");	
			} else echo("Config error "+E.getMessage()+"\n");
			System.exit(2);
			}
		
		if (Oper==Main.Oper_Gen_ServerS) { 
				echo("\nOperation complete!\n");
				System.exit(0);
				}	
		
		if (Oper!=Main.Oper_Stop && TermCmd()) {
			echo("Error: The control port is used, some TCP ports maybe in use!\n");
			System.exit(2);
			}
		
		
		
		echo("\nSMTP Service:  \t" + (Config.RUNSMTP ? "Enabled":"Disabled")+"\n");
		echo("TorDNS Service:\t" + (Config.RunDNSServer ? "Enabled":"Disabled")+"\n");
		
		if (!J.TCPRest(Config.TorIP, Config.TorPort)) {
			echo("\nCan't connect to TOR via `"+J.IP2String(Config.TorIP)+":"+Integer.toString(Config.TorPort)+"`\n");
			System.exit(2);
			}
		
		if (Config.RunDNSServer) {
			echo("Start OnionRouter:\t");
			Router = new OnionRouter(Config);
			echo("Ok\nStart DNS Server:\t");
			DNSServer = new DNSServer(Config,Router);
			echo("Ok\n");
			}
		
		if (!Config.RUNSMTP && !Config.RunDNSServer) {
				echo("Nothing to do!\n\tEnable RUNSMTP or RunDNSServer\n");
				return;
				}
			
		ListThreads= new org.tramaci.onionmail.MailingList.ListThread[Config.ListThreadsMax];
		
		if (!Config.RUNSMTP && Config.SMPTServer.length>0) echo("Warning:\n\tAll SMTP Server defined will not work because RunSMTP is not set!\n\n");
		if (Config.RUNSMTP && Config.SMPTServer.length==0) echo("Warning:\n\tNo SMTP Server defined!\n\n");
		if (Config.RUNSMTP && Config.SMPTServer.length>0) try {
			
			echo("Start DNSCheck: ");
			DNSCheck = new DNSCheck(Config);
			echo("Ok\n");
						
			echo("Running SMTP Server:\n");
			int cx = Config.SMPTServer.length;
			SMTPS = new SMTPServer[cx];
			POP3S = new POP3Server[cx];
			
			String otsm="\n";
			
			for (int ax=0;ax<cx;ax++) otsm+=Config.SMPTServer[ax].Onion.trim().toLowerCase()+"\n";
			
			for (int ax=0;ax<cx;ax++) {
				echo("\nStart "+J.Limited("`"+Config.SMPTServer[ax].Nick+"`",40)+"\n");
				echo("\tOnion:\t"+Config.SMPTServer[ax].Onion+"\n");
				echo("\tSMTP:\t"+J.Limited((Config.SMPTServer[ax].EnterRoute ? "0.0.0.0" : J.IP2String(Config.SMPTServer[ax].LocalIP) ) +	":"+Config.SMPTServer[ax].LocalPort,23));
				echo("\n\tExit:  \t");
				if (Config.SMPTServer[ax].EnterRoute) echo("YES!\n\tQFDN:\t"+Config.SMPTServer[ax].ExitRouteDomain+"\n"); else echo("No\n");
				
				try {
					SMTPS[ax] = new SMTPServer(Config,Config.SMPTServer[ax]);
					SMTPS[ax].Identity.OnTheSameMachine=otsm;
					
					} catch(Exception E) {
					echo("!Error\n\t"+E.getMessage()+"\n");
					if (Config.Debug) Config.EXC(E, "SMTP."+Config.SMPTServer[ax].Nick);
					System.exit(2);
					}
				
				try {
					echo("\tPOP3:\t"+J.IP2String(Config.SMPTServer[ax].LocalIP)+":");
					echo(Config.SMPTServer[ax].LocalPOP3Port+"\n");
					POP3S[ax] = new POP3Server(Config,Config.SMPTServer[ax]);
					} catch(Exception E) {
					echo("!Error\n\t"+E.getMessage()+"\n");
					if (Config.Debug) Config.EXC(E, "POP3."+Config.SMPTServer[ax].Nick);
					System.exit(2);
					}
				
				}
			echo("\n");
			} catch(BindException BE) {
				echo("\nAddress in use!\n");
				System.exit(2);
			}
		
		echo("Control port:\t"+J.IP2String(Config.ControlIP)+":"+Config.ControlPort+"\t");
		try {
			CS = new ControlService(Config,SMTPS);
			echo("Ok\n");
			
			int cx = Config.SMPTServer.length;
			int dx=0;
			String t0="\n";
			echo("Public control ports:\n");
			
			for (int ax=0;ax<cx;ax++) if (Config.SMPTServer[ax].PublicControlIP!=null) dx++;
			Main.CSP = new ControlService[dx];
			
			for (int ax=0;ax<cx;ax++) { 
				if (Config.SMPTServer[ax].PublicControlIP!=null) {
					String t1=Config.SMPTServer[ax].PublicControlIP+":"+Config.SMPTServer[ax].PublicControlPort;
					echo("\t"+J.Spaced(Config.SMPTServer[ax].Nick, 32));
					echo(J.Spaced(J.IP2String(Config.SMPTServer[ax].PublicControlIP)+":"+Config.SMPTServer[ax].PublicControlPort,25));
					
					if (t0.contains("\n"+t1+"\n")) {
						echo("Error!\n\tIP+Port is in use by another control port!\n");
						System.exit(2);
						}
					
					Main.CSP[ax] = new ControlService(Config ,Config.SMPTServer[ax],Config.SMPTServer[ax].PublicControlPort,Config.SMPTServer[ax].PublicControlIP);
					echo("Ok\n");
					
					}
				echo("\n");
				}
			} catch(Exception BE) {
				echo("Error "+BE.getMessage()+"\n");
				System.exit(2);
			}
		
		echo("Service Started\n");
				
	if (Main.NoDelKeys) echo("Warning: NoDelKeys ENABLED!\n");  else DelKeys();
			
	if (Main.SetPass!=null) for (int ax=0;ax<5;ax++) {
		Main.SetPass = J.RandomString(16);
		Main.SetPass = null;
		System.gc();
		}
	
		if (Config.LogFile==null) echo("\nLog to STDOUT:\n"); else {
						if (Config.KeyLog!=null) echo("LogFile is in RSA mode!\n");  else echo("LogFile is in plain text mode!\n");
						}
	
	Config.GlobalLog(Config.GLOG_All, "MAIN", "OnionMail is running!");
	Thread.sleep(2000);		
	SelfTest();
	}
	
	private void DelKeys() throws Exception {
		
			String s0 ="";
			int cx = Main.SMTPS.length;
			for (int ax=0;ax<cx;ax++) {
				String s1;
				if (Config.MindlessCompilant) {
					s1 =SMTPS[ax].Identity.Maildir+"/keyblock.txt";
					if (new File(s1).exists()) s0+=s1+"\n";
					}
				s1=SMTPS[ax].Identity.Maildir+"/sysop.txt";
				if (new File(s1).exists()) s0+=s1+"\n";
				}
			s0=s0.trim();
			if (s0.length()==0) return;
			
			String fco[] = s0.split("\\n+");
			cx = fco.length;
			if (cx>0) {
				echo("\nWarning:\n\t");
				echo("Some reserved files are detected!\n\tThese files contain the keys and must be removed with a wipe.\n");
				echo("Do you want to remove these files now?\n");
				for (int ax=0;ax<cx;ax++) echo("\t"+fco[ax]+"\n");
				echo(" Yes/No ? ");
				while(true) {
					int ax = System.in.read();
					if (ax==0x4e || ax==0x6e) return;
					if (ax==0x59 || ax==0x79) break;
				}
				echo("\n");
				for (int ax=0;ax<cx;ax++) {
					echo("\t Wipe: `"+fco[ax]+"`\t... ");
					try { J.Wipe(fco[ax], false); } catch(Exception X) { echo("Error: "+X.getMessage()+" "); }
					if (new File(fco[ax]).exists()) echo("Can't delete!\n"); else echo("Ok\n");
					}
			echo("\n");
			}
	}

public static void main(String args[]) {
		Main N=null;
		boolean verbose=false;
		
		try {
			LibSTLS.AddBCProv();
			CompiledBy = J.Compiler();
						
			String fc=null;
			for(String x:new String[] { "etc/config.conf", "onionmail.conf" , "/etc/onionmail/config.conf"} ) if (new File(x).exists()) fc = x;
												
			int cx = args.length;
			boolean fp=true;
			if (cx>0 && args[0].compareTo("-q")==0) fp=false;
			if (fp) echo("\nOnionMail Ver. "+Main.getVersion()+"\n\t(C) 2013 by Tramaci.org\n\tSome rights reserved\n\n");
			
			for (int ax=0;ax<cx;ax++) {
				boolean fm=false;
				String cmd = args[ax].toLowerCase().trim();		
				
				if (cmd.compareTo("-f")==0) { 
						fm=true;
						if ((ax+1)>=cx) {
							echo("Error in command line: -f\n\tFile required!\n");
							Helpex();
							return;
							}
						fc = args[ax+1];
						if (!new File(fc).exists()) {
							echo("\nCan't open `"+fc+"`\n");
							System.exit(2);
							}
						ax++;
						}
								
				if (cmd.compareTo("-v")==0) { 
						fm=true;
						verbose=true;
						}
				
				if (cmd.compareTo("--stop")==0) { 
						Oper=Oper_Stop; 
						fm=true; 
						OnlyLoad=true; 
						}
				
				if (cmd.compareTo("--gen-passwd")==0) { 
						GenPassword(); 
						return; 
						}
				
				if (cmd.compareTo("--gen-servers")==0) { 
						Oper=Oper_Gen_ServerS; 
						fm=true; 
						}
				
				if (cmd.compareTo("--del-keys")==0) { 
						OnlyLoad=true;
						Oper=Oper_Del_Keys; 
						fm=true; 
						}
								
				if (cmd.compareTo("--pgp")==0) { 
						PGPRootMessages=true;
						fm=true; 
						}
				
				if (cmd.compareTo("--kctl")==0) { 
						OnlyLoad=true;
						Oper=Oper_KCTL; 
						fm=true; 
						}
				
				if (cmd.compareTo("--reboot")==0) {
					fm=true;
					CmdRunBoot=true;
					}
				
				if (cmd.compareTo("-d")==0) {
					fm=true;
					CmdDaemon=true;
					RedirectOut();
					}
				
				if (cmd.compareTo("-dr")==0) {
					if ((ax+1)>=cx) {
							echo("Error in command line: -dr\n\tFile required!\n");
							Helpex();
							return;
							}
					
					fm=true;
					Main.OutFile = args[ax+1].trim();
					ax++;
					RedirectOut();
					}
				
				if (cmd.compareTo("-sp")==0) { 
						SelPass=true; 
						fm=true; 
						}
				
				if (cmd.compareTo("-q")==0) fm=true; 
								
				if (cmd.compareTo("-ndk")==0) { 
						NoDelKeys=true; 
						fm=true;
						}
				
				if (cmd.compareTo("-p")==0 && (ax+1)<args.length) {
						ax++;
						if (SetPass!=null) 
							SetPass = J.by2pass(J.Der2048(SetPass.getBytes(), args[ax].getBytes()));
							else 
							SetPass = args[ax];
						fm=true;
						}
				
				if (cmd.compareTo("-pf")==0 && (ax+1)<args.length) {
						ax++;
						String fpa = args[ax];
						fm=true;
						if (!new File(fpa).exists()) {
							echo("\nError: No password file: `"+fpa+"`.\n");
							System.exit(2);
							}
						try {
								SetPass=Main.DerKeyfile(fpa, SetPass);
							} catch(Exception E) {
								echo("Error: `"+E.getMessage()+"`\n");
								System.exit(2);
							}
						}
				
				if (cmd.compareTo("--show-passwd")==0) {
					if (SetPass==null) echo("No password!\n"); else echo(SetPass+"\n");
					System.exit(0);
					}
				
				if (cmd.compareTo("--gen-keyfile")==0 && (ax+2)<args.length) {
					try {
						Main.GenKeyFile(args[ax+1], J.parseInt(args[ax+2]));
						} catch(Exception E) {
						echo("Error: `"+E.getMessage()+"`\n");
						System.exit(2);
						}
					System.exit(0);
					}
				
				if (cmd.compareTo("--scanport")==0 && (ax+3)<args.length) {
					ScanFreePort(J.parseInt(args[ax+1]),J.parseInt(args[ax+2]),J.parseInt(args[ax+3]));
					System.exit(0);
				}
				
				if (cmd.compareTo("-?")==0) { 
						Helpex();  
						return; 
						}
				
				if (!fm) {
					echo("Invalid command line parameter `"+cmd+"`\n");
					Helpex(); 
					return;
					}
				
				}
			
			if (fc==null) {
				echo("\nCan't find any config file!\n");
				System.exit(2);
				}
			
			echo("Load Config '"+fc+"'\n");
			N = new Main();
			if (verbose) {
					N.Config.Debug=true;
					N.Config.DNSLogQuery=true;
					N.Config.LogStdout=true;
					}
			N.Start(fc);
			if (N.Config==null) { 
				echo("\nCan't start!\n");
				} 
		} catch(Exception E) { 
			if (N!=null && N.Config!=null) { 
				if (N.Config.Debug) EXC(E,"Main");
				} else EXC(E,"Main");
			echo("Fatal Error: "+E.getMessage()+"\n");
			}
      }

	private static void GenPassword() throws Exception {
		echo("\nPassword generator tool\nEnter password (UTF-8 encoding):\n");
		BufferedReader i =J.getLineReader(System.in);
		String p =i.readLine();
		p=p.trim();
		String q = J.GenCryptPass(p);
		echo("\n"+q+"\n");
		
	}

	private static String DerKeyfile(String fpa,String altpass) throws Exception {
			if (new File(fpa).length()>65536) throw new Exception("@Keyfile too big `"+fpa+"`");
		
			byte[] b = Stdio.file_get_bytes(fpa);
			byte[] c;
			
			if (altpass==null) 
					c=J.Der2048(fpa.getBytes(), ("OnionMail.VirtualClass.getDefaultKPSSWD(`"+J.md2st(Stdio.md5(fpa.getBytes()))+"`)").getBytes());
					else
					c=altpass.getBytes();
			
			b= J.Der2048(b, c);
			return J.by2pass(b);
		}
		
	public static void GenKeyFile(String fpa,int size) throws Exception {
		if (size>65535) size=65535;
		if ((size&7)!=0) size++;
		size>>=3;
		if (size<32) size=32;
		echo("Generating global salt keyfile `"+fpa+"`\n\tbits=`"+(size*8)+"`\n");
		byte[] b = new byte[size];
		Stdio.NewRnd(b);
		Stdio.file_put_bytes(fpa, b);
	
	}
	
	private static void ScanFreePort(int From,int to,int nport) {
		int[] rs = new int[nport];
		int bp=0;
		for (int ax=From;ax<to;ax++) {
			try {
				ServerSocket Test = new ServerSocket(ax,0,InetAddress.getByAddress(new byte[] {127,0,0,1}));
				Test.close();
				rs[bp++]=ax;
				if (bp==nport) break;
			} catch(Exception E) {}
		}
		if (bp<nport) echo("-ERR no all\n"); else echo("+OK\n");
		for (int ax=0;ax<nport;ax++) if (rs[ax]==0) echo("-\n"); else echo("127.0.0.1:"+rs[ax]+"\n");
		echo(".\n");
		
	}
	
	private static void Helpex() {
		
		InputStream i = Main.class.getResourceAsStream("/resources/help");
		BufferedReader h = J.getLineReader(i);
		
		while(true) try {
			String li=h.readLine();
			if (li==null) break;
			echo(li+"\n");
			} catch(Exception E) { E.printStackTrace(); break; }
		
		try {		h.close(); } catch(Exception I) {}
		try {		i.close(); } catch(Exception I) {}
		
		}	 

	public static void echo(String st) { 
		if (out!=null) try { out.print(st); } catch (Exception E) {System.out.print(st); } else System.out.print(st);
		}
	
	public  static void EXC(Exception E,String dove) {
		echo("\n\nException: "+dove+" = "+E.toString()+"\n"+E.getMessage()+"\n"+E.getLocalizedMessage()+"\n");
							StackTraceElement[] S = E.getStackTrace();
							for (int ax=0;ax<S.length;ax++) echo("STACK "+ax+":\t "+S[ax].toString()+"\n");
		}
	
	public static void file_put_bytes(String name,byte[]  data) throws Exception {
			FileOutputStream fo = new FileOutputStream(name);
			fo.write(data);
			fo.close();
		}	

	
	
	
	
	
	protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
