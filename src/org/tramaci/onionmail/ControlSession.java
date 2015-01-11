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
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Date;
import java.util.HashMap;

//import org.tramaci.onionmail.DBCrypt.DBCryptIterator;
import org.tramaci.onionmail.MailingList.MLUserInfo;

public class ControlSession extends Thread{
	
	public SrvIdentity Mid = null;
	
	private Socket sok;
	private DataInputStream in; 
	private BufferedReader br;
	private OutputStream O;
	private ControlService ParentServer=null;
	private Config Config = null;
	public long EndTime = 0;	
	private String Login=null;
	private SrvIdentity[] SRVS;
	private int CurSrv=-1; 
	private String pwl=null;
	private boolean roote =false;
	private String curmail=null;
	private boolean logon=false;
	private boolean serveruser=false;
	public boolean isPublic=false;
	
	public String AccessInfo() {
		String flg = logon ? "K" : "N";
		if (pwl!=null) flg+="E";
		if (roote) flg+="R";
		if (serveruser) flg+="S";
		if (Login!=null) flg+="I";
		if (curmail!=null) flg+="M";
		if (CurSrv!=-1) flg+="A";
		flg+=" ";
		if (CurSrv!=-1) flg+="["+SRVS[CurSrv].Nick+"] "; else flg="[] ";
		if (curmail!=null) flg+="("+curmail+") ";
		if (Login!=null) flg+="`"+Login+"`";
		
		if (isPublic) flg+=" <Public>";
	
		return flg.trim();
	}
	
	private void ReplyAccess() throws Exception { Reply(logon,AccessInfo()); }
	
	private void BeginSession() throws Exception {
		String Rns = J.GenPassword(48,40);
		Rns=Rns.replace('<', '_');
		Rns=Rns.replace('>', '^');
		Reply(true, "ControlPort 1.0 "+J.RandomString(3)+"<"+Rns+">"+J.RandomString(6));
		String li;
		
		int cx = SRVS.length;
		
		String[] Tok;
		CurSrv=-1; 
		
		while(true) {
		
			li =ReadLn();
			if (li==null) break;
			li=li.trim();
			Tok=li.split("\\s+");
			String Tk[]  =li.split("\\s+",2);
			String cmd=Tok[0].trim();
			cmd=cmd.toLowerCase();
			int pa = Tok.length;
			
			///////////////////

			if (cmd.compareTo("ver")==0) { Reply(true,Main.getVersion()); continue; }
			if (cmd.compareTo("vers")==0) { Reply(true,Main.CompiledBy+" "+Main.getVersion()); continue; }
			
			if (pa==3 && cmd.compareTo("server")==0) {
				Login = Tok[1];
				pwl = Tok[2];
				CurSrv=-1;
				cx=SRVS.length;
				for (int ax=0;ax<cx;ax++) {
					if (J.CheckCryptPass(Login, SRVS[ax].Nick) && J.CheckCryptPass(SRVS[ax].PassWd, pwl)) {
							CurSrv=ax;
							break;
							}
					}
				if (CurSrv!=-1 && logon==false)  logon=true;
				if (CurSrv==-1 && logon==false) throw new Exception("@Access denied");
				serveruser=(CurSrv!=-1);
				Log("Access "+AccessInfo());
				ReplyAccess();
				continue;
				}
			
			/////////////////
			
			if (pa==3 && cmd.compareTo("md5server")==0) {
				CurSrv=-1;
				Login = Tok[1];
				pwl = Tok[2];
				cx=SRVS.length;
				for (int ax=0;ax<cx;ax++) {
					if (SRVS[ax].Nick.compareTo(Login)==0 && SRVS[ax].PassWd!=null) {
							String vr = J.Base64Encode( Stdio.md5a(new byte[][] {Rns.getBytes() , SRVS[ax].PassWd.getBytes() }));
							if (vr.compareTo(pwl)==0) {
								CurSrv=ax;
								break;
								}
					}
				}
			if (CurSrv!=-1 && logon==false) logon=true;
			if (CurSrv==-1 && logon==false) throw new Exception("@Access denied");
			serveruser=(CurSrv!=-1);
			Log("Access "+AccessInfo());
			ReplyAccess();
			continue;
			}
			
			///////////////////
			
			if (pa==3 && cmd.compareTo("user")==0) {
				Login = Tok[1];
				pwl = Tok[2];
				curmail = J.getMail(Login, true);
				if (curmail==null) throw new Exception("@Invalid mail address");
				
				String lp = J.getLocalPart(Login);
				String ld = J.getDomain(Login);
				cx=SRVS.length;
				for (int ax=0;ax<cx;ax++) {
					if (SRVS[ax].Onion.compareTo(ld)==0) { 
							CurSrv=ax;
							if (!SRVS[ax].UsrExists(lp)) throw new Exception("@Unknown user");
							if (!SRVS[ax].UsrLogonSend(lp, pwl)) throw new Exception("@Access denied");
							logon=true;
							if (lp.compareTo("sysop")==0) serveruser=true; else serveruser=false;
							Log("Access "+AccessInfo());
							ReplyAccess();
							break;
							}
				}
			continue;
			}
		
		if (cmd.compareTo("su")==0 && pa==2) {
			if (!J.CheckCryptPass(Config.RootPass, Tok[1])) throw new Exception("@Access denied");
			roote=true;
			logon=true;
			serveruser=true;
			Login="root";
			Log("Access "+AccessInfo());
			ReplyAccess();
			continue;
			}
			
		if (cmd.compareTo("sux")==0 && pa==2) {
			String ap = Stdio.Dump(Stdio.md5a(new byte[][] { Rns.getBytes(), Config.RootPass.getBytes()}));
		
			if (ap.compareTo(Tok[1])!=0) throw new Exception("@Access denied");
			roote=true;
			logon=true;
			serveruser=true;
			Login="root";
			Log("Access "+AccessInfo());
			ReplyAccess();
			continue;
			}
				
		/////////////////
			
		if (cmd.compareTo("quit")==0) break;
		if (cmd.compareTo("access")==0) { ReplyAccess(); continue; }
		
		
		
		if (cmd.compareTo("captcha")==0) {
			if ( TextCaptcha.isEnabled()) {
				CaptchaCode C= TextCaptcha.generateCaptcha(Config.TextCaptchaSize, Config.TextCaptchaMode);
				String s = C.image.trim();
				s+="\n\n"+C.code.trim().toLowerCase();
				ReplyA(true,"CAPTCHA",s.split("\\n"));
				} else {
							int a = (int) (511&Stdio.NewRndLong());
							int b = (int) (511&Stdio.NewRndLong());
							if ((a&256)!=0) a=-(a & 255);
							if ((b&256)!=0) b=-(b & 255);
							int c = a+b;
							String[] tok = new String[] { 
											"Equation: " ,
											Integer.toString(a),
											b<0 ? "" : "+" ,
											Integer.toString(b),
											"=",
											Integer.toString(c)}
											;
							
							c = (int) (Stdio.NewRndLong()&3)%3;
							c = 1+(c*2);
							String sol = tok[c];
							tok[c]="X";
							String cap="";
							for (int al=0;al<6;al++) cap+=" "+tok[al]+" ";
							ReplyA(true,"CAPTCHA",new String[] { 
									"Please solve the following equation to prove you're human. ",
									cap.trim(),
									"What is the value of X?",
									"",
									sol})
									;
				}
			continue;
		}
		
		if (CurSrv!=-1) {	/// Server
		
				if (cmd.compareTo("vmatreg")==0 && pa>1) {
					String onim = Tok[1].trim();
					String user=J.getLocalPart(onim);
					String srvm= J.getDomain(onim);
					
					if (user==null || srvm==null) {
						Reply(false,"Invalid mail address");
						continue;
						}
					
					if (srvm.endsWith(".onion")) {
						Reply(false,"Invalid mail server");
						continue;
						}
					
					if (
						!user.matches("[a-z0-9\\-\\_\\.]{3,16}") 	|| 
						user.compareTo("server")==0 					|| 
						user.endsWith(".onion") 								|| 
						user.endsWith(".o") 									||
						user.endsWith(".sys")									||
						user.endsWith(".sysop")								||
						user.startsWith(".") 									|| 
						user.endsWith(".") 										|| 
						user.contains("..")) 									{
				
						Reply(false,"Invalid user Name");
						return;
					}
					
					ExitRouteList EL = SRVS[CurSrv].GetExitList();
					ExitRouterInfo SE = EL.selectBestExit();
					String rs=null;
					if (SE!=null && SE.canVMAT) try {
						
						VirtualRVMATEntry RVM = SRVS[CurSrv].VMATRegister(onim,user);
						if (RVM!=null) {
							rs="vmat: 1\n";
							rs+="vmatmail: "+RVM.mail+"\n";
							rs+="vmatpass: "+RVM.passwd+"\n";
							} else rs+="vmat: 0\n";
						} catch(Exception E) {
								if (Config.Debug) E.printStackTrace();
								String msge=E.getMessage();
								if (msge==null) msge="null";
								if (msge.startsWith("@")) {
										Log("VMATRegister: Error "+msge.substring(1)); 
										Reply(false,msge);
										} else {
											Config.EXC(E, "Control.VMAT");
											Reply(false,"VMAT Error");
										}
								
								rs=null;
								continue;
								}
					
					if (rs==null) Reply(false,"VMAT Error"); else ReplyA(true,"VMAT",rs.split("\\n+"));
					continue;
				}
			
				if (cmd.compareTo("info")==0) { SA_SSLInfo(); continue; }
				
				if (cmd.compareTo("dofriends")==0) {
					if (0!=( SRVS[CurSrv].Status & SrvIdentity.ST_FriendRun)) {
						Reply(false,"DoFriends arleady in progress.");
						continue;
						}
					
					Log("DoFriends CLI Request start.");
					SRVS[CurSrv].FriendOk=false; 
					SRVS[CurSrv].LastFriend=0;
					SRVS[CurSrv].DoFriends(); 
					SRVS[CurSrv].SearchExit();
					Log("DoFriends CLI Request end.");
					Reply(true);
					continue;
				}
				
				if (cmd.compareTo("sslcheck")==0 && Tok.length>1) {
					String host = Tok[1].toLowerCase().trim();
					boolean t=true;
					if (Tok.length>2) t = Config.parseY(Tok[2]);
					String rp = SRVS[CurSrv].SSLManualVerify(host,t);
					ReplyA(true, "SSLManualVerify", rp.split("\\n"));
					continue;
					}
				
				if (cmd.compareTo("getkey")==0) {
						String[] t0 =new String[] { J.Base64Encode(Stdio.Public2Arr(SRVS[CurSrv].SPK)) };
						ReplyA(true,"RSA Public Key",t0);
						t0=null;
						continue;
						}
				
				///////////////
				
				if (cmd.compareTo("dnsbl")==0 && pa==2) {
					if (!SRVS[CurSrv].EnterRoute) {
						Reply(false,"2 No exit");
						continue;
						}
					String ips = Tok[1].trim();
					String dnss=Main.DNSCheck.DNSBL(ips);
					boolean s= (dnss!=null);
					Reply(true, s ? "1 Spam `"+dnss+"`" : "0 Ok");
					continue;
					}
				
				if (cmd.compareTo("bestexit")==0) {
						ExitRouteList a= SRVS[CurSrv].GetExitList();
						ExitRouterInfo ie = a.selectBestExit();
						if (ie==null) Reply(false); else Reply(true,ie.toString());
						continue;
						}
				
				if (cmd.compareTo("sslcert")==0) {
						String t0 = SRVS[CurSrv].MyCert.toString();
						ReplyA(true,"Certificate",t0.split("\n"));
						t0=null;
						continue;
						}
				
		}				
		//////////////
		
		if (cmd.compareTo("list")==0 && pa>3) {
				SA_LISTOP(Tok);
				break;
				}
						
		
		if (!logon) {
			Reply(false,"WTF ???");
			continue;
			}
	
		////////////////////////////// LOGON
		
		if (cmd.compareTo("exit")==0) {
			curmail=null; serveruser=false; CurSrv=-1; roote=false; pwl=null; Login=null; logon=false; 
			Reply(true,AccessInfo());
			continue;
		}
		
		if (cmd.compareTo("spam")==0) try { SA_SPAM(Tok); continue; } catch(Exception E) { Config.EXC(E, "Spam Ctrl `"+AccessInfo()); Reply(false,"Spam Error"); continue; }
		
		if (CurSrv!=-1) {
			if (cmd.compareTo("elist")==0) { SA_EXITLIST(Tok); continue; }
			
			if (cmd.compareTo("rsetcnt")==0) {
				SRVS[CurSrv].LimSrvMHour=new int[0];
				SRVS[CurSrv].LimSrvMMsg=new int[0];
				SRVS[CurSrv].LimSrvMHash=new int[0];
				Reply(true,"Counter reset");
				continue; 
				}
			
			if (cmd.compareTo("vouchermk")==0) {
				Reply(true,SRVS[CurSrv].VoucherCreate(Tok.length>1 ? Config.parseIntS(Tok[1]) : 0));
				continue;
				}
			
			if ((cmd.compareTo("voucherchk")==0 || cmd.compareTo("voucher")==0) && Tok.length>1) {
				boolean save =  cmd.compareTo("voucher")==0;
				
				int ax= SRVS[CurSrv].VoucherTest(Tok[1],save);
				if (save) SRVS[CurSrv].VoucherLog(Tok[1], ax, (Tok.length>2 ? Tok[2] :"CmdAction"));
				
				if (SRVS[CurSrv].LogVoucherTo!=null && ax==1 && save) try {
						if (Config.Debug) Log("Voucher `"+(Tok.length>2 ? Tok[2] : "???")+"` V=`"+Tok[1]+"`");
						Stdio.LogFile((Tok.length>2 ? Tok[2] : "???")+"\tcli\t"+Tok[1], SRVS[CurSrv].LogVoucherTo, Config);
						} catch(Exception E) { Config.EXC(E, SRVS[CurSrv].Nick+".Cmd.Voucher"); }
				
				if (ax==SrvIdentity.VOUCHER_UNKNOWN) Reply(false,"Unknown"); else 
						if (ax==SrvIdentity.VOUCHER_OK) Reply(true,"OK"); else 
							if (ax==SrvIdentity.VOUCHER_USED) Reply(false,"Used"); else 
								if (ax==SrvIdentity.VOUCHER_OLD) Reply(false,"Old"); else Reply(false,"Error");
				continue;
				}
			
			if (curmail!=null) {
		/*		if (cmd.compareTo("par")==0) {
					if (J.getDomain(curmail).compareTo(SRVS[CurSrv].Onion)==0) {
						try {
							String s;
							if (Tok.length==3) 	s = SRVS[CurSrv].UserMSGParam(J.getLocalPart(curmail), Tok[1], Tok[2]); else s = SRVS[CurSrv].UserMSGParam(J.getLocalPart(curmail), "" , "");
							s=s.trim();
							ReplyA(true,"Parameters",s.split("\\n+"));
							} catch(Exception MR) {
								String s= MR.getMessage()+"";
								if (s.startsWith("@")) Reply(false,s.substring(1)); else Reply(false,"Error");
								Log(s.startsWith("@") ? Config.GLOG_Bad : Config.GLOG_Event , s);
							}
						} else Reply(false,"Access denied");
					continue;
					}*/
				}
			}
		
		if (!serveruser) {
			Reply(false,"WTF ???");
			continue;
			}
		
		///////////////////////////// Server
		
		if (CurSrv!=-1) {
			if (cmd.compareTo("mklist")==0  && serveruser) { SA_MKLIST(Tok); continue; }
			if (cmd.compareTo("addusr")==0  && serveruser) { SA_ADDUSR(Tok,false); continue; }
			if (cmd.compareTo("ovrusr")==0  && serveruser) { SA_ADDUSR(Tok,true); continue; }
			if (cmd.compareTo("friends")==0  && serveruser) {
					String[]fl = SRVS[CurSrv].RequildFriendsList();
					ReplyA(true,"FRIENDS/1.0",fl);
					continue; 
					}
			
			if (cmd.compareTo("deluser")==0 && serveruser && Tok.length>1) {
				if (SRVS[CurSrv].UsrExists(Tok[1])) {
					try {
						SRVS[CurSrv].UsrDestroy(Tok[1]);
						Reply(true);
						} catch(Exception E1) {
							Config.EXC(E1, "CTRL.Deluser");
							Reply(false,E1.getMessage());
						}
					} else Reply(false,"User not found"); 
					continue;
				}
			
			if (cmd.compareTo("addpgpusr")==0 && serveruser && Tok.length==2) {
				Reply(true,"Send your PGP armor Key, end width \".\"");
				String pgpk="";
				while(true) {
					String li2 = br.readLine();
					if (li2==null) throw new Exception("@Disconnected");
					li2=li2.trim();
					if (li2.compareTo(".")==0) break;
					pgpk+=li2+"\r\n";
				}
				
				DynaRes re = SRVS[CurSrv].CreaNewUserViaPGP(pgpk, Tok[1]);
				re.Res=re.Res.replace("\r\n", "\n");
				re.Res=re.Res.trim();
				ReplyA(true,re.Head.get("subject"),re.Res.split("\\n"));
				continue;
			}
			
			if (cmd.compareTo("status")==0 && serveruser) { Reply(true,SRVS[CurSrv].getStatus()); continue; }
			
			if (cmd.compareTo("addalias")==0  && serveruser && Tok.length==3) {
					Reply(SRVS[CurSrv].UsrCreateAlias(Tok[1].toLowerCase().trim(), Tok[2].toLowerCase().trim()));
					continue;
					}
			
			if (cmd.compareTo("delalias")==0  && serveruser && Tok.length==2) {
					SRVS[CurSrv].UsrDelAlias(Tok[1].toLowerCase().trim());
					String xc= SRVS[CurSrv].UsrAlias(Tok[1].toLowerCase().trim());
					Reply(xc==null);
					continue;
					}
			
			if (cmd.compareTo("alias")==0  && serveruser && Tok.length==2) {
					String xc= SRVS[CurSrv].UsrAlias(Tok[1].toLowerCase().trim());
					Reply(xc!=null,xc!=null ? xc : "No Alias");
					continue;
					}
			
			if (cmd.compareTo("vrfy")==0 && serveruser && Tok.length==2) {
				String m0 = Tok[1];
				Reply(SRVS[CurSrv].UsrExists(m0),"Ok");
				continue;
				}
			
			if (cmd.compareTo("ssleid")==0 && serveruser && Tok.length==1) {
				String msg = SRVS[CurSrv].SSLEtoString();
				ReplyA(true,"SSLEID",msg.split("\\n+"));
				continue;
				}
			
			if (cmd.compareTo("ssleid")==0 && serveruser && Tok.length==2 && Tok[1].compareToIgnoreCase("run")==0) {
				SRVS[CurSrv].CheckSSLOperations();
				String msg = SRVS[CurSrv].SSLEtoString();
				ReplyA(true,"SSLEID",msg.split("\\n+"));
				continue;
				}
			
			if (cmd.compareTo("torid")==0) {
				try { Main.ChangeTORIdentity(Config); } catch(Exception E) {
					Reply(false,"Error: "+E.getMessage());
					continue;
					}
				Reply(true,"ID: "+Config.TORIdentityNumber);
			} 
			
			if (cmd.compareTo("toridf")==0) {
				Config.TORIdentityNumber++;
				Reply(true,"ID: "+Config.TORIdentityNumber);
			} 
			
			if (cmd.compareTo("ssleid")==0 && serveruser && Tok.length==2 && Tok[1].compareToIgnoreCase("clear")==0) {
				SRVS[CurSrv].SSLErrorTracker = new HashMap <String,Integer[]>();
				String msg = SRVS[CurSrv].SSLEtoString();
				ReplyA(true,"SSLEID",msg.split("\\n+"));
				continue;
				}
			
			if (cmd.compareTo("ssleid")==0 && serveruser && Tok.length==3 && Tok[1].compareToIgnoreCase("no")==0) {
				Integer[] dta = J.newInteger(SrvIdentity.SSLEID_SIZE);
				dta[SrvIdentity.SSLEID_First] = (int) (System.currentTimeMillis()/1000L);
				dta[SrvIdentity.SSLEID_Last] = dta[SrvIdentity.SSLEID_First];
				dta[SrvIdentity.SSLEID_Flags] = SrvIdentity.SSLEID_Flags_NoSSL | SrvIdentity.SSLEID_Flags_Persistent;
				SRVS[CurSrv].SSLErrorTracker.put(Tok[2].toLowerCase().trim(), dta);
				String msg = SRVS[CurSrv].SSLEtoString();
				ReplyA(true,"SSLEID",msg.split("\\n+"));
				continue;
				}
			
			if (cmd.compareTo("ssleid")==0 && serveruser && Tok.length==3 && Tok[1].compareToIgnoreCase("del")==0) {
				Tok[2]=Tok[2].toLowerCase().trim();
				if (SRVS[CurSrv].SSLErrorTracker.containsKey(Tok[2])) SRVS[CurSrv].SSLErrorTracker.remove(Tok[2]);
				String msg = SRVS[CurSrv].SSLEtoString();
				ReplyA(true,"SSLEID",msg.split("\\n+"));
				continue;
				}
			
			if (cmd.compareTo("ssleid")==0 && serveruser && Tok.length==5 && Tok[1].compareToIgnoreCase("chg")==0) {
				// ssleid chg host name val
				String host =Tok[2].toLowerCase().trim();
			
				if (Tok[2].compareTo("?")==0) {
					Reply(true,"tor chg ecrt err hit ok sok b c i n p");
					continue;
					}
			
				try {
					 SRVS[CurSrv].SSLEIDCmd(host, new String[] { Tok[3].trim()+"="+Tok[4].trim() } );
					} catch(Exception E) {
						Reply(false,"Error: "+E.getMessage());
						continue;
					}
								
				String msg = SRVS[CurSrv].SSLEtoString();
				ReplyA(true,"SSLEID",msg.split("\\n+"));
				continue;
				}
			
			if (cmd.compareTo("sslclear")==0 && serveruser && Tok.length==2) {
				String host = Tok[1].trim().toLowerCase();
				String fn = SRVS[CurSrv].GetFNName(host)+".crt";
				
				Reply(
						new File(fn).delete() &&
						new File(fn+"h").delete() ,
						"SSL CRT "+host)
						;
				
				continue;
			}
			
			if (cmd.compareTo("send")==0 && serveruser && Tok.length==2) {
				SA_SEND(Tok);
				continue;
			}
			
			if (cmd.compareTo("stat")==0 && serveruser) {
				ReplyA(true,"Statistics", new String[] {
					"Messages-In: "+SRVS[CurSrv].StatMsgIn ,
					"Messages-Out: "+SRVS[CurSrv].StatMsgOut ,
					"Messages-Inet: "+SRVS[CurSrv].StatMsgInet ,
					"POP3-Sessions: "+SRVS[CurSrv].StatPop3 ,
					"Spam-Blocked: "+SRVS[CurSrv].StatSpam ,
					"Errors: "+SRVS[CurSrv].StatError ,
					"Exceptions: "+SRVS[CurSrv].StatException ,
					"UpTime: "+SRVS[CurSrv].StatHcount ,
					"NewUsrThisDay: "+SRVS[CurSrv].NewUsrLastDayCnt,
					"NewUsrThisHour: "+SRVS[CurSrv].NewUsrLastHourCnt,
					"NewUsrXDay: "+SRVS[CurSrv].NewUsrMaxXDay,
					"NewUsrXHour: "+SRVS[CurSrv].NewUsrMaxXHour,
					"NewUsrEnabled: "+(SRVS[CurSrv].NewUsrEnabled ? "YES" : "NO") }) ;
				continue;
			}
				
		}//cursrv
		
		
		if (!roote) {
			Reply(false,"WTF ???");
			continue;
			}
		
		/////////////////////////// Root Option
		
		/*
		 * HTTP[bx] = new HTTPServer(Config,Config.SMPTServer[ax]);
		 * */
			if (cmd.compareTo("http")==0 && Tok.length==3) {
				String nick = Tok[1].toLowerCase().trim();
				String scmd = Tok[2].toLowerCase().trim();
				
				int cl = Main.HTTP.length;
				int ch=-1;
				int sh=-1;
				for (int al=0;al<cl;al++) {
					if (Main.HTTP[al]==null) continue;
					if (Main.HTTP[al].Identity.Nick.toLowerCase().compareTo(nick)==0) {
						ch=al;
						break;
						}
					}
				
				for (int al=0;al<cl;al++) {
					if (Main.SMTPS[al]==null) continue;
					if (Main.SMTPS[al].Identity.Nick.toLowerCase().compareTo(nick)==0) {
							sh=al;
							break;
							}
					}
				
				if (ch==-1 || sh==-1) {
					Reply(false,"Server not found ["+ch+" "+sh+"]");
					continue;
					}
				
				if (scmd.compareTo("reload")==0) {
					if (Main.HTTP[ch].running) {
						Log("Terminate HTTP server "+nick);
						Main.HTTP[ch].End();
						} else {
							Main.HTTP[ch]=null;
							System.gc();
						}
					
					Log("Start HTTP server "+nick);
					Main.HTTP[ch] = new HTTPServer(Config,Config.SMPTServer[sh]);
					Reply(Main.HTTP[ch].running,"Server "+nick);
					continue;
					}
				
				if (scmd.compareTo("stop")==0) {
					Log("Terminate HTTP server "+nick);
					Main.HTTP[ch].End();
					Reply(true,"Ok");
					continue;
					}
				
				if (scmd.compareTo("status")==0) {
					Reply(Main.HTTP[ch].running,"Server "+nick);
					continue;
					}
				
			}
		
		
		if (cmd.compareTo("threads")==0 && Tok.length==2 && Tok[1].compareToIgnoreCase("all")==0) {
			String rs = Main.TheradsCounter(true,false);
			rs=rs.trim();
			ReplyA(true,"Threads",rs.split("\\n+"));
			continue;
			}
		
		if (cmd.compareTo("threads")==0 && Tok.length<2) {
			String rs = Main.TheradsCounter(true,true);
			rs=rs.trim();
			ReplyA(true,"Threads",rs.split("\\n+"));
			continue;
			}
		
		if (cmd.compareTo("threads")==0 && Tok.length==2 && Tok[1].compareToIgnoreCase("count")==0) {
			int cl = Main.StatsKThreadsXHour.length;
			String[] rs = new String[cl];
			for (int al=0;al<cl;al++) rs[al]=Short.toString(Main.StatsKThreadsXHour[al]);
			ReplyA(true,"Threads",rs);
			continue;
			}
		
		if (cmd.compareTo("queue")==0) {
			SA_Queue(Tk);
			continue;
			}
		
		if (cmd.compareTo("log")==0) {	Log("ControlSession: `"+Tk[1]+"`"); continue; }
		
		if (cmd.compareTo("showlog")==0) {
			try {
				if (Config.LogFile==null) {
					Reply(false,"See STDOUT!");
					continue;
					}
				
				Log("ReadLog");
				
				FileInputStream L = new FileInputStream(Config.LogFile);
				Reply(true, new File(Config.LogFile).length()+" octects");
				int aq=0;
				while((aq=L.available())>0) try {
					if (aq>512) aq=512;
					byte[] bb=new byte[aq];
					L.read(bb);
					String rs = new String(bb);
					bb=null;
					rs=rs.replace("\r", "");
					rs=rs.replace("\n.", "\n .");
					rs=rs.replace("\n", "\r\n");
					O.write(rs.getBytes());
					rs=null;
					} catch(Exception EQ) {
					O.write(("\r\nException: "+EQ.getMessage()+"\r\n.\r\n").getBytes());
					try { L.close(); } catch(Exception I) {}
					continue;
					}
				O.write("\r\n.\r\n".getBytes());
				L.close();
				} catch(Exception EF) {
					Reply(false,EF.getMessage());
					Config.EXC(EF, "Readlog");
				}
			continue;
			}
		
		if (cmd.compareTo("stop")==0) {
				if (pa>1) {
					if (Tok[1].compareToIgnoreCase("now")==0) { StopNow(); break; }
			
					if (Tok[1].compareToIgnoreCase("session")==0 && pa>2) {
							int si = J.parseInt(Tok[2]);
							if (ParentServer.Connection[si]==null) { Reply(false,"No session"); continue; }
							String tmp = ParentServer.Connection[si].AccessInfo();
							try {
									ParentServer.Connection[si].End();
									Reply(true,"KILLED: "+tmp);
									} catch(Exception IE) {
									Reply(false,"NOT KILLED: "+IE.toString());	
									}
							continue;
							}
					
					}
				
				Reply(false);
				}
		
		if (cmd.compareTo("all")==0) { SA_ALL(); continue; }
		
		if (cmd.compareTo("server")==0 && pa==2) {
			cx=SRVS.length;
			CurSrv=-1;
			for (int ax=0;ax<cx;ax++) if (SRVS[ax].Nick.compareTo(Tok[1])==0) { CurSrv=ax; break; }
			if (CurSrv==-1) Reply(false); else ReplyAccess();
			continue;
			}
			
		if (cmd.compareTo("trustdb")==0) {
			SA_TRUST();
			continue;
			}
				
		Reply(false,"WTF ???");
	}
	if (isConnected()) Reply(true,"Closing");
	Log("Close");
	close();
	
	}
	
	private void SA_TRUST() throws Exception {
		if (CurSrv==-1) {
			Reply(false,"No server selected");
			return;
			}
		String inb = SRVS[CurSrv].Maildir+"/feed/";
		SrvManifest M=null;	
		File ib = new File(inb);
		Log("Search Exit Scan");
		String onionlist="\n";
		FilenameFilter esf = new FilenameFilter() {
			public boolean accept(File dir, String name) { return name.toLowerCase().endsWith(".mf"); }
			} ;
		
		String[] lst = ib.list(esf);
		
		
		
		int cx = lst.length;
		Reply(true,cx+" Entries");
		for (int ax=0;ax<cx;ax++) {
				lst[ax]=lst[ax].replace(".mf", "");
				lst[ax]=SRVS[CurSrv].Maildir+"/feed/"+lst[ax];
				
			M = null;
			String H = null;
			File F = new File(lst[ax]+".mf");
			long Tcr = 0;
			String st="";
			String fl="";
			if (F.exists()) {
				try {
					M = SRVS[CurSrv].LoadManifest(lst[ax]+".mf", false);
					} catch(Exception  E) { Config.EXC(E,"TrustDBRead `"+lst[ax]+".mf`"); }
					
				st+=J.Spaced(M.my.onion, 23)+",";
				Tcr=F.lastModified();
				fl="M";
				if (M.my.isExit) st+="E,"+J.Spaced(M.my.domain, 50)+","; else st+="N,"+J.Spaced("N/A", 50)+",";
				} else {
				st+=J.Spaced("N/A", 23)+",?,"+J.Spaced("N/A", 50);
				fl="-";
				}
			F = new File(lst[ax]+".crth");
			if (F.exists()) {
				if (Tcr==0) Tcr=F.lastModified();
				if (F.length()==20) {
					fl+="H";
					st+=Stdio.Dump(Stdio.file_get_bytes(lst[ax]+".crth"))+",";
					} else {
					fl+="-";
					st+=J.Spaced("N/A", 40)+",";
					}
				} else {
					fl+="-";
					st+=J.Spaced("N/A", 40)+",";
				}
			
			F = new File(lst[ax]+".crt");
			if (F.exists()) fl+="C"; else fl+="-";
			if (Tcr!=0) Tcr+=Config.TimeSpoof;
			if (Tcr!=0) st=J.Spaced(J.TimeStandard(Tcr), 16)+","+fl+","+st; else st=J.Spaced("N/A", 16)+","+fl+","+st;
			fl=null;
			F=null;
			lst[ax]=st;
			}
		
		ReplyA(true,"TrustDB",lst);
		
	}
	
	private void SA_ALL() throws Exception {
		int cx = ParentServer.Connection.length;
		String st="";
		for (int ax=0;ax<cx;ax++) {
			if (ParentServer.Connection[ax]==null) continue;
			if (!ParentServer.Connection[ax].isAlive()) continue;
			st+=ax+"\t "+ParentServer.Connection[ax].AccessInfo().trim();
			if (ParentServer.Connection[ax]==this) st+=" <this>";
			st+="\n";
			}
		st=st.trim();
		String[] l = st.split("\\n+");
		st=null;
		ReplyA(true,l.length+" sessions",l);
	}
	
	private void SA_Queue(String[] Tok) throws Exception {
		SrvIdentity S = SRVS[CurSrv];
		
		if (Tok.length<2) {
				Reply(false,"Syntax error");
				return;
				}
		
		if (!S.hasQueue) {
				Reply(false,"Server witout queue");
				return;
				}
		
		String c = Tok[1].toLowerCase().trim();
		
		if (c.compareTo("list")==0) {
			int cx = S.Queue.QueueNext.length;
			String re="";
			for (int ax=0;ax<cx;ax++) {
				if (S.Queue.QueueNext[ax]==0) continue;
				re+=S.Queue.QueueNext[ax]+"\t"+J.TimeStandard(S.Queue.QueueNext[ax]*1000L)+"\n";
				}
			re=re.trim();
			ReplyA(true,"Queue",re.split("\\n+"));
			return;
			}
		
		if (c.compareTo("killall")==0) {
			int cx = S.QueueSender.length;
			for (int ax=0;ax<cx;ax++) {
				S.QueueSender[ax].End();
				S.QueueSender[ax]=null;
				}
			System.gc();
			c="clear";
			}
		
		if (c.compareTo("clear")==0) {
			int cx = S.Queue.QueueNext.length;
			S.Queue.QueueNext = new int[cx];
			S.Queue.QueueFiles = new String[cx];
			S.Queue.Save();
			for (int ax=0;ax<cx;ax++) S.Queue.QueueFiles[ax]="";
			String[] rm = new File(S.Maildir+"/tmp").list();
			cx = rm.length;
			for (int ax=0;ax<cx;ax++) {
				if (!rm[ax].startsWith("Q") || !rm[ax].startsWith("M")) continue;
				try { J.Wipe(rm[ax], Config.MailWipeFast); } catch(Exception E) { Config.EXC(E, S.Nick+".ControlDelQueue"); }
				}
			Reply(true);
			return;
			}
		
		if (c.compareTo("running")==0) {
			int cx = S.QueueSender.length;
			String rs="";
			long tcr = System.currentTimeMillis();
			for (int ax=0;ax<cx;ax++) {
				if (S.QueueSender[ax]==null) continue;
				rs+=ax+"\t"+Long.toString(S.QueueSender[ax].getId(),36)+"\t"+ (S.QueueSender[ax].running ? "R" : "-" );
				rs+=S.QueueSender[ax].DSN!=null ? "E":"-";
				rs+=S.QueueSender[ax].isAlive() ? "A" : "-";
				rs+=tcr > S.QueueSender[ax].Scad ? "S" : "-";
				rs+=S.QueueSender[ax].isInterrupted() ? "I":"-";
				rs+="\t"+S.QueueSender[ax].Q.stat+"\t"+Long.toString(S.QueueSender[ax].Q.MailFrom.hashCode(),36)+"\n";
				}
			rs=rs.trim();
			ReplyA(true,"Theads",rs.split("\\n"));
			}
		
		if (c.compareTo("kill")==0 && Tok.length>2) {
			int cx = S.QueueSender.length;
			int k = J.parseInt(Tok[2]);
			
			if (k<0 || k>cx) {
				Reply(false,"Syntax error");
				return;
				}
			
			S.QueueSender[k].End();
			S.QueueSender[k]=null;
			System.gc();
			Reply(true);
			}
		
		Reply(false,"Unknown queue command");
		}
	
	private void SA_EXITLIST(String[] Tok) throws Exception {
		SrvIdentity S = SRVS[CurSrv];	
		ExitRouteList RL = S.GetExitList();
		String s="";
		ExitRouterInfo[] EL = RL.getAll();
		boolean hm=false;
		if (Tok.length>1) {
			int mode =0;
			Tok[1]=Tok[1].toLowerCase();
			hm = Tok[1].contains("h");
			
			if (Tok[1].contains("-b")) mode|=ExitRouteList.EFLT_BAD_N; 		else if (Tok[1].contains("b")) mode|=ExitRouteList.EFLT_BAD_Y;
			if (Tok[1].contains("-d")) mode|=ExitRouteList.EFLT_DOWN_N; 	else if (Tok[1].contains("d")) mode|=ExitRouteList.EFLT_DOWN_Y;
			if (Tok[1].contains("-e")) mode|=ExitRouteList.EFLT_EXIT_N; 		else if (Tok[1].contains("e")) mode|=ExitRouteList.EFLT_EXIT_Y;
			if (Tok[1].contains("-l")) mode|=ExitRouteList.EFLT_LEGACY_N; 	else if (Tok[1].contains("l")) mode|=ExitRouteList.EFLT_LEGACY_Y;
			if (Tok[1].contains("-m")) mode|=ExitRouteList.EFLT_MX_N; 		else if (Tok[1].contains("m")) mode|=ExitRouteList.EFLT_MX_Y;
			if (Tok[1].contains("-t")) mode|=ExitRouteList.EFLT_TRUST_N; 	else if (Tok[1].contains("t")) mode|=ExitRouteList.EFLT_TRUST_Y;
			if (Tok[1].contains("-v")) mode|=ExitRouteList.EFLT_VMAT_N; 	else if (Tok[1].contains("v")) mode|=ExitRouteList.EFLT_VMAT_Y;
						
			if (Tok[1].contains("7")) mode=ExitRouteList.FLT_EXIT;
			if (Tok[1].contains("6")) mode=ExitRouteList.FLT_BAD;
			if (Tok[1].contains("5")) mode=ExitRouteList.FLT_DOWN;
			if (Tok[1].contains("4")) mode=ExitRouteList.FLT_MX;
			if (Tok[1].contains("3")) mode=ExitRouteList.FLT_VMAT;
			if (Tok[1].contains("2")) mode=ExitRouteList.FLT_OK;
			if (Tok[1].contains("1")) mode=ExitRouteList.FLT_TRUST;
			if (Tok[1].contains("0")) mode=ExitRouteList.FLT_ALL;
			
			EL = ExitRouteList.queryFLTArray(EL, mode);
			}
		
		int cx= EL.length;
		if (hm) for (int ax=0;ax<cx;ax++) s+=EL[ax].toInfoString()+"\n"; else for (int ax=0;ax<cx;ax++) s+=EL[ax].toString()+"\n";
		EL=null;
		RL=null;
		s=s.trim();
		if (s.length()==0) {
			Reply(false,"Empty");
			return;
			}
		ReplyA(true,hm ? "ELIST/H 2.0" : "ELIST/S 2.0",s.split("\\n+"));
	}
	
	private void SA_SPAM(String[] Tok) throws Exception {
			SrvIdentity S = null;
			String lpa = null;
			String tpa=null;
			if (curmail!=null) {
					lpa = J.getMail(curmail, true);
					if (lpa!=null) {
						String t0 = J.getDomain(curmail);
						int cs=-1;
						for (int ax=0;ax<SRVS.length;ax++) 
								if (t0.compareTo(SRVS[ax].Onion)==0) {
									cs=ax;
									tpa=curmail;
									break;	
									}
						if (cs!=-1) {
							lpa=curmail;
							S=SRVS[cs];
							}
						}
					}
			if (lpa==null && CurSrv!=-1 && serveruser) {
				S=SRVS[CurSrv];
				lpa = SrvIdentity.SpamList;
				tpa =S.Onion;
			}		
				
			if (lpa==null) {
				Reply(false,"User OR Server required");
				return;
				}
			
			int le = Tok.length;
			if (le<2) {
				Reply(false,"Parameters required");
				return;
				}
			
			String cmd = Tok[1].toLowerCase();
			lpa = J.getLocalPart(lpa);
			
			if (cmd.compareTo("create")==0) {
				S.Spam.UsrCreateList(lpa);
				Reply(true,S.Onion+" Spam List created");
				return;
				}
							
			if (cmd.compareTo("list")==0) {
				ReplyA(true,tpa+" Spam List",S.Spam.GetList(lpa));
				return;
				}
						
			if (cmd.compareTo("del")==0&&le==3) {
				String[] nos = Tok[2].split("\\,+");
				ReplyA(true,tpa+" Spam List",S.Spam.ProcList(lpa, null, nos));
				return;
				}
			
			if (cmd.compareTo("add")==0&&le==3) {
				String[] nos = Tok[2].split("\\,+");
				ReplyA(true,tpa+" Spam List",S.Spam.ProcList(lpa,nos,null));
				return;
				}
						
			if (cmd.compareTo("check")==0&le==3) {
				String st = J.getMail(Tok[2], false);
				if (st==null)  {
					Reply(false,"Invalid address");
					return;
					}
				Reply(S.Spam.isSpam(lpa, st),tpa);
				return;
				}
			
			if (cmd.compareTo("where")==0) {
				Reply(true,tpa);
				return;
			}
		Reply(false,tpa+" Wrong option");
		return;	
	}
	
	
	private void StopNow() throws Exception {
		Reply(true);
		int cx = Main.POP3S.length;
		for (int ax=0;ax<cx;ax++) {
			try {	
				Log("Terminate POP3 `"+Main.POP3S[ax].Identity.Onion+"`");
				Main.POP3S[ax].End();
				} catch(Exception E) { Config.EXC(E, "Term `"+Main.POP3S[ax].Identity.Onion+"`"); }
			}
		cx = Main.SMTPS.length;
		for (int ax=0;ax<cx;ax++) {
			try {	
				Log("Terminate SMTP `"+Main.SMTPS[ax].Identity.Onion+"`\n");
				Main.SMTPS[ax].End();
				} catch(Exception E) { Config.EXC(E, "Term `"+Main.SMTPS[ax].Identity.Onion+"`"); }
			}
		
		cx = Main.CSP.length;
		for (int ax=0;ax<cx;ax++) {
			try {	
				Log("Terminate Public control port`"+Main.CSP[ax].Identity[0].Onion+"`\n");
				Main.CSP[ax].End();
				} catch(Exception E) { Config.EXC(E, "Term `"+Main.CSP[ax].Identity[0].Onion+"`"); }
			}
		
			try {	
				Log("Terminate control port\n");
				Main.CS.End();
			} catch(Exception E) { Config.EXC(E, "Term ControlPort"); }
			
		
		System.exit(0);
		
	}
	
	///// functions ////////////
		
	private void SA_MKLIST(String[] Tok)  throws Exception {
			SrvIdentity S = SRVS[CurSrv];	
			if (Tok.length<3) {
				Reply(false,"Syntax error, parameter required");
				return;
				}
			
			String list = Tok[1].trim().toLowerCase();
			if (!list.endsWith(".list") || list.contains("@")) {
				Reply(false,"Syntax error, use localpart only");
				return;
				}
			
			String owner = J.getMail(Tok[2], true);
			String title= (Tok.length>3) ? Tok[3].trim() : "" ;
			String param = (Tok.length>4) ? Tok[4].toUpperCase() : "";
						
			if (owner==null) {
				Reply(false,"Invalid owner mail address");
				return;
				}
						
			if (S.CheckMailingList(list)) {
				Reply(false,"List arleady exists");
				return;
				}
			
			String Pwl=J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars); 
			
			MailingList ML = S.CreateMailingList(
					list, title, owner,
					Pwl,
					param.contains("/OPEN"),
					param.contains("/PGP"))
					;
			
			Log("Mailing list create `"+list+"@"+S.Onion+"`\n");
			
			HashMap<String,String> H = new HashMap<String,String>();
			H.put("from", list+"@"+S.Onion);
			H.put("to", owner);
			H.put("subject", "Mailing list");
			H.put("mime-version", "1.0");
			H.put("content-type", "text/plain; charset=iso-8859-1");
			H.put("content-transfer-encoding", "8bit");
			
			String msg="This is the new mailing list:\n"+list+"@"+S.Onion+"\nThis is the password:\n"+Pwl+"\n";

			try {
				S.SendMessage(owner, H, msg);
				} catch(Exception E) {
					if (Config.Debug) E.printStackTrace();
					
					ML.Destroy();
					String em=E.getMessage();
					if (em==null || !em.startsWith("@")) em="Owner mail error"; 
					if (em.startsWith("@")) em="Error: "+em.substring(1)+" (remote)";
					em+=" Mail=`"+owner+"`";
					Reply(false,em);
					return;
				}
			ML.Save();
			ML.Close();
			Reply(true,Pwl);
	}
	
	private void SA_SSLInfo() throws Exception {
			SrvIdentity S = SRVS[CurSrv];	
			String rs="ver="+Main.getVersion()+"\n";
			rs+="souceid="+Main.CompiledBy+"\n";
			rs+="onion="+S.Onion+"\n";
			rs+="nick="+S.Nick+"\n";
			rs+="maxmsgsize="+S.MaxMsgSize+"\n";
			rs+="maxmsgxuser="+S.MaxMsgXuser+"\n";
			rs+="maxspamxuser="+S.MaxSpamEntryXUser+"\n";
			rs+="isssl="+(S.isSSL ? 1:0)+"\n";
			rs+="relay="+(S.CanRelay ? 1:0)+"\n";
			rs+="random="+J.RandomString(16)+"\n";
			rs+="date="+S.TimeString()+" "+Long.toString(S.Time() %1000L)+"\n";
			rs+="runstring="+S.GetRunString()+"\n";
			
			for ( String K :S.SSlInfo.keySet() ) rs+="i_ssl_"+K+"="+S.SSlInfo.get(K)+"\n";
			
			rs+="c_ssl_oid="+S.MyCert.getSigAlgOID()+"\n";
			rs+="c_ssl_id="+Stdio.Dump(S.MyCert.getSerialNumber().toByteArray())+"\n";
			rs+="c_ssl_from="+new Date(Long.parseLong(S.SSlInfo.get("from")))+"\n";
			rs+="c_ssl_to="+new Date(Long.parseLong(S.SSlInfo.get("to")))+"\n";
			rs+="c_ssl_type="+S.MyCert.getType()+"\n";
			rs+="c_ssl_key_md5="+Stdio.Dump(Stdio.md5(S.MyCert.getPublicKey().getEncoded()))+"\n";
			rs+="c_ssl_md5="+Stdio.Dump(Stdio.md5(S.MyCert.getEncoded()))+"\n";
			rs+="c_ssl_sha1="+LibSTLS.GetCertHash(S.MyCert);
			rs=rs.trim();
			ReplyA(true,"OnionMail",rs.split("\n"));
			}
	
	private void SA_SEND(String[] Tok)  throws Exception {
		SrvIdentity S=SRVS[CurSrv];
		String from = "server@"+S.Onion;
		String to = J.getMail(Tok[1],false);
		if (to==null) {
			Reply(false,"Invalid address");
			return;
			}
		Reply(true,"Send message, end with \".\"");
		HashMap <String,String> H = J.ParseHeaders(br);
		H = J.FilterHeader(H);
		H.put("from",from);
		H.put("to", to);
		H.put("date", S.TimeString());
		H.put("errors-to","<>");
		H.put("x-generated", "control-port");
				
		String st="";
		while(true) {
			String li = br.readLine();
			if (li==null) throw new Exception("@Disconnected");
			li=li.replace("\r", "");
			li=li.replace("\n", "");
			if (li.compareTo(".")==0) break;
			st+=li+"\r\n";
			if (st.length()>128384) throw new Exception("message too big");
		}
		
		try {
			Log(Config.GLOG_Event,"Control.Send `"+J.getDomain(to)+"`");
			S.SendRemoteSession(to, "server@"+S.Onion, H,st,null,false);
			Reply(true,"Id=Nothing");
		} catch (Exception E) {
			String ms = E.getMessage()+"";
			if (ms.startsWith("@")) {
				Reply(false,ms.substring(1));
				Log(Config.GLOG_Event,"Error: "+ms.substring(1));
			} else {
				Reply(false,"Error");
				Config.EXC(E, "ControlPort.Send"); 
			}
		}
	}
	
	private void SA_LISTOP(String[] Tok)  throws Exception {  ///nuova!
		String list = J.getMail(Tok[1], true);
		if (list==null) {
			Reply(false,"Invalid list mail");	
			return;
			}
		String llp = J.getLocalPart(list);
		String usr = J.getMail(Tok[2], true);
		
		if (list==null || !llp.endsWith(".list")) {
			Reply(false,"Invalid list address");
			return;
			}
		
		if (usr==null) {
			Reply(false,"Invalid user address");
			return;
			}
				
		String srv = J.getDomain(list);
		
		int cx= SRVS.length;
		
		CurSrv=-1;
		for (int ax=0;ax<cx;ax++) if (SRVS[ax].Onion.compareTo(srv)==0) { CurSrv=ax; break; }
		
		if (CurSrv==-1) {
			Reply(false,"List not found in this server");
			return;
			}
		
		SrvIdentity S = SRVS[CurSrv];
		if (!S.CheckMailingList(llp))  {
			Reply(false,"List not found ");
			return;
			}
		
		MailingList ML = S.OpenMailingList(llp);
		MLUserInfo U = null;
	if (!roote) {	
		
		U= ML.GetUsr(usr);
		if (U==null || U.Type==MailingList.TYP_Del) {
			ML.Close();
			throw new Exception("@Access denied");
			}
	
		byte[] v = Stdio.md5(Tok[3].getBytes());
		for (int ax=0;ax<16;ax++) if (U.Pass[ax]!=v[ax]) {
				ML.Close();
				throw new Exception("@Access denied");
				}
		} else U = ML.NewInfo(MailingList.TYP_Admin, "sysop@"+S.Onion, J.RandomString(32));
			
	curmail = usr+" in "+list;
	if (U.Type==MailingList.TYP_Admin) curmail+=" Admin";
	Reply(true,"List Area ["+curmail+"]");
	
	while(true) {
		String li =ReadLn();
		if (li==null) break;
		li=li.trim();
		Tok=li.split("\\s+");
		String cmd=Tok[0].trim();
		cmd=cmd.toLowerCase();
		int pa = Tok.length;
		
		if (cmd.compareTo("exit")==0) break;
		if (cmd.compareTo("quit")==0) break;
		
		if (cmd.compareTo("access")==0) { ReplyAccess(); continue; }
		
		if (cmd.compareTo("unsubscribe")==0) {
			ML.DelUsr(U.Address);
			ML.Save();
			if (!serveruser || !roote) {
				ML.Close();
				break;
				}
			Reply(true,"Removed");
			}
		
		if (cmd.compareTo("passwd")==0 && pa>1) {
			U.Pass = Stdio.md5(Tok[1].getBytes());
			ML.SetUsr(U);
			Reply(true);
			continue;
			}
		
		if (cmd.compareTo("getrulez")==0) {
			String fr = ML.GetRulezFile();
			if (!new File(fr).exists()) {
				Reply(false,"No rulez file!");
				continue;
				}
			MailBoxFile ru = new MailBoxFile();
			ru.OpenAES(fr, S.Sale, false);
			while(true) {
				li = ru.ReadLn();
				if (li==null) break;
				li+="\r\n";
				O.write(li.getBytes());
			}
			ru.Close();
			O.write(".\r\n".getBytes());
			continue;
		}

		/////////////////////
		if ((!serveruser || !roote) && U.Type!=MailingList.TYP_Admin) {
			Reply(false,"WTF ???");
			continue;
			}
		
		if (cmd.compareTo("elist")==0) {
			 SA_EXITLIST(Tok);
			continue;
		}
/*		
		if (cmd.compareTo("par")==0) {
		if (J.getDomain(list).compareTo(SRVS[CurSrv].Onion)==0) {
			try {
				String s;
				if (Tok.length==3) 	s = SRVS[CurSrv].UserMSGParam(llp, Tok[1], Tok[2]); else s = SRVS[CurSrv].UserMSGParam(llp, "" , "");
				s=s.trim();
				ReplyA(true,"Parameters",s.split("\\n+"));
				} catch(Exception MR) {
					String s= MR.getMessage()+"";
					if (s.startsWith("@")) Reply(false,s.substring(1)); else Reply(false,"Error");
					Log(s.startsWith("@") ? Config.GLOG_Bad : Config.GLOG_Event , s);
				}
			} else Reply(false,"Access denied");
		continue;
		}*/
		
		if (cmd.compareTo("mode")==0 && pa>2) {
			String nu = J.getMail(Tok[1], false);
			if (nu==null) {
				Reply(false,"Invalid user name");
				continue;
				}
			MLUserInfo Ut =ML.GetUsr(nu);
			if (Ut==null) {
				Reply(false,"User not found");
				continue;
				}
			if (Tok[2].toLowerCase().contains("admin")) Ut.Type = MailingList.TYP_Admin; else Ut.Type = MailingList.TYP_Usr;
			boolean bit = ML.SetUsr(Ut);
			Reply(bit,Integer.toString(Ut.Type,36)+" "+Ut.Address);
			continue;
		}
		
		if (cmd.compareTo("invite")==0 && pa>1) {
			String nu = J.getMail(Tok[1], false);
			if (nu==null) {
				Reply(false,"Invalid user name");
				continue;
				}
			
			try {
				String Pwl = J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
				String msg="You are invited by "+U.Address+" to the "+ML.LocalPart+"@"+S.Onion+" mailing list\n"+"This is your password: "+Pwl;
				HashMap <String,String> H = new HashMap <String,String>();
				H.put("from", ML.LocalPart+"@"+S.Onion);
				H.put("to", nu);
				H.put("subject", "Mailing list invitation");
				S.SendMessage(nu, H, msg);
				boolean bit = ML.SetUsr(ML.NewInfo(MailingList.TYP_Usr, nu, Pwl));
				Reply(bit);	
			} catch(Exception E) {
				Reply(false,"Send message Error: `"+E.getMessage().replace("@", "")+"`");
			}
			continue;
			}
		
		if (cmd.compareTo("remove")==0) {
				String nu = J.getMail(Tok[1], false);
					if (nu==null) {
						Reply(false,"Invalid user name");
						continue;
						}
				ML.DelUsr(nu);
				Reply(true);
				continue;
				}
			
		if (cmd.compareTo("list")==0) {
			ML.Rewind();
			Reply(true);
			while(true) {
				MLUserInfo Ut = ML.Read();
				if (Ut==null) break;
				if (Ut.Type==MailingList.TYP_Del) continue;
				String st = Integer.toString(Ut.Type,36)+" "+Ut.Address+"\r\n";
				O.write(st.getBytes());
				}
			O.write(".\r\n".getBytes());
			continue;
		}
	
		if (cmd.compareTo("delete")==0 && pa==2 && Tok[1].compareTo(ML.LocalPart)==0) {
			boolean bit = ML.Destroy();
			if (!bit) {
				Reply(false,"Error");
				continue;
			}			
			break;
		}
		
		if (cmd.compareTo("setrulez")==0) {
			String fr = ML.GetRulezFile();
			MailBoxFile ru = new MailBoxFile();
			ru.OpenAES(fr, S.Sale, true);
			Reply(true,"Enter message, ending with \".\" on a line by itself");
			while(true) {
				li = ReadLn();
				if (li==null) return;
				if (li.compareTo(".")==0) break;
				ru.WriteLn(li);
			}
			ru.Close();
			Reply(true,"Message saved");
			continue;
		}
		
		
		Reply(false,"WTF ???");
		}
		ML.Save();
		ML.Close();
	}
	
	
	
	private void SA_ADDUSR(String[] Tok,boolean isPassWd) throws Exception {
			String smtpp;
			String pop3p;
			String user;
			int le = Tok.length;
			if (le>1) user = Tok[1].trim().toLowerCase(); else user=J.RandomString(8);
			if (le>2) smtpp = Tok[2].trim(); else smtpp=J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
			if (le>3) pop3p = Tok[3].trim(); else pop3p=J.GenPassword(Config.PasswordSize, Config.PasswordMaxStrangerChars);
			
			if (
						!user.matches("[a-z0-9\\-\\_\\.]{3,16}") 	|| 
						user.compareTo("server")==0 					|| 
						user.endsWith(".onion") 								|| 
						user.endsWith(".o") 									||
						user.endsWith(".list") 									|| 
						(!roote && user.endsWith(".sys"))				||
						(!roote && user.endsWith(".app"))				||
						(!roote && user.endsWith(".sysop"))			||
						(!roote && user.endsWith(".op"))				|| 
						user.startsWith(".") 									|| 
						user.endsWith(".") 										|| 
						user.contains("..")) 									{
				
						Reply(false,"Invalid user Name");
						return;
				}
			
			if (smtpp.length()<Config.PasswordSize) {
				Reply(false,"SMTP pasword too short");
				return;
				}
			
			if (pop3p.length()<Config.PasswordSize) {
				Reply(false,"POP3 pasword too short");
				return;
				}
			
			SrvIdentity S = SRVS[CurSrv];
			if (!isPassWd && S.UsrExists(user)) {
				Reply(false,"User arleady exists");
				return;
				}
			
			HashMap <String,String> P = new HashMap <String,String>();
			P.put("lang", S.DefaultLang);
			P.put("flag", Const.USR_FLG_TERM);
			
			S.UsrCreate(user,pop3p, smtpp, 1,P);
			
			ReplyA(true,"New user created",new String[] {
					"Mail="+user+"@"+S.Onion,
					"User="+user,
					"SMTPPasswd="+smtpp,
					"POP3Passwd="+pop3p,
					"Server="+S.Onion,
					"MsgSize="+S.MaxMsgSize,
					"MaxMsg="+S.MaxMsgXuser,
					"MsgOld="+Config.MailRetentionDays,
					"Exit="+(S.EnterRoute ? "Y":"N"),
					"Inet="+(S.EnterRoute ? S.ExitRouteDomain : S.Onion) ,
					"QFDN="+ S.Onion		})
					;
			
			Log(Config.GLOG_Event, "NewUser Created `"+user+"`");
			
			pop3p="X";
			smtpp="X";
			pop3p=null;
			smtpp=null;
			System.gc();
			
	}
	
	
	public void run() {
		
		try {
			BeginSession();		
			
		} catch(Exception E) {
			if (isConnected()) {
				String st = E.getMessage();
				if (st==null) st="Exception "+E.toString();
				
				if (st.startsWith("@")) {
					try { Reply(false,st.substring(1)); } catch(Exception I) {}
					close();
					
					if (Config.Debug) Config.EXC(E, "ControlSession"); else Log("ControlSession Fatal Error "+st+"\n");
					} else {
					Config.EXC(E, "ControlSession");
				//	E.printStackTrace();
					close();
					}
				}
			}
		
		if (isConnected()) {
			try { Reply(false,"WTF ???"); } catch(Exception i) {}
			close();
			}
		sok=null;
		in=null;
		br=null;
		O=null;
		EndTime=1;
		try { ParentServer.Garbage(); } catch(Exception E) { Config.EXC(E, Mid.Nick+".ParentGarbage"); }
	}
	
	ControlSession(ControlService pr,Socket soki) throws Exception {
		super();
		Config=pr.Config;
		ParentServer= pr;
		SRVS=pr.Identity;
		sok=soki;
		in = new DataInputStream(sok.getInputStream());
		br = new BufferedReader(new InputStreamReader(in));
		O = sok.getOutputStream();
		EndTime = System.currentTimeMillis() + Config.MaxTTLControlSession;
		start();
		}
	
	public void close() {
			try { sok.close(); } catch(Exception i) {}
			try { in.close(); } catch(Exception i) {}
			try { br.close(); } catch(Exception i) {}
			try { O.close(); } catch(Exception i) {}
		}
	
	public boolean isConnected() { 
			if (sok==null) return false;
			return sok.isConnected() && !sok.isClosed(); 
			}
	
	public String ReadLn() throws Exception { return br.readLine(); }
	public void Write(String st) throws Exception { O.write(st.getBytes()); }
	
	
	public boolean isOld() { return System.currentTimeMillis()> EndTime; }
	
	public void End() {
		close();
		try {this.interrupt(); } catch(Exception I) {}
	}
	
	private void Reply(boolean state) throws Exception { Reply(state, null); }
	
	private void Reply(boolean state, String data) throws Exception {
		String s = state ? "+OK" : "-ERR";
		if (data!=null && data.length()>0) s+=" "+data;
		s=s.trim();
		s+="\r\n";
		O.write(s.getBytes());
	}
	private void ReplyA(boolean state,String Msg, String[] data) throws Exception {
		String s = state ? "+OK" : "-ERR";
		int cx = data.length;
		if (cx>0) s+=" "+Msg.trim();
		for (int ax=0;ax<cx;ax++) {
			if(data[ax].compareTo(".")==0) data[ax]=". ";
			s+="\r\n"+data[ax];
			}
		s=s.trim();
		s+="\r\n.\r\n";
		O.write(s.getBytes());
	}
	
	
	
	
	
	
	
	//////////////////////////
	
		public  Pop3Cmd getcmd() throws Exception{
			Pop3Cmd Q = new Pop3Cmd();
	
			String li="";
			li=br.readLine();
			if (li==null) throw new Exception("INTP.CMD.1 Incomplete I/O sequence");
			li=li.trim();
			
			String[] tok = li.split(" ",3);
			int pc = tok.length;
			if (pc<2) throw new Exception("INTP.CMD.2 Incomplete I/O sequence");
			
			Q.cmd = tok[0].toUpperCase().trim();
			int cx = Integer.parseInt("0"+tok[1].trim());
			if (pc==3) {
				Q.par=tok[2].trim();
				Q.pars=Q.par.split(" ");
				}
			
			if (cx>0) {
				Q.lin = new String[cx];
				for (int ax=0;ax<cx;ax++) {
						li=br.readLine();
						if (li==null) throw new Exception("INTP.CMD.3 Incomplete I/O sequence");
						li=li.trim();
						Q.lin[ax]=li;
					}
			
			}
			return Q;
			
		} 

		public static String recmd( boolean ok, String rcod,String msg,String[] lin) {
				String ho="";
				int cx=0;
				
				if (ok) ho="+"; else ho="-";
				if (rcod==null | rcod=="") {
					if (ok) rcod="OK"; else rcod="ERR";
					}
				
				if (lin != null) cx = lin.length;
				
				rcod = rcod.replace(" ","");
				ho+=rcod+" "+cx+" "+msg+"\r\n";
				if (cx>0) for(int ax=0;ax<cx;ax++) ho+=lin[ax]+"\r\n";
				
				return ho;
			}
		
		public  RdCmd  rdcmd ()  throws Exception {
				RdCmd Q = new RdCmd();
				String li="";
				li=br.readLine();
				if (li==null) throw new Exception("INPT:INC.1 Empty cmd response");
				li=li.trim();
				if (li.charAt(0)=='+') Q.ok=true; else Q.ok=false;
				li=li.substring(1);
				li+="    ";
				String tok[] = li.split(" ", 3);
				int cx = Integer.parseInt("0"+tok[1]);
				Q.cod = tok[0].trim();
				Q.msg=tok[2].trim();
				if (cx>0) {
					Q.lin = new String[cx];
					try {
						for (int ax=0;ax<cx;ax++) {
							li=br.readLine();
							li=li.trim();
							Q.lin[ax]=li;
							}
					 } catch(Exception E) { throw new Exception("INPT:INC.2 Incomplete cmd response"); }
					}
						return Q;
				}

		
		public void Log(String st) { Config.GlobalLog(Config.GLOG_All, "CTRL", st); 	}
		public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_All, "CTRL", st); 	}		
		
protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify		
}
