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
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.sql.Date;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.zip.CRC32;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.openpgp.PGPUtil;


public class J {

	public static final int MaxLineWidth= 75;
	public static final int MaxHeaderLine=512;

	public static final String AllowedHeaders = 
						"|date|return-path|envelope-to|delivery-date|subject|mime-version|content-type|"+
						"from|to|sender|mailing-list|list-id|errors-to|precedence|x-priority|sensitivity|"+
						"importance|x-original-to|references|in-reply-to|x-beenthere|list-id|list-post|"+
						"list-help|content-transfer-encoding|errors-to|return-receipt-to|thread-index|"+
						"content-language|disposition-notification-to|x-original-sender|x-lastcount|x-vmat-server|"+
						"x-y-counter|message-id|cc|bcc|reply-to|x-ssl-transaction|x-hellomode|disposition-notification-to|"+
						"organization|list-unsubscribe|list-subscribe|envelope-to|x-ssl-transaction|auto-submitted|x-vmat-sign|"+
						"x-generated|return-path|errors-to|envelope-to|ccn|tkim-server-auth|x-vmat-address|x-failed-recipients|";
		
	public static final String NoFilterHost = 
						"|return-path|envelope-to|subject|content-type|mime-version|content-transfer-encoding|"+
						"from|to|sender|mailing-list|list-id|errors-to|precedence|"+
						"x-original-to|references|in-reply-to|x-beenthere|list-id|list-post|"+
						"list-help|errors-to|return-receipt-to|thread-index|x-vmat-server|"+
						"disposition-notification-to|x-original-sender|"+
						"message-id|cc|bcc|reply-to|disposition-notification-to|errors-to|x-vmat-sign|"+
						"|list-unsubscribe|list-subscribe|envelope-to|x-vmat-address|x-failed-recipients|";
	
	private final static char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    private static int[]  toInt   = new int[128];

    static {
        for(int i=0; i< ALPHABET.length; i++){
            toInt[ALPHABET[i]]= i;
        }
    }
    
    public static String IP2String(InetAddress A) {	//Without Java Fuffa
    	byte[] a = A.getAddress();
    	String ip="";
    	for (int ax=0;ax<4;ax++) {
    		ip+=Integer.toString((int)(255&a[ax]));
    		if (ax!=3) ip+=".";
    	}
    	return ip;
    }
    
    public static String TimeStandard(long tcr) {
    	return TimeStandard(tcr,"+0000");    	
    } 
    
    public static String TimeStandard(long tcr,String fus) {
    	String[] M = new String [] { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    	//String[] S = new String [] { "Sun" , "Mon", "Tue", "Wed", "Thu", "Fri", "Sat","Sun"};
    	//SUNDAY, MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY
    	GregorianCalendar  c = new GregorianCalendar();
    	c.setTime(new Date(tcr));
    	 
    	String q = "???";
    
    	 switch (c.get(Calendar.DAY_OF_WEEK)) {
    	 			case Calendar.SUNDAY:
    	 				q="Sun";
    	 				break;
    	 			case Calendar.MONDAY:
    	 				q="Mon";
    	 				break;
    	 			case Calendar.TUESDAY:
    	 				q="Tue";
    	 				break;
    	 			case Calendar.WEDNESDAY:
    	 				q="Wed";
    	 				break;
    	 			case Calendar.THURSDAY:
    	 				q="Thu";
    	 				break;
    	 			case Calendar.FRIDAY:
    	 				q="Fri";
    	 				break;
    	 			case Calendar.SATURDAY:
    	 				q="Sat";
    	 				break;
    	 	}
    			
    	q+=", "; //Timestandard!
    	q+=c.get(Calendar.DAY_OF_MONTH)+" ";
    	q+=M[c.get(Calendar.MONTH)]+" ";
    	q+=J.Int2Str(c.get(Calendar.YEAR), 4)+" ";
    	q+=J.Int2Str(c.get(Calendar.HOUR_OF_DAY), 2)+":";
    	q+=J.Int2Str(c.get(Calendar.MINUTE), 2)+":";
    	q+=J.Int2Str(c.get(Calendar.SECOND), 2)+" "+fus;
    	return q;
    	
    } 
    
    
	 public static String Base64Encode(byte[] buf){
        int size = buf.length;
        char[] ar = new char[((size + 2) / 3) * 4];
        int a = 0;
        int i=0;
        while(i < size){
            byte b0 = buf[i++];
            byte b1 = (i < size) ? buf[i++] : 0;
            byte b2 = (i < size) ? buf[i++] : 0;

            int mask = 0x3F;
            ar[a++] = ALPHABET[(b0 >> 2) & mask];
            ar[a++] = ALPHABET[((b0 << 4) | ((b1 & 0xFF) >> 4)) & mask];
            ar[a++] = ALPHABET[((b1 << 2) | ((b2 & 0xFF) >> 6)) & mask];
            ar[a++] = ALPHABET[b2 & mask];
        }
        switch(size % 3){
            case 1: ar[--a]  = '=';
            case 2: ar[--a]  = '=';
        }
        return new String(ar);
    }
	 
	 public static byte[] Base64Decode(String s){
       try {
			int delta = s.endsWith( "==" ) ? 2 : s.endsWith( "=" ) ? 1 : 0;
	        byte[] buffer = new byte[s.length()*3/4 - delta];
	        int mask = 0xFF;
	        int index = 0;
	        for(int i=0; i< s.length(); i+=4){
	            int c0 = toInt[s.charAt( i )];
	            int c1 = toInt[s.charAt( i + 1)];
	            buffer[index++]= (byte)(((c0 << 2) | (c1 >> 4)) & mask);
	            if(index >= buffer.length){
	                return buffer;
	            }
	            int c2 = toInt[s.charAt( i + 2)];
	            buffer[index++]= (byte)(((c1 << 4) | (c2 >> 2)) & mask);
	            if(index >= buffer.length){
	                return buffer;
	            }
	            int c3 = toInt[s.charAt( i + 3 )];
	            buffer[index++]= (byte)(((c2 << 6) | c3) & mask);
	        }
	        return buffer;
       } catch(Exception E) {
    	   return new byte[0];
       }
    }  
	
	public static String[] Data2Lines(byte[] data,String extra) {
		CRC32 C = new CRC32();
		
		int cx = data.length;
		C.update(data);
		long crc = C.getValue();
		
		String t0 = Base64Encode(data);
		
		int dx = t0.length();
		int li = dx>>5;
		if ((dx&31)!=0) li++;
		li++;
		String[] RS = new String[li];
		RS[0] = cx+" "+Long.toString(crc,36)+" "+extra.trim();
		
		int ax=0;
		for (ax=1;ax<li;ax++) {
			if (t0.length()>31) {
				RS[ax] = t0.substring(0, 31);
				t0=t0.substring(31);
				} else { 
				RS[ax]=t0;
				t0="";
				}
			
		}
		RS[ax-1]+=t0;
				
		return RS;
	} 
	 
	public static byte[] Lines2Data(String[] LI) throws Exception {
		LI[0]=LI[0].trim();
		String[] tok = LI[0].split(" ");
		if (LI==null || LI.length<1 || tok.length<2) throw new Exception("@500 Invalid ASCII data");
		int cx = LI.length;
		//int siz = Integer.parseInt("0"+tok[0].trim());
		long crc = Long.parseLong(tok[1].trim(),36);
		String t0="";
		for (int ax=1;ax<cx;ax++) t0+=LI[ax].trim();
		byte[] data = Base64Decode(t0);
		t0="";
		CRC32 C = new CRC32();
		C.update(data);
		if (C.getValue()!=crc) throw new Exception("@500 Corrupted ASCII data");
		return data;	
	}
	
	public  static byte[] Lines2DataX(String[] LI,String[] EXTRA) throws Exception {
		LI[0]=LI[0].trim();
		String[] tok = LI[0].split(" ");
		if (LI==null || LI.length<1 || tok.length<2) throw new Exception("@500 Invalid ASCII data");
		int cx= tok.length-1;
		if (EXTRA.length<cx) cx=EXTRA.length;
		for (int ax=0;ax<cx;ax++) EXTRA[ax]=tok[ax+1];
		
		cx = LI.length;
		
		//int siz = Integer.parseInt("0"+tok[0].trim());
		
		long crc = Long.parseLong(tok[1].trim(),36);
		String t0="";
		for (int ax=1;ax<cx;ax++) t0+=LI[ax].trim();
		byte[] data = Base64Decode(t0);
		t0="";
		CRC32 C = new CRC32();
		C.update(data);
		if (C.getValue()!=crc) throw new Exception("@500 Corrupted ASCII data");
		return data;	
	}
	
	public static HashMap<String,String> ParseHeaders(BufferedReader I) throws Exception {
		String in="";
		for (int ax=0;ax<MaxHeaderLine;ax++) {
			String li = I.readLine();
			if (li==null) break;
			li=li.replace("\r", "");
			li=li.replace("\n", "");
			in+=li+"\n";
			if (li.length()==0) break;
		}
		return ParseHeaders(in.split("\\n"));
	} 	
	
	public static HashMap<String,String> ParseHeadersEx(BufferedReader I) throws Exception {
		String in="";
		for (int ax=0;ax<MaxHeaderLine;ax++) {
			String li = I.readLine();
			if (li==null) break;
			li=li.trim();
			if (li.length()==0) break;
			in+=li+"\n";
			if (li.length()==0) break;
		}
		return ParseHeaders(in.split("\\n"));
	} 	
	
	public static HashMap<String,String> ParseHeaders(String[] li) {
		HashMap<String,String> Q = new HashMap<>();
		int cx=li.length;
		String lastkey=null;
		for (int ax=0;ax<cx;ax++) {
			String l = li[ax];
			if(l.length()==0) continue;
			int primo = l.codePointAt(0);
			if (primo==32 || primo==9) {
				if (lastkey==null) continue;
				String t = Q.get(lastkey);
				t+=" "+l.trim();
				Q.put(lastkey, t);
				continue;
				}
			
			l=l.trim();
			String[] Tok = l.split("\\:",2);
			if (Tok.length!=2) continue;
			Tok[0]=Tok[0].trim();
			Tok[0]=Tok[0].toLowerCase();
			Tok[1]=Tok[1].trim();
			Q.put(Tok[0], Tok[1]);
			lastkey=Tok[0];
			}
		return Q;
	} 
	
	public static String[] WordWrap(String St,int maxsz) {
		St = St.replace("\n", " ");
		St = St.replaceAll("\\s+", " ");
		if (St.length()<=maxsz) return new String[] { St };
		String[] Tok = St.split("\\s");
		String Q="";
		String Cl="";
		int cx = Tok.length;
		for (int ax=0;ax<cx;ax++) {
			if ((Cl.length() + Tok[ax].length()+1) >=maxsz) {
				Q+=Cl+Tok[ax]+"\n";
				Cl="";
				} else {
				Cl = Cl+Tok[ax]+" ";	
				}	
		}
		if (Cl.length()>0) Q+=Cl+"\n";
		Q=Q.trim();
		return Q.split("\\n");
	}
	
	public static String[] WordWrapNT(String St,int maxsz) {
		int cx = St.length();
		if (cx<=maxsz) return new String[] { St };
		String q="";
		int cmp=0;
		for (int ax=0;ax<cx;ax++) {
			if (cmp==maxsz) {
					q+="\n";
					cmp=0;
					}
			char c = St.charAt(ax);
			q+=c;
			if (c==13 || c==10) cmp=0; else cmp++;
			}
		q=q.trim();
		return q.split("\\n");
	}
	
	
	public static HashMap<String,String> ParsePair(String st,String RegExp) {
		HashMap<String,String> Q = new HashMap<>();
		String[] li = st.split(RegExp);
		int cx=li.length;
		for (int ax=0;ax<cx;ax++) {
			String l = li[ax].trim();
			String[] Tok = l.split("\\=",2);
			if (Tok.length!=2) continue;
			Tok[0]=Tok[0].trim();
			Tok[0]=Tok[0].toLowerCase();
			Tok[1]=Tok[1].trim();
			Q.put(Tok[0], Tok[1]);
			}
		return Q;
	} 
	
	public static String BeautifulHeader(String st) {
		String ABR="-smtp-http-mime-id-dkim-ip-ssl-tls-url-https-uri-uidl-tkim-tor-vmat-mat-";
		st=st.trim().toLowerCase();
		String Tok[] = st.split("\\-");
		String Q="";
		int cx = Tok.length;
		for (int ax=0;ax<cx;ax++) {
			if (Tok[ax].length()==0) {
				Q+="\n";
				continue;
				}
			if (ABR.contains("-"+Tok[ax]+"-")) {
				Q+=Tok[ax].toUpperCase()+"\n";
			} else {
				String p = (""+Tok[ax].charAt(0)).toUpperCase();
				Q+=p+Tok[ax].substring(1)+"\n";
			}
		}
		
		Q=Q.trim();
		return Q.replace('\n', '-');
	}

	public static String Implode(String[] a,String glue) {
		String Q="";
		int cx=a.length-1;
		for (int ax=0;ax<=cx;ax++) {
			Q+=a[ax];
			if (ax!=cx) Q+=glue;
		}
		return Q;
	}
	
	public static String IPFilter(String in) {
		return in.replaceAll("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}","0.0.0.0");
	}
	
	
	
	
	public static HashMap<String,String> AddMsgID(HashMap<String,String> h,String domain) {
		
		String s0="";
		for ( String K :h.keySet() ) s0+=K+"\t"+h.get(K)+"\n";
		s0+=domain;
		
		byte[] id = Stdio.md5(s0.getBytes());
		s0=J.md2st(id);
		id=null;
		h.put("message-id", "<"+s0+"@"+domain+">");
		return h;
	}
	
	public static HashMap<String,String> FilterHeader(HashMap<String,String> h) {
		HashMap<String,String> Q = new HashMap<>();
	
		for ( String K :h.keySet() ) {
			String k1 = "|"+K.replace("|","")+"|";

			if (AllowedHeaders.contains(k1)) {
				K=K.toLowerCase();
				String v = h.get(K);
				if (!NoFilterHost.contains(k1)) v = IPFilter(v);
				if (K.compareTo("message-id")==0) continue;
				Q.put(K, v);
			}
		}
		if (Q.containsKey("x-vmat-server")) {
			String q = Q.get("x-vmat-server");
			if (!q.matches("[0-9a-z]{16}\\.onion")) Q.put("x-vmat-server", "iam.onion");
			}
		return Q;
	}
	
	public static String CreateHeaders( HashMap<String,String> h) {
		String Q="";
		for ( String K :h.keySet() ) {
			String hk = BeautifulHeader(K);
			String vl  = h.get(K);
			if (vl==null) vl="NULL";
			vl=vl.trim();
			if (vl.length()>MaxLineWidth) {
				String[] Tok = WordWrap(vl,MaxLineWidth);
				vl = Implode(Tok,"\r\n\t");
				}
			Q+=hk+": "+vl+"\r\n";
		}
		return Q;	
	}
	
	public static String getMailEx(String in) {
		String rs = getMail(in,false);
		if (rs!=null) return rs;
	
		String tm="";
		int cx = in.length();
		int st=0;
		for (int ax=0;ax<cx;ax++) {
			char c = in.charAt(ax);
			if (c=='>' && st==1) {
				st=2;
				break;
				}
			if (st==1) tm=tm+c;
			if (c=='<' && st==0) {
				st=1;
				}
		}
		if (st!=2) return null;
		return getMail(tm,false);
	}
	
	public static String getMail(String in,boolean onion) {
		in = getLtGt(in);
		if (in==null) return null;
		in=in.trim();
		String t0=in+"\n";
		if (onion) {
			if (t0.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.onion\\n")) return in;
			} else {
			if (t0.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-_]+\\.[A-Za-z]{2,5}\\n")) return in;	
			}
		return null;
	}
	
	public static String getLtGt(String in) {
			in = in.trim();
			if (in.length()==0) return null;
			if (in.charAt(0)=='<') in=in.substring(1);
			int cx = in.length()-1;
			if (cx<2) return null;
			if (in.charAt(cx)=='>') {
				in=in.substring(0,cx);
				in=in.trim();
				}
			return in;
	}
				
	public static BufferedReader getLineReader(InputStream i) {
		DataInputStream in = new DataInputStream(i);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		return br;
	}	
	
		public static BufferedReader getLineReader8(InputStream i) {
			try {
				DataInputStream in = new DataInputStream(i);
				BufferedReader br = new BufferedReader(new InputStreamReader(in,"UTF-8"));
				return br;
			} catch(Exception I) { return null; }
	}	
	
	public static int parseInt(String st) {
		try { return Integer.parseInt(st); } catch(Exception E) { return 0; }
	}	
	
	public static long parseLong(String st) {
		try { return Long.parseLong(st); } catch(Exception E) { return 0; }
	}	
	
	public static String getLocalPart(String mail) {
		if (mail==null) return null;
		if (mail.contains("<")) mail=getLtGt(mail);
		String[] Tok = mail.split("\\@",2);
		if (Tok.length!=2) return null;
		String u = Tok[0].trim();
		u=u.toLowerCase();
		return u;
	}
	
	public static String getDomain(String mail) {
	if (mail.contains("<")) mail=getLtGt(mail);
		String[] Tok = mail.split("\\@",2);
		if (Tok.length!=2) return null;
		String u = Tok[1].trim();
		u=u.toLowerCase();
		return u;	
	}
	
	public static String RandomString(int sz) {
		byte[] s = new byte[sz];
		Stdio.NewRnd(s);
		String q="";
		for (int ax=0;ax<sz;ax++) q+=Long.toString((long)(255&s[ax]) % 36,36);
		return q;
	}
	
	public static String GenPassword(int sz,int mcs) {
		String PWLA="1234567890QAZXSWEDCVFRTGBNHYUJMKIOPLqwedsazxcvfrtgbnhyuioplkjmn";
		String PWLB="~|\\`'\"/*-+_<>,.:;@#[]+!{=}%)&?($^/";
		int PWLAL=PWLA.length();
		int PWLBL=PWLB.length();
		String q="";
		byte[] s = new byte[sz];
		Stdio.NewRnd(s);
		int cs=0;
		int r=0;
		for (int ax=0;ax<sz;ax++) {
			int c = (int)(255&s[ax]);
			c+=r;
			if (cs<mcs && (c>192)) {
				cs++;
				r+= c/PWLBL;
				c = c % PWLBL;
				q+=PWLB.substring(c,c+1);
				} else {
				c+= c/PWLAL;					
				c = c % PWLAL;
				q+=PWLA.substring(c,c+1);
				}
			}
		return q;
	}
	
	public static boolean TCPRest(InetAddress ip,int port) {
		Socket sok=null;
		try {
			sok = new Socket(ip,port);
			sok.close();
			return true;
			} catch(Exception E) {
				if (sok!=null) try { sok.close(); } catch(Exception I) {}
				return false;
			}
	}
	
	public static Socket IncapsulateSOCKS(InetAddress ip,int port,String SockAddr ,int SockPort) throws Exception {
		
		Socket sok = new Socket(ip,port);
		InputStream TI = sok.getInputStream();
		OutputStream TO = sok.getOutputStream();
		int dx = SockAddr.length();
		int cx = 10+dx;
		byte[] req = new byte[cx];
		req[0] = 4;	//Socks 4
		req[1] = 1; //Connect
		Stdio.PokeB(2, SockPort, req);
		req[7] = 1; //Socks 4/a ip  0.0.0.1
		int bp = 9; //user "" Hsot:
		for (int ax=0;ax<dx;ax++) req[bp++] = (byte) (255&SockAddr.codePointAt(ax));

		TO.write(req);
		req = new byte[8];
		TI.read(req);
		
		if (req[1]!=0x5a) throw new SocketException("Socks: Error H"+Long.toHexString((long)(255&req[1])).toUpperCase()+" on "+SockAddr);
		return sok;
	}
	
	public static String MailOnion2Inet(Config C, String MailFrom,String ExitDomain) throws Exception {
		XOnionParser tor = XOnionParser.fromString(C,getDomain(MailFrom));
		MailFrom = J.getLocalPart(MailFrom)+"."+tor.Onion+"@"+ExitDomain;
		return MailFrom;
	}
	
	public static boolean isMailOnionized(String MailFrom) throws Exception {
		String lo = getLocalPart(MailFrom);
		String se = getDomain(MailFrom);
		if (!se.endsWith(".onion") && lo.endsWith(".onion")) return true;
		return false;
	}
	
	public static String MailInet2Onion(String MailFrom,String ExitDomain) throws Exception { //TODO Verifica!
		String E = "@503 Invalid Onion Exit Route Mail Address '"+MailFrom+"'";
		String lo = getLocalPart(MailFrom);
		if (getDomain(MailFrom).compareTo(ExitDomain)!=0) throw new Exception(E);
		if (!lo.endsWith(".onion")) throw new Exception(E);
		String[] Tok = lo.split("\\.+");
		int cx = Tok.length;
		if (cx<3) throw new Exception(E);
		cx-=2;
		String o = Tok[cx].trim();
		cx--;
		String l = "";
		for (int ax=0;ax<=cx;ax++) {
			l += Tok[ax].trim();
			if (ax!=cx) l+=".";
			}
		if (l.length()<4) throw new Exception(E);
		l+="@"+o+".onion";
		return l.toLowerCase().trim();
	}

	public static String MailInet2Onion(String MailFrom) throws Exception {
	String lo = getLocalPart(MailFrom);
		if (!lo.endsWith(".onion")) throw new Exception("@503 Invalid Onion Exit Route Mail Address `"+MailFrom+"`");
		String[] Tok = lo.split("\\.+");
		int cx = Tok.length;
		if (cx<3) throw new Exception("@503 Invalid Onion Exit Route Mail Address `"+MailFrom+"`");
		cx-=2;
		String o = Tok[cx].trim();
		cx--;
		String l = "";
		for (int ax=0;ax<=cx;ax++) {
			l += Tok[ax].trim();
			if (ax!=cx) l+=".";
			}
		if (l.length()<4) throw new Exception("@503 Invalid Onion Exit Route Mail Address `"+MailFrom+"`");
		l+="@"+o+".onion";
		return l.toLowerCase().trim();
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
	
	public static void Wipe(String fn,boolean fast) throws Exception {
		
		RandomAccessFile O =new RandomAccessFile(fn,"rw");
		try {
			try {
				long sz = O.length();
				O.seek(0);
				byte[] rnd = new byte[512];
				Stdio.NewRnd(rnd);
				O.write(rnd);
				O.write(rnd);
				if (!fast) {
					int cx =(int) Math.ceil(sz/512);
					for (int ax=0;ax<cx;ax++) {
						if ((ax&4) == 0) Stdio.NewRnd(rnd);
						O.write(rnd);
						}
					}
				O.close();
				} catch(Exception I) {
					try { O.close(); } catch(Exception II) {}
					throw I;
				}
			O=null;
			System.gc();
			
			FileOutputStream Q = new FileOutputStream(fn);
			Q.flush();
			Q.close();
			Q=null;
			System.gc();
			
			File F = new File(fn);
			if (!F.delete()) {
				if (F.exists()) throw new Exception("Can't delete Size="+F.length()); 
				}
			} catch(Exception F) { 
				F.printStackTrace();	
				throw new Exception("@500 Can't delete `"+fn+"` CAUSE="+F.getMessage());
				}
		}
	
	public static String MapPath(String path,String file) throws Exception {
		boolean xk=false;
		if (file.startsWith("$")) {
				file = Main.ProgPath+file.substring(1);
				file=file.replace("\\", "/");
				file=file.replace("//", "/");
				xk=true;
				}
		if (file.contains("/../") || file.contains("/./") || file.startsWith("../") || file.startsWith("./")) throw new Exception("Ugly file name `"+file+"`");
		if (file.indexOf('/')==0) return file;
		if (!xk) {
				if (path.endsWith("/")) file=path+file; else file=path+"/"+file;
				}
		file=file.replace("//", "/");
		return file;
	}
	
	public static String GetPath(String aq) throws Exception {
		if (aq.startsWith("$")) {
				aq = Main.ProgPath+aq.substring(1);
				aq=aq.replace("\\", "/");
				aq=aq.replace("//", "/");
				}	
			
		if (aq.contains("/../") || aq.startsWith("../") || aq.startsWith("./")) {
			String qaq =new File(aq).getCanonicalPath().replace('\\', '/');
			if (qaq.endsWith("/")) qaq=qaq.substring(0,qaq.length()-1);
			if (qaq.contains("/../") || qaq.contains("/./") || qaq.startsWith("../") || qaq.startsWith("./")) throw new Exception("Ugly path `"+aq+"` 1");
			aq=qaq;
			}		
		int qx = aq.lastIndexOf('/');
		if (qx==-1) {
			String qaq =new File(".").getCanonicalPath().replace('\\', '/');
			
			if (!qaq.endsWith("/")) qaq+="/";
			return qaq;
		}
		String pa = aq.substring(0,qx);
		if (aq.contains("/../") || aq.contains("/./") || aq.startsWith("../") || aq.startsWith("./")) throw new Exception("Ugly path `"+aq+"` 2");
		return pa+"/";
	}
	
	public static String GenCryptPass(String orgp) throws Exception {
		long sale = Stdio.NewRndLong() & 0x7FFFFFFFFFFFFFFFL;
		byte[] b = Stdio.md5a(new byte[][] { Long.toString(sale,36).getBytes() , orgp.getBytes("UTF-8") });
		return "$SCR{"+Long.toString(sale,35)+"@"+J.Base64Encode(b)+"}";
		} 

	public static boolean CheckCryptPass(String pwl,String passtover)  throws Exception {
		pwl=pwl.trim();
		if (!pwl.startsWith("$SCR{")) {
			if (pwl.compareTo(passtover)!=0) return false;
			return true;
			}
		String EE="Invalid scrambled password. Error: ";
		if (!pwl.contains("{") || !pwl.contains("}") || !pwl.contains("@")) throw new Exception(EE+"Syntax error");
		
		String[] Tok = pwl.split("\\{|\\@|\\}");
	
		if (Tok.length!=3) throw new Exception(EE+"Scrambled format "+Tok.length);
		if (Tok[0].compareToIgnoreCase("$SCR")!=0) throw new Exception(EE+"Scrambled filter");
		long sale=0;
		try { sale=Long.parseLong(Tok[1].trim(),35); } catch(Exception E) { throw new Exception(EE+"Invalid salt"); }
		byte[] b = null;
		try { b = J.Base64Decode(Tok[2].trim()); } catch(Exception E) { throw new Exception(EE+"Invalid hash"); }
		if (b.length!=16) throw new Exception(EE+"Invalid hash length");
		byte[] c = Stdio.md5a(new byte[][] { Long.toString(sale,36).getBytes() , passtover.getBytes("UTF-8") });
		for (int ax=0;ax<16;ax++) if (c[ax]!=b[ax]) return false;
		return true;
	}

	public static String md2st(byte[] b) {
			long[] H = Stdio.Lodsx(b, 8);
			int h = (H[0]<0) ? 1:0;
			h|=(H[1]<0) ?2:0;
			h^=0x7FC&(H[0]^H[1]);
			return Integer.toString(h,36)+Long.toString(H[0]&0x7FFFFFFFFFFFFFFL,36)+Long.toString(H[1]&0x7FFFFFFFFFFFFFFL,36);
		}

	public static String by2pass(byte[] b) throws Exception {
		String Alfab="1qazZAQ2wsxXSW3edcCDE4rfvVFR5tgbBGT6yhnNHY7ujmMJU8ikKI9olLO0pP<>,;.:-_@#+*[]{}~|\\!`\"?=$)%(&/^!";
		int ma = Alfab.length()-1;
		int cx = b.length;
		String q="";
		int ra=0x5a;
		for (int ax=0;ax<cx;ax++) {
			int bx = (int)(255&b[ax]);
			bx^=ra;
			ra = bx % ma;
			q+=Alfab.substring(ra,ra+1);
			ra>>=4;
			}
		return q;
	}

	public static byte[] HashMapPack(HashMap <String,String> M) throws Exception {
		int cx= M.size();
		byte[][] a = new byte[cx][];
		byte[][] b = new byte[cx][];
		int bp=0;
		for (String K:M.keySet()) {
			a[bp] = K.getBytes();
			b[bp] = M.get(K).getBytes();
			bp++;
			}
		
		return Stdio.MxAccuShifter(new byte[][] {
				Stdio.MxAccuShifter(a, Const.MX_MIddle)	,
				Stdio.MxAccuShifter(b, Const.MX_MIddle)	
				},Const.MX_HashMap,true);
		}
	
	public static HashMap <String,String> HashMapUnPack(byte[] i) throws Exception {
		byte[][] F = Stdio.MxDaccuShifter(i, Const.MX_HashMap);
		HashMap <String,String> M = new HashMap <String,String>();
		byte[][] a = Stdio.MxDaccuShifter(F[0], Const.MX_MIddle);
		byte[][] b = Stdio.MxDaccuShifter(F[1], Const.MX_MIddle);
		int cx=a.length;
		for (int ax=0;ax<cx;ax++)  M.put(new String(a[ax]), new String(b[ax]));
		return M;		
	}
	
	public static byte[] PackSrv(SrvIdentity S) throws Exception {
			
			HashMap <String,String> H = new HashMap <String,String>();
			H.put("ver", Long.toString(Main.VersionID,36));
			H.put("onion", S.Onion);
			H.put("nick", S.Nick);
			H.put("banner", S.Banner);
			H.put("pass", S.PassWd);
			
			return  Stdio.MxAccuShifter(new byte[][] {
						J.HashMapPack(H)					,
						J.HashMapPack(S.SSlInfo)		,
						S.KBL										},
						Const.MX_Server_Conf, true)
						;
			
		}
	
	public static void UnPakcSrv(SrvIdentity S,byte[] b) throws Exception {
		byte[][] F = Stdio.MxDaccuShifter(b, Const.MX_Server_Conf);
		
		HashMap <String,String> H = J.HashMapUnPack(F[0]);
		S.Onion = H.get("onion");
		S.Nick = H.get("nick");
		S.Banner = H.get("banner");
		S.PassWd = H.get("pass");
		S.SSlInfo = J.HashMapUnPack(F[1]);
		S.KBL = F[2];
	}
	
	public static byte[][] DerAesKey2(byte[] Sale,String Ders) throws Exception { //XXX Cambiare Key a 256bit
		byte[] b = Stdio.sha512a(new byte[][] { Sale, Ders.getBytes()});
		byte[][] k = new byte[][] { new byte[32] , new byte[16] };
		System.arraycopy(b, 0, k[0], 0, 31);
		System.arraycopy(b, 32, k[1], 0, 16);
		return k;
	}
	
	public static byte[][] DerAesKeyB2(byte[] Sale,byte[] Ders) throws Exception {
		byte[] b = Stdio.sha512a(new byte[][] { Sale, Ders });
		byte[][] k = new byte[][] { new byte[32] , new byte[16] };
		System.arraycopy(b, 0, k[0], 0, 31);
		System.arraycopy(b, 32, k[1], 0, 16);
		return k;
	}
	
	public static byte[][] DerAesKey(byte[] Sale,String Ders) throws Exception { //XXX Cambiare Key a 256bit
		byte[] b = Stdio.sha256a(new byte[][] { Sale, Ders.getBytes()});
		byte[][] k = new byte[2][16];
		System.arraycopy(b, 0, k[0], 0, 16);
		System.arraycopy(b, 16, k[1], 0, 16);
		return k;
	}
	public static byte[][] DerAesKeyB(byte[] Sale,byte[] Ders) throws Exception {
		byte[] b = Stdio.sha256a(new byte[][] { Sale, Ders});
		byte[][] k = new byte[2][16];
		System.arraycopy(b, 0, k[0], 0, 16);
		System.arraycopy(b, 16, k[1], 0, 16);
		return k;
	}
	
	public static byte[] Der2048(byte[] A,byte[] B) throws Exception {
		byte[] c = Stdio.sha512a(new byte[][] { A,B });
		byte[] e = c.clone();
		byte[] d = Stdio.sha512a(new byte[][] { c , A , B });
		byte[] f = d.clone();
		for (int ax=0;ax<64;ax++) {
			c[63&d[63&c[ax]]] ^= d[63&c[63&d[63&c[ax]]]];
			d[63&c[63&d[ax]]] ^= d[63&d[63&d[ax]]];
			}
		int b=0x5a;
		int a=0xa5;
		for (int ax=0; ax<64;ax++) {
		    b -= d[ax]^d[63^ax];
		    a +=c[ax]^c[63^ax];
			for (int bx=0;ax<64;ax++) {
				b+=d[63&c[63&e[63&f[bx^ax]]]];
				a-= c[63&d[63&f[63&f[63&(bx^ax^b)]]]];
				a^=d[a&63];
				b^=c[b&63];
				}
			c[ax&63]^=(byte)(a&255);
			d[ax&63]^=(byte)(b&255);
			}
		
		return Stdio.MulBlock(new byte[][] {c,f, d,e},64);				
	}

	public static String Limited(String st,int size) {
		int cx = st.length();
		if (cx<size) return st;
		if (size>5) {
			size-=5;
			return st.substring(0,size)+" ...";
			} else return st.substring(0,size-1);
	}
	
	public static String Spaced(String st,int size) {
		char[] rs = new char[size];
		int dx = st.length();
		for (int ax=0;ax<size;ax++) {
			if (ax<dx) rs[ax] = st.charAt(ax); else rs[ax]=' ';
			}
		return new String(rs);
	}
	
	public static String Int2Str(int n, int sz) {
		long  k =(long) Math.pow(10,sz+1);
		k+=n;
		int b;
		boolean s = (n<0);
		if (s) { 
				k=-k; 
				b=3; 
				} else b=2;
		
		String q = Long.toString(k);
		return q.substring(b);
		}
	
	public static void WipeRam(byte[] b) {
		if (b==null) return;
		
		int cx = b.length;
		for (int ax=0;ax<cx;ax++) b[ax]=0;
		}
	public static void WipeRam(byte[][] b) {
		if (b==null) return;
		int cx = b.length;
		for (int ax=0;ax<cx;ax++) {
			if (b[ax]==null) continue;
			int dx = b[ax].length;
			for (int bx=0;bx<dx;bx++)	b[ax][bx]=0;
			}
	}

	public static String GetLangSt(String Lang) throws Exception {
		InputStream i = Main.class.getResourceAsStream("/resources/langs");
		BufferedReader h = J.getLineReader(i);
		Lang=Lang.toLowerCase().trim();
		
		while(true) {
			String li = h.readLine();
			if (li==null) break;
			if (li.length()==0) continue;
			li=li.toLowerCase().trim();
			String[] st = li.split("\\=");
			if (st.length!=2) continue;
			if (st[0].contains(Lang) || st[1].compareTo(Lang)==0) {
					i.close();
					return st[1];
					}
		}
		return null;
	}

	public static String[][] SplitChunkLines(String[] I, int MaxC,String Splitter,String Excs) throws Exception {
		String[] C = new String[MaxC];
		int cb=0;
		int cx= I.length;
		C[0]="";
		for (int ax=0;ax<cx;ax++) {
			String s = I[ax].trim().replace("\n", "");
			
			if (s.length()==0 || s.compareTo(Splitter)==0) {
				cb++;
				C[cb]="";
				if (cb>=MaxC) throw new PException(Excs);
				} else C[cb] += s+"\n";
			}
		cb++;
		String[][] Q = new String[cb][];
		for (int ax=0;ax<cb;ax++) {
				Q[ax] = C[ax].trim().split("\\n+");
				}
		return Q;
	}
	
	public static boolean isMailMat(String addr) {
		String lp = J.getLocalPart(addr);
		String dn = J.getDomain(addr);
		if (lp==null || dn==null) return false;
		if (!dn.endsWith(".onion") && lp.endsWith(".onion")) return true;
		return false;
	}
	
	public static int[] MultiArrayCompare(byte[][] in) throws Exception {
		int cx = in.length;
		int[] rs = new int[cx];
		boolean[] fat=new boolean[cx];
		for (int y = 0;y<cx;y++) {
			for (int x=0;x<cx;x++) {
				if (x==y) continue;
				if (fat[x]) continue;
				if (Arrays.equals(in[y], in[x])) {
					rs[y]++;
					fat[x]=true;
					fat[y]=true;
					}
				}			
			}
		
		return rs;
	}

	public static void xorsb(byte[] a,byte[] b) {
		int cx = a.length;
		int dx = b.length;
		int ex = (cx>dx) ? cx : dx;
		
		for (int ax=0;ax<ex;ax++) {
			int bp = ax % cx;
			int si = ax % dx;
			a[bp] ^=b[si];
			}
	
	}

	public static String ASCIISequenceCreate(byte[] data, String name) throws Exception {
		name=name.toUpperCase().trim();
		CRC32 C = new CRC32();
		C.update(data);
		long crc = C.getValue();
		String w="------ BEGIN "+name+" SEQUENCE ------\r\n";
		String crt = J.Base64Encode(data);
		int cx = crt.length();
				for (int ax=0;ax<cx;ax++) {
					w+=crt.charAt(ax);
					if ((ax&63)==63) w+="\r\n";
				}

		w=w.trim();		
		w+="\r\n@"+Long.toString(crc,36)+"\r\n------ END "+name+" SEQUENCE ------\r\n";
		return w;				
	} 
	
	public static String ASCIISequenceReadI(InputStream ino,String name) throws Exception {
		name=name.toUpperCase().trim();
		String in="";
		int by=0;
		boolean st=false;
		while(true) {
			String li = "";
			 //How to prevent JAVA Buffer overflow!
			for (int ax=0;ax<1024;ax++) {
				by = ino.read();
				if (by==-1) break;
				li+=(char) (255&by);
				if (by==13 || by==10) break;
				}
			li=li.trim();
			if (li.contains("------ BEGIN "+name+" SEQUENCE ------")) if (!st) st=true; else throw new Exception("ASCII sequence: `"+name+"` too many marker!");
			if (!st) continue;
			in+=li+"\n";
			if (in.length()>65535) throw new Exception("@500 ASCII sequence: `"+name+"` too long");
			if (li.contains("------ END "+name+" SEQUENCE ------")) break;
			if (by==-1) break;
			}
		if (!st) throw new Exception("ASCII sequence: ` "+name+"` not found!");
		return in;
	}
	
	public static byte[] ASCIISequenceRead(String in,String name) throws Exception {
		name=name.toUpperCase().trim();
		in=in.trim();
		String[] lin = in.split("\\n+");
		int cx = lin.length;
		String w="";
		long crcs=-1;
		int st=0;
		try {
			for (int ax=0;ax<cx;ax++) {
				String li=lin[ax].trim();
				if (st==0) {
					if (li.contains("------ BEGIN "+name+" SEQUENCE ------")) st=1;
					continue;
					}
				if (st==1) {
					if (li.contains("------ END "+name+" SEQUENCE ------")) {
						st=2;
						break;
						}
					if (li.startsWith("@")) {
						li=li.substring(1);
						crcs=Long.parseLong(li,36) & 0xFFFFFFFF;
						continue;
						} 
					
					if (li.startsWith(";")) continue;
					w+=li;
					continue;
				}
			}
		} catch(Exception E) { throw new Exception("Invalid ASCII `"+name+"` Ivalid sequence data"); }
		if (st!=2) throw new Exception("Invalid ASCII `"+name+"` sequence: Incomplete or not found");
		if (crcs==-1) throw new Exception("Invalid ASCII `"+name+"` sequence: No @CRC32");
		byte[] b0;
		try { b0 = J.Base64Decode(w); } catch(Exception E) { throw new Exception("Invalid ASCII `"+name+"` sequence: Invalid BASE64 Data"); }
		CRC32 C = new CRC32();
		C.update(b0);
		if (C.getValue() !=crcs)  throw new Exception("Invalid ASCII `"+name+"` sequence: Data corrupted");
		return b0;
	}

	public static String Compiler() {
		/*
		 * Try to certificate  the source/version of program
		 * 
		 * */	
		byte[] mf = new byte[] {0};
		//Get MANIFEST HASH
		try {
			InputStream i = Main.class.getResourceAsStream("/META-INF/MANIFEST.MF");
			int cx = i.available();
			mf = new byte[cx];
			i.read(mf);
			} catch(Exception E) { 
				String st = E.getLocalizedMessage();
				mf=Stdio.md5( st==null ? new byte[0] : st.getBytes() );	
				}
			String rs="";
			//Verify Source via DEBUG and Exception
				try { Config.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { Const.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { DBCrypt.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { DynaRes.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { ExitRouteList.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { LibSTLS.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { MailBox.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { MailBoxFile.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { MailingList.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { Main.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { PGP.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { RemoteDerK.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { SrvIdentity.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { J.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
				try { Stdio.ZZ_Exceptionale(); } catch(Exception I) { rs+= GetExceptionalInfo(I); }
			try { mf = Stdio.md5a(new byte[][] { mf , rs.getBytes("UTF-8") }); } catch(Exception I) {}
					
		//	byte[] vm=new byte[] { 0 };
		//	try { vm= Stdio.md5(rs.getBytes("UTF-8")); } catch(Exception I) {}
			return 
						Stdio.Dump(mf) + "-" +					//Manifest compiled
						Long.toHexString(Main.VersionID);//Ver.
			}
		
		public static String GetExceptionalInfo(Exception E) {
			String St = E.getLocalizedMessage();
			StackTraceElement[] Sp = E.getStackTrace();
			int cx = Sp.length;
			for (int ax=0;ax<cx;ax++) try {
				if (Sp[ax].isNativeMethod()) continue;
				St+=Sp[ax].getClassName()+"\t"+Sp[ax].getFileName()+"\t"+Sp[ax].getLineNumber()+"\t"+Sp[ax].getMethodName()+"\t"+Sp[ax].getClassName()+"\n";
				} catch(Exception F) { St+="\n"+F.getLocalizedMessage()+" "+F.getMessage()+"\n\n"; }
			return St.trim();
		}

		public static boolean isReserved(String m,int type,boolean canSysOp) {
			m=m.toLowerCase().trim();
			String[] tok = m.split("\\@");
			m=tok[0].trim();
			if (
						m.endsWith(".onion") 	||
						m.endsWith(".o")			||
						m.endsWith(".sys")		||
						(canSysOp ? false : m.compareTo("sysop")==0)||
						m.compareTo("server")==0) return true;
			
			if (type!=1 && m.endsWith(".list")) return true;
			if (type!=2 && m.endsWith(".op")) return true;
			if (type!=3 && m.endsWith(".app")) return true;
			
			return false;
						
		}

	public static String ParsePGPObj(String msg,String MARKER) throws Exception {
		String q="";
		String[] li = msg.split("\\n");
		int cx = li.length;
		int pgp = 0;
	
		for (int ax=0;ax<cx;ax++) {
			String s = li[ax].trim();
			
			if (s.contains("---BEGIN "+ MARKER+"---")) {
				if (pgp!=0) throw new PException("@550 Invalid "+ MARKER);
				pgp=1;
				}
			if (pgp==1) q+=s+"\r\n";
			if (s.contains("---END "+ MARKER+"---")) {
				if (pgp!=1) throw new PException("@550 Invalid "+ MARKER); else {
						pgp=2;
						break;
						}
				} 
		}
	
		if (pgp!=2) throw new PException("@550 Can't read "+ MARKER+" correctly");
	return q;
	}
	
	public static String ParsePGPKey(String msg) throws Exception { return ParsePGPObj(msg,"PGP PUBLIC KEY BLOCK"); }
	public static String ParsePGPPrivKey(String msg) throws Exception { return ParsePGPObj(msg,"PGP PRIVATE KEY BLOCK"); }
	public static String ParsePGPMessage(String msg) throws Exception { return ParsePGPObj(msg,"PGP MESSAGE"); }
	
	public static boolean PGPVerifyKey(String ascii,String mail) throws Exception {
		ascii = ParsePGPKey(ascii);
		InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(ascii.getBytes()));
		int cx = in.available();
		byte[] dat = new byte[cx];
		in.read(dat);
		in.close();
		in=null;
		ascii=new String(dat);
		int m = (int)(dat[0]&255);
		if (
				m!=0x98 &&
				m!=0x99 &&
				m!=0x9A &&
				m!=0xC6 ) throw new PException(550,"Invalid KEYRING file");
				
		mail=mail.toLowerCase();
		ascii=ascii.toLowerCase(); // Auguri!!!
		if (ascii.contains("<"+mail+">")) return true;
		return false;
	}
	
	public static String MQuotedDecode(String in) {
		String q="";
		in=in.replace("=\r\n", "");
		in=in.replace("=\n", "");
		int cx=in.length();
		for (int ax=0;ax<cx;ax++) {
			char c = in.charAt(ax);
			if (c=='=') {
				String h = in.substring(ax+1, ax+3);
				ax+=2;
				int hi=63;
				try { hi = Integer.parseInt(h.toLowerCase(),16); } catch(Exception E) {}
				q+=(char) hi;
			} else q+=c;
		}
		return q;
	}
	
	public static String MBase64Decode(String in) {
		in=in.trim();
		in=in.replace("\r", "");
		in=in.replace("\n", "");
		in=in.replace("\t", "");
		in=in.replace(" ", "");
		return new String(J.Base64Decode(in));
	}
	
	public static void LoopFileInit(String fileName,int magicNumber,int maxRecord,int recordSize) throws Exception {
		File f = new File(fileName);
		
		if (!f.exists()) {
			 	LoopFileCreate( fileName, magicNumber, maxRecord, recordSize);
			 	f=null;
			 	return;
				}
		
		long size= 16+(recordSize+2)*maxRecord;
		if (f.length()<size) LoopFileCreate( fileName, magicNumber, maxRecord, recordSize);
		}
	
	public static void LoopFileCreate(String fileName,int magicNumber,int maxRecord,int recordSize) throws Exception {
		RandomAccessFile O = new RandomAccessFile(fileName,"rw");
		recordSize=recordSize+2;
		O.seek(0);							
		O.writeShort(0x1234);		//magic_fmt
		O.writeShort(-1);				//curr 
		O.writeShort(0);					//hi
		O.writeShort(0);					//0
		O.writeInt(magicNumber);	//magic
		O.writeShort(maxRecord);	//maxrec
		O.writeShort(recordSize);	//size
		
		byte[] b= new byte[256];
		long size = recordSize*maxRecord;
		int block = (int) size>>8;
		if ((size&255)!=0) block++;
		for (int ax=0;ax<block;ax++) O.write(b);
		
		//Extended Record
		O.write(b); 
		O.writeShort(0x1234);
		O.writeShort(0x0102);		
		O.writeInt(magicNumber);	//magic
		O.writeShort(maxRecord);	//maxrec
		O.writeShort(recordSize);	//size
		O.writeShort(0x5678);
		O.writeShort(12);
		O.close();
		b=null;
	}
	
	public static void LoopFileWrite(String fileName,long[] data,int[] sizes) throws Exception {
		RandomAccessFile O = new RandomAccessFile(fileName,"rw");
		try {
			O.seek(0);
			int oem = O.readShort();	//oem fmt
			if (oem!=0x1234) throw new Exception("LoopFileWrite: Invalid Magic number 0x1234");
			int currentRecord = O.readShort();		//curr
			int currentHI = O.readShort();	//hi
			O.readShort();	//0
			O.readInt();		//magic
			int maxRecord = O.readShort(); //maxrec
			int recordSize = O.readShort();	//size
					
			currentRecord=currentRecord+1;
			if (currentRecord>=maxRecord) {
				currentRecord=0;
				currentHI=(currentHI+1) & 16383;
				}
					
			long addr = 16 + currentRecord*recordSize;
			O.seek(addr);
			byte[] b = Stdio.Stosxm(data, sizes);
			if (b.length>(recordSize-1)) throw new Exception("LoopFileWrite: Record too big "+b.length+"/"+(recordSize-1));
			O.writeByte(0x80 | (127 & currentHI));
			O.write(b);
			b=null;
			O.seek(2);
			O.writeShort(currentRecord);
			O.writeShort(currentHI);
			} catch(Exception E) {
				try { O.close(); } catch(Exception F) {}
				throw E;
				} 
		O.close();
		
	}

	public static String msgBase64Encode(String msg) {
		msg=msg.replace("\r\n", "\n");
		msg=msg.replace("\n", "\r\n");
		msg=J.Base64Encode(msg.getBytes());
		String q="";
		int cx=msg.length();
		for (int ax=0;ax<cx;ax++) {
			q+=msg.charAt(ax);
			if ((ax%75)==74) q+="\r\n";
			}
		return q.trim()+"\r\n";
	}
	
	public static String Implode(String glue, String[] array) {
		int cx= array.length-1;
		String rs="";
		for (int ax=0;ax<=cx;ax++) {
			rs+=array[ax];
			if (ax!=cx) rs+=glue;
			}
		return rs;
	}
	
	public static float fPercMax(int val,int max,int per) {
		if (max==0)  return 0;
		return (val/max)*per;
		}
	
	public static int iPercMax(int val,int max,int per) {
		if (max==0)  return 0;
		return (int) Math.ceil((val/max)*per);
		}
	
	public static String sPercMax(int val,int max,int per,int dec) {
		if (max==0)  return "0";
		double f = (val/max)*per;
		double v = Math.pow(10, dec);
		f=Math.ceil(f*v);		
		f=f/v;
		return Double.toString(f);
		}

	public static String LogHash(SrvIdentity S,String address) throws Exception {
		long a = System.currentTimeMillis()/3600000L;
		a=a^a>>1;
		int i = (int) (a&3);
		String s = Stdio.Dump(S.Subs[i])+"#"+address+"#"+Long.toString(a,36);
		return Long.toString(s.hashCode(),36);
	}

	public static String PrintStackTrace(Exception E) {
			String rs="Exception: "+	E.toString()+"\n\t";
			StackTraceElement[] st = E.getStackTrace();
			int cx = st.length;
			for (int ax=0;ax<cx;ax++) {
				rs+=st[ax].toString()+"\n\t";
				if (st[ax].isNativeMethod()) break;
				}
			return rs.trim();
		}
			
	protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
