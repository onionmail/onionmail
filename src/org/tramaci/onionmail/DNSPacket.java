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
import java.net.DatagramPacket;
import java.net.InetAddress;

	
	public class DNSPacket {
		public int id = 0;
		public boolean response=false;
		public int opcode = 0;
		public boolean authoritative =false;
		public boolean truncation = false;
		public boolean recursiond = false;
		public boolean recursiona = false;
		public int  Z=0;
		public int rcode=0;
		public int rawhead = 0;
		
		public int qdcount=0;
		public int ancount=0;
		public int nscount=0;
		public int arcount=0;
		public int qtype=0;
		public int qclass=0;
		
		public String Host="";
		public String Tld="";
		
		private int endpointer=0;
		public byte[] packet = null;
		private int dnsdelirio=0;
			
			public static final int OP_Query=1;
			public static final int OP_IQuery=2;
			public static final int OP_Status=3;
		
			public static final int RE_Ok=0;
			public static final int RE_ErrFmt=1;
			public static final int RE_ErrSrv=2;
			public static final int RE_ErrNotExists=3;
			public static final int RE_NotImpl=4;
			public static final int RE_Refused=5;
			
			public static final  int TYP_A = 1;
			public static final  int TYP_NS=2;
			public static final  int TYP_MD=3;
			public static final  int TYP_MF=4;
			public static final  int TYP_CNAME=5;
			public static final  int TYP_SOA=6;
			public static final  int TYP_MB = 7;
			public static final  int TYP_MG = 8;
			public static final  int TYP_MR = 9;
			public static final  int TYP_NULL = 10;
			public static final  int TYP_WKS = 11;
			public static final  int TYP_PTR = 12;
			public static final  int TYP_HINFO = 13;
			public static final  int TYP_MINFO = 14;
			public static final  int TYP_MX = 15;
			public static final  int TYP_TXT = 16;
			public static final  int TYP_Q_AXFR = 252;
			public static final  int TYP_Q_MAILB = 253;
			public static final  int TYP_Q_MAILA = 254;
			public static final  int TYP_Q_ANY = 255;
		
		public  int pksize=0;
		public InetAddress pkfrom = null;
		public int pkport=0;
		
		DNSPacket() {}
						
		DNSPacket(DatagramPacket rp) throws Exception {
			byte[] data = rp.getData();
			pksize=rp.getLength();
			pkfrom = rp.getAddress();
			pkport=rp.getPort();
			ParseReq(data);
		}
		
		private int GetHPoint() { return  0xc000 | (dnsdelirio); }
		
		public void setId(int id) { PokeB(0, id, packet); }
		
		public byte[] DoReply() throws Exception {
			int raw=								0b1000000000000000;
			if (authoritative) raw|= 		0b0000010000000000;
			if (recursiond) raw|= 			0b0000000100000000;
			if (recursiona)raw|= 			0b0000000010000000;
			raw|=(opcode&15)<<11;
			raw|=(rcode&15);
			raw|=									0b1000000010000000;
			
			byte[] q = new byte[endpointer];
			System.arraycopy(packet, 0, q, 0, endpointer);
			PokeB(2, raw, q);
			PokeB(4, qdcount, q);
			PokeB(6, ancount, q);
			PokeB(8, nscount, q);
			PokeB(10, arcount, q);
						
			return q;
			}
		
		public byte[] DoRequest() throws Exception {
			int raw=								0b0000000000000000;
			if (authoritative) raw|= 		0b0000010000000000;
			if (recursiond) raw|= 			0b0000000100000000;
			if (recursiona)raw|= 			0b0000000010000000;
			raw|=(opcode&15)<<11;
			raw|=(rcode&15);
			raw|=									0b1000000010000000;
			
			byte[] q = new byte[endpointer];
			System.arraycopy(packet, 0, q, 0, endpointer);
			PokeB(2, raw, q);
			PokeB(4, qdcount, q);
			PokeB(6, ancount, q);
			PokeB(8, nscount, q);
			PokeB(10, arcount, q);
						
			return q;
			}
		
		public void ParseReq(byte[] data) throws Exception {
			packet=new byte[512];
			int lp = data.length;
			if (lp>512) lp=512;
			System.arraycopy(data, 0, packet,0,lp);
			
			id = PeekB(0,data);
			rawhead = PeekB(2, data);
			response = (rawhead 		& 0b1000000000000000)!=0;
			opcode = (rawhead			& 0b0111100000000000)>>11;
			authoritative=(rawhead	& 0b0000010000000000)!=0;
			truncation=(rawhead		& 0b0000001000000000)!=0;
			recursiond=(rawhead		& 0b0000000100000000)!=0;
			recursiona=(rawhead		& 0b0000000010000000)!=0;
			Z = (rawhead					& 0b0000000001110000)>>4;
			rcode=(rawhead				& 0b0000000000001111);
			
			qdcount=PeekB(4, data);
			ancount=PeekB(6, data);
			nscount=PeekB(8, data);
			arcount=PeekB(10, data);
			
			int bp=12;
			int cx=data.length;
			Host="";
			Tld="";
			dnsdelirio=bp;
			for (int ax=bp;ax<cx;ax++) {
				int cl = (int)(255&data[bp++]);
				dnsdelirio++;
				if (cl==0) break;
				Tld="";
				for (int al=0;al<cl;al++) {
					Tld += (char)(255&data[bp++]);
					dnsdelirio++;
					if (bp>=cx) break;
					}
				Host+=Tld+".";
				}
			
			qtype = PeekB(bp, data);
			bp+=2;
			qclass = PeekB(bp, data);
			bp+=2;
			endpointer=bp;
			Tld=Tld.toLowerCase();
			}
		
		public void AddMXReply(int pri,int ttl) throws Exception {
			byte[] data = new byte[7];
			PokeB(0, pri,data);
			data[2] = 2;
			data[3] = 0x32;
			data[4] = 0x35;
			PokeB(5,GetHPoint(),data);
			AddReply(0x000f,ttl,null,data);
			}
		
		public void AddReply(int type,int ttl,String sub,byte[] data) throws Exception {
				
				if (sub!=null && sub.length()>0) {
					int cx = sub.length();
					packet[endpointer++]=(byte)cx;
					for (int al=0;al<cx;al++) packet[endpointer++]=(byte)(sub.codePointAt(al)&255); 
					}
				
				int raw = GetHPoint();
				
				PokeB(endpointer, raw, packet);
				endpointer+=2;
				PokeB(endpointer, type, packet);
				endpointer+=2;
				PokeB(endpointer, 1, packet);
				endpointer+=2;
				PokeB(endpointer, ttl>>16, packet);
				endpointer+=2;
				PokeB(endpointer, ttl&65535, packet);
				endpointer+=2;
				PokeB(endpointer, data.length, packet);
				endpointer+=2;
				System.arraycopy(data, 0, packet, endpointer, data.length);
				endpointer+=data.length;
				ancount++;
			}
		
		public static void PokeB(int addr,int valu, byte[] ram) {
		ram[addr+1] = (byte)(255&valu);
		ram[addr] = (byte)(255&(valu>>8));
		
	}
		
	public static int PeekB(int addr,byte[] ram) {
		int valu = (int)(255&ram[addr+1]);
		valu|=(int)((255&ram[addr])<<8);
		return valu; 
	}
		
	}	
