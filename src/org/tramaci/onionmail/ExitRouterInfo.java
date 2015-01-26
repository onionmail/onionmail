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

public class ExitRouterInfo {
	
	public boolean isTrust = false;
	public boolean isBad = false;
	public boolean canMX = false;
	public boolean isDown= false;
	public boolean canVMAT=false;
	public boolean isLegacy=false;
	public boolean isExit = false;
	public long lastCHK = 0;
	public volatile int Goods=0;
	public volatile int Bads=0;
	public String domain = null;
	public String onion = null;
	public int port = 10025;
	public int knowFrom=0;
	
	
	public void setResult(boolean ok) { if (ok) Goods++; else Bads++; }
	
	public ExitRouterInfo clone() {
		ExitRouterInfo i = new ExitRouterInfo();
		i.isTrust=isTrust;
		i.isBad=isBad;
		i.canMX=canMX;
		i.isDown=isDown;
		i.canVMAT=canVMAT;
		i.lastCHK=lastCHK;
		i.Goods=Goods;
		i.Bads=Bads;
		i.domain=domain.trim();
		i.onion=onion.trim();
		i.port=port;
		i.knowFrom=knowFrom;
		i.isLegacy=isLegacy;
		i.isExit=isExit;
		return i;
		}
	
	public static ExitRouterInfo fromLegacy(String dom,String oni) {
		ExitRouterInfo i = new ExitRouterInfo();
		i.isLegacy=true;
		i.onion=oni.toLowerCase().trim();
		i.domain=dom.toLowerCase().trim();
		return i;
		}
	
	public static ExitRouterInfo fromString(String s) {
		try {
			s=s.replace(':', ' ');
			String[] tok = s.split("\\s+");
			ExitRouterInfo i = new ExitRouterInfo();
			i.domain=tok[0].toLowerCase().trim();
			i.onion=tok[1].toLowerCase().trim();
			
			if (!i.onion.matches("[a-z0-9]{16}\\.onion") || !i.domain.matches("[a-z0-9\\-\\_\\.]{2,40}\\.[a-z0-9]{2,5}") || i.domain.endsWith(".onion")) throw new Exception("dom/oni"); //XXX Rimuovi return null;
			
			i.port=Config.parseInt(tok[2], "", 1, 65535);
			i.lastCHK=0;
			i.canVMAT = tok[3].contains("V");
			i.canMX = tok[3].contains("M");
			i.isTrust = tok[3].contains("T");
			i.isBad = tok[3].contains("B");
			i.isDown = tok[3].contains("D");
			i.isLegacy = tok[3].contains("L");
			i.isExit = tok[3].contains("X");
			i.Goods = 1;
			i.Bads= 0;
			return i;
			} catch(Exception E) {
				///Main.echo("ERROROO |"+s+"|\n");///XXX Rimuovi
				E.printStackTrace();
				return null; }
		}
	
	public String toString() {
		String bits = "";
		
		if (canVMAT) bits+="V";
		if (canMX) bits+="M";
		if (isTrust) bits+="T";
		if (isBad) bits+="B";
		if (isDown) bits+="D";
		if (isLegacy) bits+="L";
		if (isExit) bits+="X";		
		int p =(int) Math.floor(100.0*(Goods / (1+Goods+Bads)));
		return domain+": "+onion+":"+port+" "+bits+" "+p+"%";
		}
	
	public String toInfoString() {
		String bits = "";
		
		if (isExit) bits+="X"; else bits+="-";
		if (canVMAT) bits+="V"; else bits+="-";
		if (canMX) bits+="M"; else bits+="-";
		if (isTrust) bits+="T"; else bits+="-";
		if (isBad) bits+="B"; else bits+="-";
		if (isDown) bits+="D"; else bits+="-";
		if (isLegacy) bits+="L"; else bits+="-";
		
		int p =(int) Math.floor(100.0*(Goods / (1+Goods+Bads)));
		return domain+"\t"+bits+" "+p+"%";
		}
	
		private static final int[] Fmt = new int[] { 2,4,2,2,2,4 };
		
		public byte[] getBytes() throws Exception {
		
			int bits=
					(canMX ? 1: 0) 
					| (canVMAT ? 2:0)
				    | (isTrust ? 4: 0)
				    | (isBad ? 8: 0)
				    | (isDown ? 16 : 0)
				    | (isLegacy ? 32 : 0)
				    | (isExit ? 64 : 0 );
			
			long[] dta =new long[] { bits,lastCHK ,Bads,Goods,port,knowFrom };
			return Stdio.MxAccuShifter(new byte[][]{
					domain.toLowerCase().trim().getBytes(),
					onion.toLowerCase().trim().getBytes(),
					Stdio.Stosxm(dta, Fmt) }, Const.MX_ExitRouterInfo);
			}

		public static synchronized ExitRouterInfo fromBytes(byte[] b) throws Exception {
			byte[][] mx = Stdio.MxDaccuShifter(b,  Const.MX_ExitRouterInfo);
				String dom = new String(mx[0]);
				String oni = new String(mx[1]);
				ExitRouterInfo i =new ExitRouterInfo();
				long[] dat = Stdio.Lodsxm(mx[2], Fmt);
				i.onion=oni.toLowerCase().trim();
				i.domain=dom.toLowerCase().trim();
				i.isTrust = (dat[0]&4)!=0;
				i.isBad = (dat[0]&8)!=0;
				i.isDown= (dat[0]&16)!=0;
				i.canMX = (dat[0]&1)!=0;
				i.canVMAT = (dat[0]&2)!=0;
				i.isLegacy = (dat[0]&32)!=0;
				i.isExit = (dat[0]&64)!=0;
				i.lastCHK=dat[1];
				i.Bads=(int)dat[2];
				i.Goods=(int)dat[3];
				i.port=(int)dat[4];
				i.knowFrom=(int)dat[5];
				return i;
				}
	
	}
