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

import java.util.HashMap;

public class ExitRouteList  {

	public static final int EFLT_ALL = 						0b000000000000000000;
	public static final int EFLT_BAD_N = 				0b000000010000000000;
	public static final int EFLT_BAD_Y = 					0b000000010000000010;
	public static final int EFLT_DOWN_N =				0b000000100000000000;
	public static final int EFLT_DOWN_Y =				0b000000100000000100;
	public static final int EFLT_TRUST_N =				0b000001000000000000;
	public static final int EFLT_TRUST_Y =				0b000001000000001000;
	public static final int EFLT_LEGACY_N = 			0b000010000000000000;
	public static final int EFLT_LEGACY_Y = 			0b000010000000010000;
	public static final int EFLT_EXIT_N = 				0b000100000000000000;
	public static final int EFLT_EXIT_Y = 				0b000100000000100000;
	public static final int EFLT_MX_N = 					0b001000000000000000;
	public static final int EFLT_MX_Y = 					0b001000000001000000;
	public static final int EFLT_VMAT_N =				0b010000000000000000;
	public static final int EFLT_VMAT_Y =				0b010000000010000000;

	private static final int EFLT_WHAT=					0b111111111000000000;
	private static final int EFLT_BITS=					0b000000000111111111;
	
	public static final int FLT_BAD = EFLT_BAD_Y | EFLT_DOWN_N;
	public static final int FLT_OK = EFLT_BAD_N | EFLT_DOWN_N | EFLT_LEGACY_N | EFLT_MX_Y | EFLT_VMAT_Y;
	public static final int FLT_TRUST = EFLT_BAD_N | EFLT_DOWN_N | EFLT_TRUST_Y | EFLT_LEGACY_N;
	public static final int FLT_ALL = EFLT_BAD_N | EFLT_DOWN_N;
	public static final int FLT_DOWN = EFLT_BAD_N | EFLT_DOWN_Y;
	public static final int FLT_MX = EFLT_BAD_N | EFLT_DOWN_N | EFLT_MX_Y;
	public static final int FLT_VMAT = EFLT_BAD_N | EFLT_DOWN_N | EFLT_VMAT_Y;
	public static final int FLT_EXIT = EFLT_BAD_N | EFLT_DOWN_N | EFLT_EXIT_Y;
	
	private HashMap <String,ExitRouterInfo> byOnion = new HashMap <String,ExitRouterInfo>();
	private HashMap <String,ExitRouterInfo> byDomain = new HashMap <String,ExitRouterInfo>();

	
	public  ExitRouterInfo[] queryFLT(int flt) {
		ExitRouterInfo[]a = getAll();
		return queryFLTArray(a,flt);
		}
	
	public static ExitRouterInfo[] queryFLTArray(ExitRouterInfo[]a ,int flt) {
			int cx = a.length;
			ExitRouterInfo[] b=new ExitRouterInfo[cx];
			int bx=0;
			
			int what = flt&EFLT_WHAT;
			int bits = flt&EFLT_BITS;
			
			for (int ax=0;ax<cx;ax++) {
				if ((what&EFLT_BAD_Y)!=0 && ( (bits&EFLT_BAD_Y)!=0 != a[ax].isBad)) continue;
				if ((what&EFLT_DOWN_Y)!=0 && ( (bits&EFLT_DOWN_Y)!=0 != a[ax].isDown)) continue;
				if ((what&EFLT_TRUST_Y)!=0 && ( (bits&EFLT_TRUST_Y)!=0 != a[ax].isTrust)) continue;
				if ((what& EFLT_LEGACY_Y)!=0 && ( (bits& EFLT_LEGACY_Y)!=0 != a[ax].isLegacy)) continue;
				if ((what& EFLT_EXIT_Y)!=0 && ( (bits& EFLT_EXIT_Y)!=0 != a[ax].isExit)) continue;
				if ((what& EFLT_MX_Y)!=0 && ( (bits& EFLT_MX_Y)!=0 != a[ax].canMX)) continue;
				if ((what& EFLT_VMAT_Y)!=0 && ( (bits&EFLT_VMAT_Y)!=0 != a[ax].canVMAT)) continue;
				b[bx++]=a[ax];
				}
			a = new ExitRouterInfo[bx];
			System.arraycopy(b, 0, a, 0, bx);
			return a;
			}
	
	public boolean isEmpty() { return byDomain.isEmpty(); }
		
	public static HashMap <String,String> getExitHashMap(ExitRouterInfo[] arr, int mode) {
		HashMap <String,String> rs = new HashMap <String,String>();
		arr = queryFLTArray(arr,mode);
		int j=arr.length;
		for (int i=0;i<j;i++) rs.put(arr[i].domain, arr[i].onion);
		return rs;
	}
	
	public boolean containsDomain(String dom) { return byDomain.containsKey(dom); }
	public boolean containsOnion(String dom) { return byOnion.containsKey(dom); }
	
	public int Length() { return byDomain.size(); }
	public ExitRouterInfo getByOnion(String oni) { return byOnion.get(oni); }
	public ExitRouterInfo getByDomain(String dom) { return byDomain.get(dom); }
	
	public void applyServerPolicy(SrvIdentity S) {
		if (S.ExitBad==null && S.ExitGood==null) return; 
		ExitRouterInfo[] a = getAll();
		int cx = a.length;
		for (int ax=0;ax<cx;ax++) {
			if (S.ExitBad!=null && (S.ExitBad.contains(","+a[ax].domain+",") || S.ExitBad.contains(","+a[ax].onion+","))) a[ax].isBad=true;
			if (S.ExitGood!=null && (S.ExitGood.contains(","+a[ax].domain+",") || S.ExitGood.contains(","+a[ax].onion+","))) a[ax].isTrust=true;
			}
		}
	
	public void clear() {
		byOnion.clear();
		byDomain.clear();
		}
	
	public void setByOnion(String oni,ExitRouterInfo i) {
		byOnion.put(oni, i);
		byDomain.put(i.domain, i);
		}
	
	public void setByDomain(String dom,ExitRouterInfo i) {
		byDomain.put(dom,i);
		byOnion.put(i.onion,i);
		}
	
	public void addRouter(ExitRouterInfo i) {
		byOnion.put(i.onion,i);
		byDomain.put(i.domain, i);
		}
	
	public void addRouters(ExitRouterInfo i[]) {
		int cx=i.length;
		for (int ax=0;ax<cx;ax++) if (i[ax]!=null) {
			byOnion.put(i[ax].onion,i[ax]);
			byDomain.put(i[ax].domain, i[ax]);
			}
		}
	
	public ExitRouterInfo[] getAll() {
			ExitRouterInfo[] a=new ExitRouterInfo[byDomain.size()];
			byDomain.values().toArray(a);
			return a;
			}
	
	public ExitRouterInfo[] getElist(int elm) {
			ExitRouterInfo[] a=new ExitRouterInfo[byDomain.size()];
			byDomain.values().toArray(a);
			return ExitRouteList.queryFLTArray(a, elm);
			}
	
	public ExitRouterInfo selectExit(boolean reqMX) {
		ExitRouterInfo i=null;
		int perc=-1;
		ExitRouterInfo[] a =reqMX ? queryFLT(ExitRouteList.FLT_MX) : getAll();
		int cx = a.length;
		for (int ax=0;ax<cx;ax++) {
			int p =(int) Math.floor(1000.0*(a[ax].Goods / (1+a[ax].Goods+a[ax].Bads)));
			if (p>perc) {
				perc=p;
				i=a[ax];
				}
			}
		return i;
		}
	
	public ExitRouterInfo selectBestExit() {
		ExitRouterInfo cc=null;
		ExitRouterInfo cb=null;
		ExitRouterInfo ca=null;
		int perc=-1;
		int perb=-1;
		int pera=-1;
		
		ExitRouterInfo[] a = getAll();
		int cx = a.length;
		for (int ax=0;ax<cx;ax++) {
			if (a[ax].isBad || a[ax].isDown) continue;
			int p =(int) Math.floor(1000.0*(a[ax].Goods / (1+a[ax].Goods+a[ax].Bads)));
			
			if (!a[ax].isLegacy && a[ax].canMX && a[ax].canVMAT) {
				if (a[ax].isTrust) {
						if (p>pera) {
							pera=p;
							ca=a[ax];
							continue;
							}
					} else {
						if (p>perb) {
							perb=p;
							cb=a[ax];
							continue;
							}
					}				
				}
			
			if (p>perc) {
				perc=p;
				cc=a[ax];
				}
			}
		
		if (ca!=null) return ca;
		if (cb!=null) return cb;
		return cc;
		}
	
	public ExitRouterInfo selectAnExit() {
		ExitRouterInfo[] a = getAll();
		int cx = a.length;
		for (int ax=0;ax<cx;ax++) {
			if (a[ax].isBad || a[ax].isDown) continue;
			return a[ax];
			}
		return null;
	}
	
	public String getOnion(String dom) {
		ExitRouterInfo i = byDomain.get(dom);
		if (i==null || i.isBad || i.isDown) return null;
		return i.onion;
		}
	
	public String getDomainOnly(String domnul) {
		ExitRouterInfo i=null;
		if (domnul!=null) {
			if (byDomain.containsKey(domnul)) i=byDomain.get(domnul);
			if (i.isBad || i.isDown) i=null;
			}
		
		if (i==null) i = selectExit(false);
		return i.domain;
		}
	
	public String domain2Onion(String domnul) {
		ExitRouterInfo i=null;
		if (byDomain.containsKey(domnul)) i=byDomain.get(domnul);
		if (i!=null) return i.onion; else return null;
		}
	
	public String onion2Domain(String domnul) {
		ExitRouterInfo i=null;
		if (byOnion.containsKey(domnul)) i=byOnion.get(domnul);
		if (i!=null) return i.domain; else return null;
		}
	
	public ExitRouterInfo selectExitByDomain(String domnul,boolean canMX) {
		ExitRouterInfo i=null;
		if (domnul!=null) {
			if (byDomain.containsKey(domnul)) i=byDomain.get(domnul);
			if (canMX&!i.canMX) i=null;
			if (i.isBad || i.isDown) i=null;
			}
		
		if (i==null) i = selectExit(canMX);
		return i;
		}
	
	public ExitRouterInfo selectExitByOnion(String domnul,boolean canMX) {
		ExitRouterInfo i=null;
		if (domnul!=null) {
			if (byOnion.containsKey(domnul)) i=byOnion.get(domnul);
			if (canMX&!i.canMX) i=null;
			if (i.isBad || i.isDown) i=null;
			}
		
		if (i==null) i = selectExit(canMX);
		return i;
		}
	
	public void removeServerByOnion(String s) {
		ExitRouterInfo i = byOnion.get(s);
		if (i!=null) {
			byOnion.remove(i.onion);
			byDomain.remove(i.domain);
			}
		}
	
	public void removeServerByDomain(String s) {
		ExitRouterInfo i = byDomain.get(s);
		if (i!=null) {
			byOnion.remove(i.onion);
			byDomain.remove(i.domain);
			}
		}
	
	public void removeServer(ExitRouterInfo i) {
		byOnion.remove(i.onion);
		byDomain.remove(i.domain);
		}
		
	public byte[] getBytes() throws Exception {
		ExitRouterInfo[] a = getAll();
		int ecx=a.length;
		byte[][] exl = new byte[ecx][];
		for (int ax=0;ax<ecx;ax++) exl[ax]=a[ax].getBytes();
		return Stdio.MxAccuShifter(exl, Const.MX_ListExit, true);
		}
		
	public static ExitRouteList fromBytes(byte[] b) throws Exception { 
			ExitRouteList  Q = new ExitRouteList();
			byte[][] exl = Stdio.MxDaccuShifter(b, Const.MX_ListExit);
			int cx= exl.length;
			for (int ax=0;ax<cx;ax++) {
				ExitRouterInfo i =ExitRouterInfo.fromBytes(exl[ax]);
				Q.addRouter(i);
				}
			return Q;
	}
	
	public String toString() {
		ExitRouterInfo[] a = getAll();
		int cx= a.length;
		String s="";
		for (int ax=0;ax<cx;ax++) s+=a[ax].toInfoString()+"\n";
		return s;
		}

	public ExitRouteList clone() {
		ExitRouterInfo[] a = getAll();
		ExitRouteList r = new ExitRouteList();
		int cx = a.length;
		for (int ax=0;ax<cx;ax++) {
			ExitRouterInfo b=a[ax].clone();
			r.addRouter(b);
			}
		return r;
		}
	
protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
