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

import java.util.HashMap;

public class ExitRouteList extends HashMap<String, String> {

	private static final long serialVersionUID = -5533788482927242034L;

	public String GetOnion(String dom) {
		dom=dom.toLowerCase().trim();
		if (!containsKey(dom)) return null;
		return get(dom);
		}
	
	public String GetDomain(String onion) {
		if (onion==null) {
			if (isEmpty()) return null;
			String o=null;
				for (String K:keySet()) {
				o=K;
				break;
				}
			return o;
			}
		onion=onion.toLowerCase().trim();
		for (String K:keySet()) {
			String o = get(K);
			if (o.compareTo(onion)==0) return K;
			}		
		return null;
		}
	
	public String SelectOnion(String dom) {
		if (isEmpty()) return null;
		String o = null;
		if (dom!=null) o=GetOnion(dom);
		if (o!=null) return o;
		for (String K:keySet()) {
			o=get(K);
			break;
			}
		return o;
		}
	
	public String toString() {
		String r="";
		for(String K:keySet()) {
			r+=J.Spaced(K, 40)+J.Limited(get(K), 40)+"\n";
			}
		return r;
	}
	
	public byte[] getBytes() throws Exception { return J.HashMapPack((HashMap <String,String>) this);	}
	public static ExitRouteList fromBytes(byte[] b) throws Exception { return ExitRouteList.fromHashMap(J.HashMapUnPack(b)); }
	
	public static ExitRouteList fromHashMap(HashMap <String,String> H) throws Exception {
		ExitRouteList E = new ExitRouteList();
		for (String K:H.keySet()) E.put(K.toLowerCase().trim(), H.get(K).toLowerCase().trim());
		return E;
	}

protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify
}
