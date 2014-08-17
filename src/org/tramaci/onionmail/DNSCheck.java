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
import java.util.Hashtable;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.Context;
import javax.naming.NameNotFoundException;

public class DNSCheck {

	private Config Config = null;
    private DirContext Cox=null;
    private HashMap <String,MXRecord[]> CacheMX = new HashMap<String, MXRecord[]>();
    private HashMap <String,Integer> CacheMXT = new HashMap<String, Integer>();
    private HashMap <String,String> CacheDNSBL = new HashMap<String, String>();
    private HashMap <String,Integer> CacheDNSBLT = new HashMap<String, Integer>();
   
    private int GarbageTCR = 0;
    private int PreventTooManyGarbages=0;
    
    private synchronized void CHAddM(String host,MXRecord[] MX) {
    	if (CacheMX==null) return;
    	CacheMX.put(host,MX);
    	CacheMXT.put(host, (int)(System.currentTimeMillis()/1000)+Config.DNSBLCacheTTL);
    	}
    
    private synchronized void CHAddB(String host,String bl) {
    	if (CacheDNSBL==null) return;
    	CacheDNSBL.put(host,bl);
    	CacheDNSBLT.put(host, (int)(System.currentTimeMillis()/1000)+Config.DNSBLCacheTTL);
    	}
        
    public synchronized void Garbage(boolean force) {
    	int tcr =(int)(System.currentTimeMillis()/1000);
    	if (!force && PreventTooManyGarbages==tcr) return;
    	PreventTooManyGarbages=tcr;
    	try {
	    	String[] del = new String[CacheMXT.size()];
	    	int bp=0;
	    	for (String host : CacheMXT.keySet()) {
	    		int t = CacheMXT.get(host);
	    		if (tcr>t) del[bp++]=host;
	    		}
	    	for (int ax=0;ax<bp;ax++) {
	    		CacheMXT.remove(del[ax]);
	    		CacheMX.remove(del[ax]);
	    		}
	    	
	    	del = new String[CacheDNSBL.size()];
	    	bp=0;
	    	for (String host : CacheDNSBLT.keySet()) {
	    		int t = CacheDNSBLT.get(host);
	    		if (tcr>t) del[bp++]=host;
	    		}
	    	for (int ax=0;ax<bp;ax++) {
	    		CacheDNSBLT.remove(del[ax]);
	    		CacheDNSBL.remove(del[ax]);
	    		}
    	} catch(Exception E) { Config.EXC(E, "DNSCheck.Garbage"); }
    }
    
    @SuppressWarnings({ "rawtypes", "unchecked" })
	public DNSCheck(Config C) throws Exception {
		Config=C;
		
		if (Config.DNSServer==null) throw new Exception("DNSServer missing");
		if (Config.DNSCheckTimeout==0) throw new Exception("Invalid DNSCheckTimeout");
		if (Config.DNSCheckRetry==0) throw new Exception("Invalid DNSCheckRetry"); 
		
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");       
		env.put("com.sun.jndi.dns.timeout.initial",Integer.toString(Config.DNSCheckTimeout));
		env.put("com.sun.jndi.dns.timeout.retries", Integer.toString(Config.DNSCheckRetry));
		if (Config.DNSBLForceMainDNSServer) env.put(Context.PROVIDER_URL,"dns://"+J.IP2String(Config.DNSServer));
		
		Cox = new InitialDirContext(env);
		if (Config.DNSBLUseCache) {
			CacheMX = new HashMap();
			CacheMXT = new HashMap();
			CacheDNSBL = new HashMap();
			CacheDNSBLT = new HashMap();
			GarbageTCR =(int)((System.currentTimeMillis()/1000)+Config.DNSBLCacheTTL);
		} else {
			CacheMX = null;
			CacheMXT = null;
			CacheDNSBL = null;
			CacheDNSBLT = null;
			GarbageTCR =0;
		}
		
    }
      
    public String DNSBL(String tip) throws Exception {
        if (Config.DNSBLUseCache) {
        	int tcr= (int)(System.currentTimeMillis()/1000);
        	if (tcr>GarbageTCR || CacheDNSBL.size()>Config.DNSBLCacheSize) {
        		GarbageTCR=(int)((System.currentTimeMillis()/1000)+Config.DNSBLCacheTTL);
        		Garbage(!Config.MindlessCompilant); //Minimo 1" 
        		}
        	if (CacheDNSBL.containsKey(tip)) return CacheDNSBL.get(tip);
        	}
        
    	String[] Tok = tip.split("\\.");
        if (Tok.length!=4) return null;		//Don't cache fuffa!!!
        		
        String ip = "";
        for (int ax=3;ax>-1;ax--) ip+=Tok[ax]+".";
        Tok=null;
        Attribute attribute;
        Attributes attributes;
        String lookupHost;
        for ( String service : Config.SPAMSrvCheck ) {
            lookupHost = ip + service;
            try {
            	synchronized(Cox) {
            		attributes = Cox.getAttributes(lookupHost, new String[]  { "A", "TXT" } );
            		}
                attribute = attributes.get("TXT");
                if ( attribute != null ) {
                		ip=attribute.get().toString();
                		if (Config.DNSBLUseCache) CHAddB(tip,service);
                		return service;
                		}
            } 	catch (NameNotFoundException e) {}
            	catch (NamingException e) {}
        }
     
     if (Config.DNSBLUseCache) CHAddB(tip,null);
     return null;
    }
	   
    @SuppressWarnings("rawtypes")
	public MXRecord[] getMX(String hostname) {
         MXRecord[] re =null;
    	
    	 if (Config.DNSBLUseCache) {
        	int tcr= (int)(System.currentTimeMillis()/1000);
        	if (tcr>GarbageTCR|| CacheMX.size()>Config.DNSBLCacheSize) {
        		GarbageTCR=(int)((System.currentTimeMillis()/1000)+Config.DNSBLCacheTTL);
        		Garbage(!Config.MindlessCompilant); //Minimo 1" 
        		}
        	if (CacheMX.containsKey(hostname)) return CacheMX.get(hostname);
        	}
    	
    	try {
            
            String[] typ = new String[] { "MX" };
            Attributes dnsdata;
            synchronized (Cox) {
            	dnsdata = Cox.getAttributes(hostname, typ);
            	}	
            Attribute data = dnsdata.get("MX");
           
            if(data != null && data.size() > 0)  {
					String tmp="";
					NamingEnumeration obj = data.getAll();
                    while(obj.hasMore()) tmp+=(String) obj.next()+"\n";
                    tmp=tmp.trim();
                    String[] Tok = tmp.split("\\n+");
                    int cx = Tok.length;
                    re = new MXRecord[cx];////
                    for (int ax=0;ax<cx;ax++) {
                    		String[] Tik = Tok[ax].split("\\s+");
                    		if (Tik.length!=2) continue;
                    		int dx = Tik[1].length()-1;
                    		Tik[1] = Tik[1].substring(0,dx);
                    		re[ax] = new MXRecord( J.parseInt(Tik[0]),Tik[1]);
                    		}	
                    
                    if (Config.DNSBLUseCache) CHAddM(hostname,re);                    
                    return re;
                } else {
                	if (Config.DNSBLUseCache) CHAddM(hostname,null);
                	return null;
                	} 
            
    	} catch(Exception ne) {
    		if (Config.DNSBLUseCache) CHAddM(hostname,null);
    		return null; 
    		}
    }
	
}
