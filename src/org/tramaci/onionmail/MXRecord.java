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

import java.net.InetAddress;

public class MXRecord {
    	public int Priority = 0;
    	public String Host = null;
    	private InetAddress A=null;
    	
    	public InetAddress getAddress() throws Exception {	//TODO Attenzione all'utilizzo di questo metodo può creare richieste DNS
    		if (A==null) A = InetAddress.getByName(Host);
    		return A;
    	}
    	
    MXRecord(int p, String h) {
    	Priority=p;
    	Host=h;
    }
      
    
    public static void MXSort(MXRecord[] records) {
	    int cx = records.length;
	    MXRecord tmp;
	    int bx = 0;
	    boolean running = true;
	    
	    while (running) {
	        running = false;
	        bx++;
	        for (int ax = 0; ax < cx - bx; ax++) {
	    
	        	if (records[ax].Priority > records[ax + 1].Priority) {
	                running = true;
	                tmp = records[ax];
	                records[ax] = records[ax + 1];
	                records[ax + 1] = tmp;
	                }
	        	
	        	}
	    	}
	    }
    
    
}
