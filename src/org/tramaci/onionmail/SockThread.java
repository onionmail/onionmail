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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;


public class SockThread extends Thread{
	private Socket conc = null;
	private Socket cons = null;
	private InputStream C = null;
	private OutputStream S = null;
	private SocksConnection SOK = null;
	public boolean running=true;
	SockThread(Socket cli,Socket srv, SocksConnection sok) throws Exception  {
		super();
		conc = cli;
		cons = srv;
		SOK=sok;
		C = conc.getInputStream();
		S = cons.getOutputStream();
		start();
	}
	
	public void run() {
		running=true;
		while(running) try {
				int i = C.available();
				if (i<1) i=1;
				if (i>8192) i=8192;
				byte[] buf = new byte[i];
				SOK.Refresh();
				C.read(buf);
				if (conc.isClosed() || cons.isClosed()) break;
				S.write(buf);
				buf=null;
				} catch(Exception E) { 
					running=false;
					break;
				}
			try { conc.close(); } catch(Exception E) {}
			try { cons.close(); } catch(Exception E) {}
			SOK.EndTime = 0;
			running=false;
			}
}
