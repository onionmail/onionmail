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
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;


public class DNSServer extends Thread {

	public Config Config = new Config();

	public boolean running=true;
	public DatagramSocket serverSocket = null;
	public DatagramSocket clientSocket=null;
	
	private OnionRouter Router = null;
	
	public void run() {
		while (running) try { ServerDNS(); } catch(Exception E) { Config.EXC(E,"Server"); }
		try { serverSocket.close(); } catch(Exception E) {}
	}
	
	DNSServer(Config C,OnionRouter R) throws Exception {
		super();
		Config = C;
		Router = R;
		running=false;
		serverSocket = new DatagramSocket(53); 
		
		running=true;
		start();
	}
	
private void ServerDNS() throws Exception {

		 while(running)
               {
                  byte[] receiveData = new byte[512];
			 	  DatagramPacket receivePacket = new DatagramPacket(receiveData, 512);
                  serverSocket.receive(receivePacket);
                  InetAddress sourceAddr = receivePacket.getAddress();
                  int sourcePort = receivePacket.getPort();
                  int size = receivePacket.getLength();
                  DNSPacket D = new DNSPacket(receivePacket);
                //0 if (D.response) continue; //Rispondo io non tu!
                  if (D.response==true) continue;
                  if (Config.DNSLogQuery) Log("DNS: Req "+D.id+"\t"+D.qtype+"\t"+(D.response ? "A" : "Q")+"\t"+Integer.toHexString(D.rawhead)+"\tF: "+sourceAddr.toString()+":"+sourcePort+"\tH: `"+ D.Host+"`");
                  
                  if (!FireWallizer.IPCan(Config, sourceAddr)) {
                	Log("FireWallizer: "+sourceAddr.toString()+" Drop!");
                	continue;
                  	}
                  
                  if (D.Tld.compareTo("onion")==0) {
                	  //DNS onion
               
                	  D = Router.QueryDNS(D);
                      byte[]  sendData = D.DoReply();
                 	  DatagramPacket sendPacket =  new DatagramPacket(sendData, sendData.length, sourceAddr, sourcePort);
                 	  serverSocket.send(sendPacket);
                  } else {
                	  //DNS Proxy "Normale"
                	 clientSocket = new DatagramSocket();
                	 clientSocket.setSoTimeout(Config.DNSSoTimeout);
                	 try {                		 
	                	 DatagramPacket sendPacket =  new DatagramPacket(receivePacket.getData(), size,Config.DNSServer,53);
	                	 clientSocket.send(sendPacket);
	                	 receiveData = new byte[512];
	                	 receivePacket = new DatagramPacket(receiveData, 512);
	                	 clientSocket.receive(receivePacket);
	                	 if (Config.DNSLogQuery) Log("DNS: Reply by DNSServer");
	                	 DatagramPacket replyPacket =  new DatagramPacket(receivePacket.getData(), receivePacket.getLength(), sourceAddr,sourcePort);
	                	 serverSocket.send(replyPacket);
                	 	} catch(SocketTimeoutException T) { Log("Timeout"); } 
                  	}
               }
	}

	public void Log(String st) { Config.GlobalLog(Config.GLOG_Server, "DNS", st); 	}
	//public void Log(int flg,String st) { Config.GlobalLog(flg | Config.GLOG_Server, "DNS", st); 	}
}
