package org.tramaci.onionmail;

public class ETHTimeoutException extends Exception {
	
	private static final long serialVersionUID = 8191189068025555063L;
	ExtraThread T=null;
	
	ETHTimeoutException(ExtraThread ET) {
		super("ETH Timeout: "+ET.Server.Nick+":"+ET.Oper+" "+Long.toHexString(ET.exclusiveID));
		T.excetpioned=true;
		if (!ET.isInterrupted()) try { ET.interrupt(); } catch(Exception  E) {}
		ET.LoopOn=false;
		T=ET;
		T.Server.Log("ETH Timeout: "+T.Oper);
		try { T.onTimeout(); } catch(Exception E) {
			T.Server.Log(Config.GLOG_Bad, "ETH Timeout: "+ET.Oper+" "+Long.toHexString(ET.exclusiveID));
			if (T.Server.Config.Debug) E.printStackTrace();
			}
		T.Error=this;
		}
	
	}
