package org.tramaci.onionmail;

public class ExtraThread extends Thread {
	
	public String Oper=null;
	private int OperID=0;
	public volatile long deadLine = 0;
	public volatile long startTime=0;
	public SrvIdentity Server=null;
	public Exception Error = null;
	public long exclusiveID=0;
	public volatile boolean LoopOn=false;
	public Object[] VAR = null;
	
	public static final long ETH_ID_FRIENDS=	0x1000000100000000L;
	public static final long ETH_ID_EXITUP=		0x1000000200000000L;
	
	public void Run() throws Exception {}
	public void onError(Exception E) throws Exception {}
	public void onTimeout() throws Exception {}
	
	public boolean excetpioned=false;
	
	public final void runCheck() throws Exception {
		if (	
				!LoopOn || 
				this.isInterrupted() ||
				System.currentTimeMillis()> this.deadLine ) throw new ETHTimeoutException(this);
		}
	
	public final void run() {
		startTime=System.currentTimeMillis();
		LoopOn=true;
		try { Run(); } catch(Exception E) {
			try {  
					Error=E;	
					Server.Log(Config.GLOG_Bad, "Th:"+Oper+" Error: "+E.getMessage());
					onError(E); 
					} catch(Exception F) {
					Server.Log(Config.GLOG_Bad,"Th:"+Oper+" Exception:"+F.getMessage());
					if (Server.Config.Debug) F.printStackTrace();
					}			
			}
		}

	public final void end() { 
		LoopOn=false;
		try { this.interrupt(); } catch(Exception E) {}
		}
		
	ExtraThread(SrvIdentity s,String oper,int timLen,long exc) throws Exception {
		startTime=System.currentTimeMillis();
		deadLine=startTime+1000L*timLen;
		Server=s;
		Error=null;
		Oper=oper;
		OperID=Oper.hashCode();
		exclusiveID=exc;
		int cx = Main.ETH.length;
		int zt=-1;
		this.setName("ETH "+s.Nick+" "+oper+ (exc!=0 ? " "+Long.toHexString(exc) : ""));
		for (int ax=0;ax<cx;ax++) {
			if (exclusiveID!=0 && Main.ETH[ax]!=null && Main.ETH[ax].exclusiveID==exclusiveID) throw new Exception("Double thread `"+oper+"` "+Long.toHexString(exclusiveID)+"`");
			if (Main.ETH[ax]!=null && startTime>Main.ETH[ax].deadLine) {
				Main.ETH[ax].end();
				Main.ETH[ax]=null;
				System.gc();
				}
			
			if (zt==-1 && Main.ETH[ax]==null) zt=ax;
			}
		
		if (zt==-1) throw new Exception("Too many ExtraThreads");
		Main.ETH[zt]=this;
		}
	
	public static void doGarbage() {
		int cx = Main.ETH.length;
		long tcr=System.currentTimeMillis();
		for (int ax=0;ax<cx;ax++) {
			if (Main.ETH[ax]!=null && (tcr>Main.ETH[ax].deadLine || Main.ETH[ax].Error!=null)) {
				if (Main.ETH[ax].Error!=null) 
						Main.ETH[ax].Server.Log("Terminate: `"+Main.ETH[ax].Oper+"` Error: "+Main.ETH[ax].Error.getMessage());
				else
						Main.ETH[ax].Server.Log("Terminate: `"+Main.ETH[ax].Oper+"` Timeout");
				Main.ETH[ax].end();
				Main.ETH[ax]=null;
				}
			}
		System.gc();
		}
	
	public static void killAll() {
		int cx = Main.ETH.length;
		for (int ax=0;ax<cx;ax++) {
			if (Main.ETH[ax]!=null) {
					Main.ETH[ax].end();
					Main.ETH[ax]=null;
					}
				}
		System.gc();
		}
	
	public static void killAll(String op) {
		int cx = Main.ETH.length;
		int opid=op.hashCode();
		for (int ax=0;ax<cx;ax++) {
				if (Main.ETH[ax]!=null &&  Main.ETH[ax].OperID==opid) {
					Main.ETH[ax].end();
					Main.ETH[ax]=null;
					}
				}
		System.gc();
		}
	
}
