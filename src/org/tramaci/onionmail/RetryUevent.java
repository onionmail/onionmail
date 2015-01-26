package org.tramaci.onionmail;

public class RetryUevent extends Exception {
	
	private static final long serialVersionUID = -3364956385352198211L;
	public int SMTPCode = 0;
	public String SMTPError = "";
	public String SMTPServer = "";
	public int position = 0;
	
	public static final int POX_EHLO = 0;
	public static final int POX_FROM = 1;
	public static final int POX_TO = 2;
	public static final int POX_DATA = 3;
	
	RetryUevent(int pox,int code, String error,String server) {
		super("@"+code+" "+error+" (pox/"+code+")");
		position=pox;
		SMTPCode = code;
		SMTPError=error;
		SMTPServer=server;
		}
	
}
