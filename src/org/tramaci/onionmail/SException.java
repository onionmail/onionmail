package org.tramaci.onionmail;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

public class SException extends Exception {
	private static final long serialVersionUID = 6511514952346097990L;
	
	public SSLParameters SSLParam = null;
	public SSLSession SSLSess = null;
	public String Host = null;
	
	public String OvrMsg=null;
	
	SException(String fuffa) { super(fuffa); }
	SException() { super(); }
	SException(int code,String fuffa) { super("@"+Integer.toString(code+1000).substring(1,4)+" "+fuffa.replace("\n", "")); }
	SException(Exception E) {
		super();
		if (E.getMessage()!=null) OvrMsg=E.getMessage();
		}
	
	SException(Exception E,String pre) {
		super();
		if (E.getMessage()!=null) OvrMsg=pre+": "+E.getMessage(); else OvrMsg=pre;
		}
	
	public String getMessage() {
		if (OvrMsg!=null) return OvrMsg;
		return super.getMessage();
		}
	
	public void concat(String s) {
		if (OvrMsg==null) {
			if (super.getMessage()==null) OvrMsg=s; else OvrMsg=super.getMessage()+" "+s;
			} else OvrMsg+=" "+s;
		}
	
}
