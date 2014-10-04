/*
 * Copyright (C) 2014 by Tramaci.Org
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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.util.HashMap;

public class WebCheck {

	public String name = "";
	public String value = "";
	private String onPath=null;
	private boolean onPathFile=true;
	public boolean not = false;
	public boolean caseSensitive=false;
	public boolean onDefault=false;
	public short condition = 0;	
	public short type = 0;
	public String[] removedBy=new String[0];
	public String[] onlyWith=new String[0];
	
	public String actionPar=null;
	public short action=0;
	
	public static final short WCA_NOP=0;
	public static final short WCA_REDIRECT=1;
	public static final short WCA_DENY=2;
	public static final short WCA_404=3;
	public static final short WCA_SET=4;
	public static final short WCA_LOG=6;
	
	public static final short WCC_PRESENT = 1;
	public static final short WCC_STARTW = 2;
	public static final short WCC_ENDW = 3;
	public static final short WCC_CONTAINS = 4;
	public static final short WCC_LT=5;
	public static final short WCC_GT=6;
	public static final short WCC_MATCH=7;
	public static final short WCC_EQUAL=8;
	public static final short WCC_DUMMY=9;
			
	public static final short WCT_HEADER=1;
	public static final short WCT_SESSION=2;
	public static final short WCT_ETEXVAR=3;
	public static final short WCT_POST=4;
	public static final short WCT_GET=5;
	
	public void setOnPath(String p) {
		if (!p.endsWith("/")) p+="/";
		onPath=p;
		onPathFile=false;
		}
	
	public void setOnFile(String f) {
		onPath=f;
		onPathFile=true;
		}
	
	public static HashMap <String,Boolean> eval(
				String currentPath,
				HashMap <String,WebCheck> test,
				HashMap <String,String> headers,
				HashMap <String,String> Session,
				HashMap <String,String> ETEXVar,
				HashMap <String,String> Get,
				HashMap <String,String> Post ) throws Exception {
		
		HashMap <String,Boolean> rs = new HashMap <String,Boolean>();
		for (String k:test.keySet()) {
			WebCheck ck = test.get(k);
			if (ck==null) continue;
			
			if (ck.onPath!=null) {
				if (ck.onPathFile) {
					if (ck.onPath.compareTo(currentPath)!=0) continue;
					} else {
					if (!currentPath.startsWith(ck.onPath)) continue;	
					}
				}
			
			boolean bit = ck.evalLevel1(headers, Session, ETEXVar, Get, Post);

			rs.put(k, bit);
			}
		
		HashMap <String,Boolean> rs2 = new HashMap <String,Boolean>();
		for (String k:rs.keySet()) {
			boolean bit = rs.get(k);
			WebCheck ck = test.get(k);
			
			if (bit) {
				int cx = ck.onlyWith.length;
				for (int ax=0;ax<cx;ax++) {
					boolean sb=false;
					if (!rs.containsKey(ck.onlyWith[ax])) {
						if (!test.containsKey(ck.onlyWith[ax])) throw new Exception("@500 The WebCheck `"+k+"` is try to get value from unknown element `"+ck.onlyWith[ax]+"`");
						sb = test.get(ck.onlyWith[ax]).onDefault;
						} else sb = rs.get(ck.onlyWith[ax]);
					if (!sb) {
						bit=false;
						break;
						}
					}
				}
			
			if (bit) {
				int cx = ck.removedBy.length;
				
				for (int ax=0;ax<cx;ax++) {
					boolean sb=false;
					if (!rs.containsKey(ck.removedBy[ax])) {
						if (!test.containsKey(ck.removedBy[ax])) throw new Exception("@500 The WebCheck `"+k+"` is try to get value from unknown element `"+ck.removedBy[ax]+"`");
						sb = test.get(ck.removedBy[ax]).onDefault;
						} else sb = rs.get(ck.removedBy[ax]);
					if (sb) {
						bit=false;
						break;
						}
					}
				}
		
			bit^=ck.not;
			rs2.put(k, bit);
			}
		
		return rs2;
		}
	
	private boolean evalLevel1(
				HashMap <String,String> headers,
				HashMap <String,String> Session,
				HashMap <String,String> ETEXVar,
				HashMap <String,String> Get,
				HashMap <String,String> Post ) throws Exception {
		
		boolean bit = false;
		
		if (type == WebCheck.WCT_ETEXVAR) bit = subEval(ETEXVar);
		if (type == WebCheck.WCT_GET) bit = subEval(Get);
		if (type == WebCheck.WCT_HEADER) bit = subEval(headers);
		if (type == WebCheck.WCT_POST) bit = subEval(Post);
		if (type == WebCheck.WCT_SESSION) {
				if (Session==null) bit = onDefault; else bit = subEval(Session);
				}

		return bit;		
	}
	
	private boolean subEval(HashMap <String,String> H) throws Exception {
		
		if (condition==WebCheck.WCC_DUMMY) return true;
		if (H.containsKey(name)) {
			if (condition==WebCheck.WCC_PRESENT) return true;
			String val = H.get(name);
			String base=value;
			if (val==null) val="";
			if (!caseSensitive) {
				val=val.toLowerCase();
				base=base.toLowerCase();
				}
			if (condition==WebCheck.WCC_ENDW) return val.endsWith(base);
			if (condition==WebCheck.WCC_STARTW) return val.startsWith(base);
			if (condition==WebCheck.WCC_CONTAINS) return val.contains(base);
			if (condition==WebCheck.WCC_EQUAL) return val.compareTo(base)==0;
			if (condition==WebCheck.WCC_GT) return val.compareTo(base)>0;
			if (condition==WebCheck.WCC_LT) return val.compareTo(base)<0;

			try {
				if (condition==WebCheck.WCC_MATCH) return val.matches(base);
				} catch(Exception E) {
					throw new Exception("@500 Invalid REGEXP in WebCheck `"+name+"`");
				}

			return false;			
			}

		return onDefault;
		}
	
	public static HashMap <String,WebCheck> FileParser(String file) throws Exception {
		FileInputStream F = new FileInputStream(file);
		BufferedReader L = J.getLineReader(F);
		String li="";
		int linea=0;
		HashMap <String,WebCheck> RS = new HashMap <String,WebCheck>();
		Exception Error=null;
		try {
			while(true) {
				li = L.readLine();
				linea++;
				if (li==null) break;
				li = li.trim();
				String[] tok = li.split("\\#",2);
				li=tok[0];
				li=li.trim();
				if (li.length()==0) continue;
				li = li.replace("\t", " ");
				if (
							!li.matches("[a-zA-Z0-9]{1,40}\\s+\\{") &&
							!li.matches("[a-zA-Z0-9]{1,40}\\-[a-zA-Z0-9]{1,40}\\s+\\{") 
							) throw new Exception("Invalid WebCheck in line "+linea);
				
				WebCheck x = new WebCheck();
				tok = li.split("\\s+");
				String name = tok[0].toLowerCase();
				
				if (RS.containsKey(name)) throw new Exception("Overlapped definition for `"+name+"` in line "+linea);
				
				boolean endOk=false;
				boolean norRed=false;
					while(true) {
						li = L.readLine();
						linea++;
						if (li==null) break;
						li = li.trim();
						tok = li.split("\\#",2);
						li=tok[0];
						li=li.trim();
						if (li.length()==0) continue;
						li = li.replace("\t", " ");
						tok=li.split("\\s+",2);
						tok[0]=tok[0].toLowerCase();
						
						if (tok[0].compareTo("dup")==0 || tok[0].compareTo("new")==0) {
							if (norRed) throw new Exception("The duplication command is not the first command of `"+name+"` on line "+linea);
							tok[1]=tok[1].toLowerCase();
							if (!RS.containsKey(tok[1])) throw new Exception("Can't duplicate unknown `"+tok[1]+"` in `"+name+"` on line "+linea);
							WebCheck o = RS.get(tok[1]);
							if (o==null) throw new Exception("WebCheck not found `"+tok[1]+"` on line "+linea);
							x.action=o.action;
							x.actionPar=o.actionPar;
							x.caseSensitive=o.caseSensitive;
							x.condition=o.condition;
							x.name=o.name;
							x.not=o.not;
							x.onDefault=o.onDefault;
							x.onlyWith=o.onlyWith;
							x.onPath=o.onPath;
							x.onPathFile=o.onPathFile;
							x.removedBy=o.removedBy;
							x.type=o.type;
							x.value=o.value;
							norRed=true;
							continue;
							}
						
						norRed=true;
						
						if (tok[0].contains("when")) {
							if (tok[0].contains("not")) x.not=true;
							if (tok.length!=2) throw new Exception("Invalid `when` definition in `"+x.name+"` on line "+linea);
							tok=tok[1].split("\\s+",3);
							if (tok.length!=3) throw new Exception("Invalid `when` definition in `"+x.name+"` on line "+linea);
							tok[0]=tok[0].toLowerCase();
							String[] pox = tok[0].split("\\.",2);
							if (pox.length!=2) throw new Exception("Invalid subject on `when` definition in `"+x.name+"` on line "+linea);
							x.name=pox[1];
							x.value=tok[2];
							tok[1]=tok[1].toLowerCase();
							
							if (tok[1].compareTo("=")==0  || tok[1].compareTo("is")==0) x.condition=WebCheck.WCC_EQUAL;
							if (tok[1].compareTo(">")==0) x.condition=WebCheck.WCC_GT;
							if (tok[1].compareTo("<")==0) x.condition=WebCheck.WCC_LT;
							if (tok[1].compareTo("(")==0 || tok[1].compareTo("start")==0) x.condition=WebCheck.WCC_STARTW;
							if (tok[1].compareTo(")")==0  || tok[1].compareTo("end")==0) x.condition=WebCheck.WCC_ENDW;
							if (tok[1].compareTo("()")==0 || tok[1].compareTo("contains")==0) x.condition=WebCheck.WCC_CONTAINS;
							if (tok[1].compareTo("has")==0 && x.value.toLowerCase().contains("key")) x.condition=WebCheck.WCC_PRESENT;
							if (tok[1].compareTo("match")==0) x.condition=WebCheck.WCC_MATCH;
							if (x.condition==0) throw new Exception("Invalid condition operator `"+tok[1]+"` on `when` definition in `"+name+"` on line "+linea);
							
							if (pox[0].compareTo("head")==0) { x.type=WebCheck.WCT_HEADER; continue; }
							if (pox[0].compareTo("session")==0) { x.type=WebCheck.WCT_SESSION; continue; }
							if (pox[0].compareTo("get")==0) { x.type=WebCheck.WCT_GET; continue; }
							if (pox[0].compareTo("post")==0) { x.type=WebCheck.WCT_POST; continue; }
							if (pox[0].compareTo("etex")==0) { x.type=WebCheck.WCT_ETEXVAR; continue; }
							throw new Exception("Invalid subject pointer `"+pox[0]+"` on `when` definition in `"+name+"` on line "+linea);
							}
						
						if (tok[0].compareTo("case")==0) {
							x.caseSensitive=true;
							continue;
							}
						
						if (tok[0].compareTo("default")==0 && tok.length==2) {
							tok[1]=tok[1].toLowerCase();
							
							if (tok[1].compareTo("true")==0) {
								x.onDefault=true;
								continue;
								}
							
							if (tok[1].compareTo("false")==0) {
								x.onDefault=false;
								continue;
								}
							
							}
						
						if (tok[0].compareTo("and")==0 && tok.length==2) {
							String[] pox = tok[1].split("\\s+");
							int cx = pox.length;
							String sy="";
							String sn="";
							for (int ax=0;ax<cx;ax++) {
								String c = pox[ax];
								if (c.startsWith("!")) {
									c=c.substring(1);
									sn+=c+"\n";
									} else {
									sy+=c+"\n";
									}
								}
							sn=sn.toLowerCase();
							sy=sy.toLowerCase();
							sn=sn.trim();
							sy=sy.trim();
							x.onlyWith=sy.split("\\n+");
							x.removedBy=sn.split("\\n+");
							continue;
							}
						
						if (tok[0].compareTo("onpath")==0 && tok.length>1) {
							x.setOnPath(tok[1]);
							continue;
							}
						
						if (tok[0].compareTo("onfile")==0 && tok.length>1) {
							x.setOnFile(tok[1]);
							continue;
							}
						
						
						if (tok[0].compareTo("deny")==0) {
							x.action=WebCheck.WCA_DENY;
							continue;
							}
						
						if (tok[0].compareTo("404")==0) {
							x.action=WebCheck.WCA_404;
							continue;
							}
						
						if (tok[0].compareTo("set")==0 && tok.length>1) {
							if (!tok[1].matches("[shpgvSHPGV]{1}\\.[a-zA-Z0-9\\_\\-]{1,40}\\=*")) throw new Exception("Invalid set format for `"+name+"` in line "+linea);
							x.action=WebCheck.WCA_SET;
							x.actionPar=tok[1];
							continue;
							}
												
						if (tok[0].compareTo("redirect")==0 && tok.length>1) {
							x.action=WebCheck.WCA_REDIRECT;
							x.actionPar=tok[1];
							continue;
							}
						
						if (tok[0].compareTo("log")==0 && tok.length>1) {
							x.action=WebCheck.WCA_LOG;
							x.actionPar=tok[1];
							continue;
							}
						
						if (tok[0].compareTo("}")==0 && tok.length==1) {
							endOk=true;
							break;
							}
						
						throw new Exception("Unknown command `"+tok[0]+"` in line "+linea);
						} //while2
				
					if (!endOk) throw new Exception("Definition not closed in line "+linea);
					
					if (
							x.type==0 ||
							x.condition==0 ||
							x.name.length()==0 ||
							x.value.length()==0 ) throw new Exception("Incomplete definition of `"+name+"` in line "+linea);
					
				RS.put(name, x);
					
				} //while1
		} catch(Exception E) {
			Error=E;
			}
		
	try { F.close(); } catch(Exception IO) {}
	try { L.close(); } catch(Exception IO) {}
	
	if (Error==null) return RS; else throw Error;
	} //fun
	
}
