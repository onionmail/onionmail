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

public class PException extends Exception {

	private static final long serialVersionUID = 2701305490619748514L;
	public int TYPE = 0;
	public String Subject=null;
	
	public static final int MS_Typ=							0xFF000000;
	public static final int MS_Id=								0x0000FFFF;
	public static final int MS_Act=							0x00FF0000;
	public static final int TF_Conf=							0x01000000;
	public static final int TF_Session=						0x02000000;
	public static final int TF_Session_Bad=				0x02010000;
	
	PException(String fuffa) { super(fuffa); }
	PException() { super(); }
	PException(int code,String fuffa) { super("@"+Integer.toString(code+1000).substring(1,4)+" "+fuffa.replace("\n", "")); }
}
