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

public class Const {
	
		public static final int MX_MIddle =				0x1A00;
		public static final int MX_User = 				0x1A02;
		public static final int MX_HashMap = 		0x1A03;
		public static final int MX_Server_Conf=	0x1A04;
		public static final int MX_DBTrust=			0x1A08;
		public static final int MX_ListExit=				0x1A29;
		public static final int MX_CertChain=		0x1A0A;
		public static final int MX_Friends=				0x1A0B;
		public static final int MX_Alias=					0x1A0C;
		public static final int MX_RVMAT=				0x1A0D;
		public static final int MX_DERK=				0x7310;
		public static final int MX_ExitRouterInfo=0x1A0E;
		public static final int MX_RemotePhFile=	0xFCAF;
		public static final int MX_RemotePhFileS=	0xFCAE;
		public static final int MX_E_Boot=				0x7C01;
		public static final int MX_1_Boot=				0x7C00;
		
		public static final int MX_RKCTL=				0xfc4a;
		
		public static final int MS_Server = 			0x701;
		
		
		public static final int MX_Message=			0x1ac801;
		public static final int UBL_Magic = 			0xfeca;
		
		public static final int MIntent_SpamList=	0xfeca01;
		
		public static final int SRV_DTA = 				0x900e;
		
		public static final String USR_FLG_ADMIN="A";
		public static final String USR_FLG_TERM="U";
		
		public static final String KD_ExitList="OnionMail.ExitList("+Long.toString(0x13c03c0942942dc8L,36)+")";
		public static final String Manifest_Splitter="-:-";
		public static final String TormVer="1.5, VMAT, MX, MF2";
		
		public static final String ASC_KB_KCTL = "KCTL";
		public static final String SRV_PRIV="#Server/Private#";
		
		protected static void ZZ_Exceptionale() throws Exception { throw new Exception(); } //Remote version verify	
}
