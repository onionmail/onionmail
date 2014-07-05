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

import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;

public class Main {
	static byte[] charH = null;
	static byte[] charFrom = null;
	static byte[] charTo = null;
	static byte[] fontFlags = null;
	static int[] fontPTR = null;
	static int[] fix=null;
	
	public static final byte FLG_SYMBOL= 1;
	public static final byte FLG_AZL= 2;
	public static final byte FLG_AZU= 4;
	public static final byte FLG_NUM= 8;
	public static final byte FLG_ALL= 16;
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try { Run(); } catch(Exception E) {
			E.printStackTrace();
			}
				
		}

	public static void Run() throws Exception {
		String outFile="out";
		String path="bin/";
		boolean useMeta=false; //true;
		
		byte[] arb = Main.file_get_bytes("list.txt");
		String st = new String(arb);
		arb=null;
		st=st.trim();
		String[] list = st.split("\\n+");
		int max=list.length;
		charH = new byte[max];
		charFrom = new byte[max];
		charTo = new byte[max];
		fontFlags = new byte[max];
		fontPTR=new int[max];
		fix=new int[max];
		int fontAx=0;
		int metaSize=4;
		
		for (fontAx=0;fontAx<max;fontAx++) {
			list[fontAx]=list[fontAx].trim();
			String[] tok = list[fontAx].split("\\s+");
			list[fontAx] = tok[0].trim();
			if (tok.length>1) fix[fontAx]=Integer.parseInt(tok[1].trim());
			
			if (useMeta) metaSize+=list[fontAx].length()+1;
			}
		
		int dataPtr = 12+metaSize + 8*max;
		
		fontAx = dataPtr>>4;
		if ((dataPtr&15)!=0) fontAx++;
		dataPtr=fontAx*16;
		dataPtr-=4;
				
		File FS = new File(outFile);
		if (FS.exists()) FS.delete();
		RandomAccessFile O = new RandomAccessFile(outFile,"rw");
		O.seek(0);
		arb = new byte[dataPtr];
		O.write(arb);
		O.write("DATA".getBytes());
		
		arb=null;
		for (fontAx = 0 ; fontAx<max;fontAx++) {
				RandomAccessFile I = new RandomAccessFile(path+list[fontAx],"rw");
				I.readInt();
				I.readByte();
				charH[fontAx] = I.readByte();
				charFrom[fontAx] = I.readByte();
				charTo[fontAx] = I.readByte();
				int a = 255&charFrom[fontAx];
				int b = 255&charTo[fontAx];
				if (a==0 && b==255) {
							fontFlags[fontAx] = Main.FLG_ALL | Main.FLG_AZL | Main.FLG_AZU | Main.FLG_NUM | Main.FLG_SYMBOL;
							} else {
							if (a<=49 && b>=57) fontFlags[fontAx] |=Main.FLG_NUM;
							if (a<=65 && b>=90) fontFlags[fontAx] |=Main.FLG_AZU;
							if (a<=97 && b>=122) fontFlags[fontAx] |=Main.FLG_AZL;
							if ( 
									fontFlags[fontAx]==0 ||
									a<0x2f ||
									a>0x7b ||
									b>0x7b ||
									b<0x2f ||
									(a>-1 && b<0x30) ||
									(a>0x5a && b<0x61) ||
									(a>0x7C && b<0x100) ) fontFlags[fontAx] = Main.FLG_SYMBOL;
							}
				fontPTR[fontAx] = (int) O.getFilePointer();
				I.seek(15+fix[fontAx]);
				int sz = (int) (I.length() - 16);
				arb = new byte[sz];
				I.read(arb);
				I.close();
				O.write(arb);
				arb=null;
				}
	O.seek(0);
	O.write("FONT".getBytes());
	O.writeShort(max);
	O.write(charH);
	O.write(charFrom);
	O.write(charTo);
	O.write(fontFlags);
	for (fontAx=0;fontAx<max;fontAx++) O.writeInt(fontPTR[fontAx]);
	if (useMeta) {
		O.write("META".getBytes());
		for (fontAx=0;fontAx<max;fontAx++) {
				arb = list[fontAx].getBytes();
				int len = arb.length;
				O.write(len);
				O.write(arb);
				}
		}
	O.close();
	}
	
	
	
	
	public static byte[] file_get_bytes(String name) throws Exception {
		File file = new File(name);
		long length = file.length();
		if (length>512384) throw new Exception("File Too big");
		
		byte[] data=new byte[(int)length];
		FileInputStream f = new FileInputStream(name);
		
		f.read(data);
		f.close();
		return data;
	}
	
}
