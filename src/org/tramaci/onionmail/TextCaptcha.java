package org.tramaci.onionmail;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.SecureRandom;

public class TextCaptcha {
	
	public static final String DEFAULT_FILE="TextCaptcha.ext";
	
	private static final byte FLG_SYMBOL= 1;
	private static final byte FLG_AZL= 2;
	private static final byte FLG_AZU= 4;
	private static final byte FLG_NUM= 8;
	
	public static final int MODE_SWX = 1;
	public static final int MODE_SWY = 2;
	public static final int MODE_SYM = 4;
	public static final int MODE_NOISE=8;
	public static final int MODE_INV=16;
	public static final int MODE_SQR=32;
	public static final int MODE_UTF8=64;
	public static final int MODE_RANDOM=128;
	public static final int MODE_NUMBERONLY = 256;
	
	private static byte[] charH = null;
	private static byte[] charFrom = null;
	private static byte[] charTo = null;
	private static byte[] fontFlags = null;
	private static int[] fontPTR = null;

	private static int maxFont = 0;
	private static RandomAccessFile F = null;
	private static long loadedTCR = 0;
	private static long fontDataTTL = 60000;
	private static String fontFile = null;
	private static SecureRandom random = null;
	
	private static volatile boolean running=false;
	
	public static boolean isEnabled() { return fontFile!=null; }
	
	private static void LoadFontsEx(String file) throws Exception {
		if (!new File(file).exists()) throw new Exception("File not found `"+file+"`");
		F = new RandomAccessFile(file,"r");
		F.seek(0);
		if (F.readInt()!=0x464f4e54) throw new Exception("Invalid multiFont file");
		maxFont = F.readShort();
		charH = new byte[maxFont];
		charFrom = new byte[maxFont];
		charTo = new byte[maxFont];
		fontFlags = new byte[maxFont];
		fontPTR=new int[maxFont];
		F.read(charH);
		F.read(charFrom);
		F.read(charTo);
		F.read(fontFlags);
		for (int fontAx=0;fontAx<maxFont;fontAx++) fontPTR[fontAx] = F.readInt();
	
		loadedTCR= System.currentTimeMillis()+fontDataTTL;
		random = SecureRandom.getInstance("SHA1PRNG");
		}
	
	public static synchronized void LoadFonts(String file) throws Exception {
		fontFile = file;
		if (!running) {
				if (F!=null) try { F.close(); } catch(Exception E) {}
				F=null;
				LoadFontsEx(fontFile);
				}
		} 
	
	private static void preload() throws Exception {
		if (F==null) {
			if (fontFile==null) throw new Exception("Not initialized");
			LoadFontsEx(fontFile);
			}
		}
	
	public static void Garbage(boolean force) {
		if (force || (!running && System.currentTimeMillis()>loadedTCR)) {
			if (F!=null) try { F.close(); } catch(Exception E) {}
			charH =null;
			charFrom = null;
			charTo = null;
			fontFlags = null;
			fontPTR=null;
			F=null;
			random=null;
			}
		}
	
	public static void square(boolean[][] bitmap,int x0,int y0,int sw,int sh,int maxW,int maxH,boolean bit) {
		
		for (int y =0 ;y<sh;y++) {
			for (int x=0;x<sw;x++) {
			int xx=x0+x;
			int yy=y0+y;
			if (xx>-1 && yy>-1 && xx<maxW && yy<maxH) bitmap[xx][yy]=bit;
			}
		}
	}
	
	public static void writeChar(boolean[][] bitmap, int charCode,int px,int py,int fontId,boolean invX,boolean invY,boolean inv,int maxW,int maxH) throws Exception {
		preload();
		int ch = charCode - charFrom[fontId];
		int bp =fontPTR[fontId] +( ch * charH[fontId]);
		byte[] dta = new byte[(int) charH[fontId]];

		synchronized(F) {
			F.seek(bp);
			F.read(dta);
			}
		
		int byt=0;
		int h =charH[fontId];
		for (int y = 0 ;y <h ; y++) {
					byt=dta[y]&255;
					for (int x=0;x<8;x++) {
						boolean bit=false;
						if (invX) bit = ((1<<x)&byt)!=0; else bit = ((1<<(7-x))&byt)!=0;
						int xx = px+x;
						int yy;
						if (invY) yy = py+(h-y); else yy= py+y;
						bit^=inv;
						if (xx>-1 && yy>-1 && xx<maxW && yy<maxH) bitmap[xx][yy] |=bit;
					}
			}
		
		if (inv) {
			for (int y = 0 ;y <h ; y++) {
				int yy=py+y;
				int xx=px-1;
				if (xx>-1 && yy>-1 && xx<maxW && yy<maxH) bitmap[xx][yy]=true;
				xx=px+8;
				if (xx>-1 && yy>-1 && xx<maxW && yy<maxH) bitmap[xx][yy]=true;
				}
			for (int x = -1 ;x <9 ; x++) {
				int yy=py-1;
				int xx=px+x;
				if (xx>-1 && yy>-1 && xx<maxW && yy<maxH) bitmap[xx][yy]=true;
				yy=py+h;
				if (xx>-1 && yy>-1 && xx<maxW && yy<maxH) bitmap[xx][yy]=true;
				}
			
			}
	}
	
	private static int[][] randomFontSelector(String code) throws Exception {
		int cx = code.length();
		int[][] arr = new int[cx][3];
		
		for (int ax=0;ax<cx;ax++) {
			int rf = Math.abs(random.nextInt()) % maxFont;
			int charCode = code.codePointAt(ax);
			int fontId=-1;
			int req = FLG_SYMBOL;
			int def=-1;
			if (charCode>0x29 && charCode<0x3a) req=FLG_NUM;
			if (charCode>0x40 && charCode<0x5b) req=FLG_AZU;
			if (charCode>0x60 && charCode<0x7b) req=FLG_AZL;
			
			for (int al=0;al<maxFont;al++) {
				int bl = (al+rf) % maxFont;
				if ((fontFlags[bl]&req)!=0) {
					fontId=bl;
					break;
					}
				if (charCode>=(charFrom[bl]&255) && charCode<=(charTo[bl]&255)) def=al;
				}
			
			if (fontId==-1) fontId=def;
			if (fontId==-1) throw new Exception("Too few fonts to find current situation");
			
			if (req==FLG_SYMBOL || charCode==0x2a) {
				charCode = (random.nextInt()&255);
				charCode = charCode % ((charTo[fontId]&255)-(charFrom[fontId]&255));
				charCode = (charFrom[fontId]&255) + charCode;
				}
			
			arr[ax][0] = charCode;
			arr[ax][1] = fontId;
			arr[ax][2] = charH[fontId];
			}
		return arr;
	}
	
	private static Object[] getNewCode(int[][] dta) {
		int cx = dta.length;	
		int bad=0;
		String code="";
		for (int ax=0;ax<cx;ax++) {
			int req = FLG_SYMBOL;
			int charCode = dta[ax][0];
			if (charCode>0x2f && charCode<0x3a) req=FLG_NUM;
			if (charCode>0x40 && charCode<0x5b) req=FLG_AZU;
			if (charCode>0x60 && charCode<0x7b) req=FLG_AZL;
			if (req!=FLG_SYMBOL) code+=(char)(charCode); else bad++;
		}
		return new Object[] { code.trim() , bad }; 
	}
	
	private static boolean[][] drawCaptcha(int[][] code,int wh,int he,int mode) throws Exception {
		running=true;
		boolean bitmap[][] = new boolean[wh][he];
		int xx =  1+Math.abs(random.nextInt())%3;
		int len = code.length;
		
		if ((mode&MODE_SQR)!=0) for (int ax =0 ;ax<len;ax++) {
			int h = 4*(Math.abs(random.nextInt())%4);
			
			square(bitmap,
					(ax*9)+xx+(Math.abs(random.nextInt())%4)-2,
					2+Math.abs(random.nextInt())%(he-h),
					8, h, wh, he, true)
					;		
			
			square(bitmap, 
						(Math.abs(random.nextInt())%wh)-4, 
						(Math.abs(random.nextInt())%he)-4,
						4,4, wh, he, false)
						;
			}
	
		for (int ax =0 ;ax<len;ax++) {
			int y = Math.abs(random.nextInt()) % (he-code[ax][2]);
			
			if ((mode&MODE_SQR)!=0) square(bitmap, xx, y, 8, code[ax][2], wh, he, false); 
			
			writeChar(bitmap,code[ax][0],xx,y,code[ax][1],
						( mode&MODE_SWX)!=0 ? random.nextBoolean() : false,
						( mode&MODE_SWY)!=0 ? random.nextBoolean() : false,
						( mode&MODE_INV)!=0 ? random.nextBoolean() : false,
						wh,he)
						;
			
			xx+=10+ (Math.abs(random.nextInt()) % 2);
			}
		running=false;
		return bitmap;
		}
	
	public static String bitmap2Text(boolean[][] bmp,String zero,String uno,int wh,int he) {
		char[] b0 = zero.toCharArray();
		char[] b1 = uno.toCharArray();
		String txt="";
		for (int y=0;y<he;y++) {
			for (int x=0;x<wh;x++) {
				int r = Math.abs(random.nextInt());
				if (bmp[x][y]) txt+=b1[r%b1.length]; else txt+=b0[r%b0.length];
			}
		txt+="\n";	
		}
	return txt;
	}
	
	private static String codeGen(int sz,int mode) {
		String alfa;
		char[] none;
		if ((mode & MODE_NUMBERONLY)!=0) {
			alfa ="12345780";
			none ="69|&£qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM".toCharArray();			
			} else {
			alfa ="1345780QERTYUADFGHJLKXCVBrtyihjkxcv";
			none ="69Opql|ZNbdpPoun&£".toCharArray();
			}
		int nl=none.length;
		if ((mode&MODE_SYM)!=0) alfa+="********";
		
		char[] al = alfa.toCharArray();
		String code="";
		int mx = al.length;
		for (int ax=0;ax<sz;ax++) {
			int r = Math.abs(random.nextInt()) % mx;
			char c = al[r];
			if (c=='*') c =(char)(random.nextInt()&255);
			for (int bl=0;bl<nl;bl++) {
				if (none[bl]==c) c = 1;
				}
			code+=c;
			}
		return code;
		}
	
	public static CaptchaCode generateCaptcha(int nChar,int mode) throws Exception {
		running=true;
		try {
			preload();
			String sZero;
			String sUno;
			String sNZero;
			String sNUno;
			
			if ((mode&MODE_RANDOM)!=0) mode = random.nextInt() & mode;
						
			if ((mode&MODE_UTF8)!=0) {
				sZero="        ";
			 	sUno="\u2588\u2588\u2593";
			 	sNZero=",.'`\u2592\u25ab   ";
			 	sNUno="\u2593\u2593\u2593\u2593";	
			} else {
				sZero="               ";
			 	sUno="###@%MW";
			 	sNZero=",.` ";
			 	sNUno="WM$%@@@";
			}
			
			loadedTCR = System.currentTimeMillis()+fontDataTTL;
			int wh = 2+(11*nChar);
			int he = 18;
				
			if ((mode&MODE_NOISE)!=0) {
					sZero+=sNZero;
					sUno+=sNUno;
					} else sZero+=".,      ";
			
			if (random.nextBoolean()) {
				    String a = sZero;
				    sZero=sUno;
				    sUno=a;
					}
			
			String code=codeGen(nChar,mode);
			int[][] draw = randomFontSelector(code);
			
			Object[] rs = getNewCode(draw);
			code = (String) rs[0];
			boolean[][] bmp = drawCaptcha(draw,wh,he,mode);
			draw=null;
			String txt = bitmap2Text(bmp,sZero,sUno,wh,he);
			bmp=null;
			CaptchaCode re = new CaptchaCode();
			re.badChars=(int) rs[1];
			re.width=wh;
			re.height=he;
			re.code = code;
			re.image=txt;
			re.mode=mode;
			return re;
			} catch(Exception E) {
				running=false;
				throw E;
			}
		}
	
	public static CaptchaCode generateCaptchaEx(String code,int mode,int wh,int he,String sZero,String sUno) throws Exception {
		if (F==null) throw new Exception("Not initialized");
		running=true;
		try {
			if ((mode&MODE_RANDOM)!=0) mode = random.nextInt() & mode;
			loadedTCR = System.currentTimeMillis()+fontDataTTL;
			int[][] draw = randomFontSelector(code);
			Object[] rs = getNewCode(draw);
			code = (String) rs[0];
			boolean[][] bmp = drawCaptcha(draw,wh,he,mode);
			draw=null;
			String txt = bitmap2Text(bmp,sZero,sUno,wh,he);
			bmp=null;
			CaptchaCode re = new CaptchaCode();
			re.badChars=(int) rs[1];
			re.width=wh;
			re.height=he;
			re.code = code;
			re.image=txt;
			re.mode=mode;
			return re;
			} catch(Exception E) {
				running=false;
				throw E;
			}
		}
	
	public static String[] CaptchaForumula(int size) throws Exception {
					int maxi = (int) Math.pow(10,size);
					int a = (int) (0xFFFFFFFFL&Stdio.NewRndLong());
					int b = (int) (0xFFFFFFFFL&Stdio.NewRndLong());
					a=a%maxi;
					b=b%maxi;
					int c = a+b;
					String[] tok = new String[] { 
									"Equation: " ,
									Integer.toString(a),
									b<0 ? "-" : "+" ,
									Integer.toString(b).replace("-",""),
									"=",
									Integer.toString(c)}
									;
					
					c = (int) (Stdio.NewRndLong()&3)%3;
					c = 1+(c*2);
					String sol = tok[c];
					tok[c]= "X";
					String cap="";
					for (int al=0;al<6;al++) cap+=" "+tok[al]+" ";
				
					return new String[] {
							"Please solve the following equation/sum to prove you're human.\n"+
							cap.trim()+"\n"+
							"What is the value of X?" ,
							sol }
					;

			}
	
}
