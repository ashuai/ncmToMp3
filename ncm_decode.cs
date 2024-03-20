using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;

// c# 解码ncm文件，基于dotnetfx by ashuai
class decode {
	byte[] meta_key = { 0x23,0x31,0x34,0x6C,0x6A,0x6B,0x5F,0x21,0x5C,0x5D,0x26,0x30,0x55,0x3C,0x27,0x28 };
	byte[] core_key = { 0x68,0x7A,0x48,0x52,0x41,0x6D,0x73,0x6F,0x35,0x6B,0x49,0x6E,0x62,0x61,0x78,0x57 };
	static public void Main(string[] args) {
		if( args.Length <= 0 ) {
			Console.WriteLine("require ncm music file.");
		} else {
			var ncm = new decode();
			ncm.DecodeFile(args[0]);
		}
	}
	
	public void DecodeFile(string file) {
		Info(file);
		var fs = new FileStream(file, FileMode.Open, FileAccess.Read);
		
		byte[] buf = new byte[16];
		int len = 0;
		int i = 0;
		
		fs.Seek(10, SeekOrigin.Current);
		fs.Read(buf, 0, 4);
    len = (int)BitConverter.ToUInt32(buf, 0);
		
		byte[] rc4Key = new byte[len];
		fs.Read(rc4Key, 0, len);
		// 解密rc4密钥
		for( i = 0; i < len; i ++ ) rc4Key[i] ^= 0x64;
		
		// AES Decode
		len = rc4Get(core_key, ref rc4Key);
		rc4Key = rc4Key.Take(len).ToArray();
		
		// Info("读取Music Info 长度");
		fs.Read(buf, 0, 4);    // 读取Music Info 长度数据
		len = (int)BitConverter.ToUInt32(buf, 0);
		fs.Seek(22, SeekOrigin.Current);
		len -= 22;
		byte[] meta = new byte[len];
		fs.Read(meta, 0, len); // 读取Music Info数据

		Info("解析Music info信息");
		for (i = 0; i < len; i++) meta[i] ^= 0x63;
		
		string base64Str = Encoding.ASCII.GetString(meta);
		byte[] data = Convert.FromBase64String(base64Str);
		len = rc4Get(meta_key, ref data);
		
		string metaj = Encoding.UTF8.GetString(data);
		Console.WriteLine(metaj);
		
		Info(jsonGet(metaj, "artist", ',').Trim('[', '"'));
		Info(jsonGet(metaj, "musicName"));
		Info(jsonGet(metaj, "format"));

    // CRC Gap
		fs.Seek(9, SeekOrigin.Current);
		
		fs.Read(buf, 0, 4);    // 读取图片大小
		len = (int)BitConverter.ToUInt32(buf, 0);
		// byte[] img = new byte[len];
		// fs.Read(img, 0, len);  // 读取图片数据
		fs.Seek(len, SeekOrigin.Current);
		
		byte[] sBox = new byte[256];
		byte[] rc4Key17 = rc4Key.Skip(17).ToArray();
		rc4Init(sBox, rc4Key17, rc4Key17.Length);	//用rC4密钥进行初始化s盒
		// const int ReadBlockSize = 1024 * 1024 * 10; // 每次读取10MB
		const int ReadBlockSize = 1024 * 1024; // 每次读取1MB
		byte[] musicData = new byte[ReadBlockSize];
		long total = 0;
		
		string newfile = $"{jsonGet(metaj, "artist", ',').Trim('[', '"')} - {jsonGet(metaj, "musicName")}";
		File.WriteAllText($"{newfile}.txt", metaj);

		using (FileStream fo = new FileStream(newfile + $".{jsonGet(metaj, "format")}", FileMode.Create, FileAccess.Write))
		while( true ) {
			len = fs.Read(musicData, 0, ReadBlockSize);
			
			rc4PRGA(sBox, ref musicData, len);
			fo.Write(musicData, 0, len);
			
			total += len;
			if (len < ReadBlockSize) break;
		}
		Info($"{newfile} {total}");
	}
	
	string jsonGet(string json, string key, char suffix = '"') {
        int n = json.IndexOf($"\"{key}\":");
        if (n < 0) return string.Empty;
        n += key.Length + 4;
        int e = json.IndexOf(suffix, n);
        if (n < 0 || e < n) {
            return string.Empty;
        }
        // return json.[n..e];
		return json.Substring(n, e - n);
    }
	
	void Info(string msg) => Console.WriteLine(msg);
	
	int rc4Get(byte[] key, ref byte[] rc4Key){
		int len = rc4Key.Length;
		using (Aes aes = Aes.Create()) {
			aes.Key = key;
			aes.Mode = CipherMode.ECB;
			aes.Padding = PaddingMode.PKCS7;
			ICryptoTransform decryptor = aes.CreateDecryptor();
			//int packSize = len / 16;

			using (MemoryStream ms = new MemoryStream(rc4Key))
			using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {
				rc4Key = new byte[len];
				len = cs.Read(rc4Key, 0, len);
			}
			// rc4Key[len - pad] = 0; // 去除填充的部分，得到RC4密钥
		}
		return len;
	}
	
	void swap(ref byte a, ref byte b) {
		byte t = a;
		a = b;
		b = t;
	}

	//用key生成S盒
	/*
	* s: s盒
	* key: 密钥
	* len: 密钥长度
	*/
	void rc4Init(byte[] s, byte[] key, int len) {
		int i = 0, j = 0;
		byte[] T = new byte[256];

		for (i = 0; i < 256; i++) {
			s[i] = (byte)i;
			T[i] = key[i % len];
		}

		for (i = 0; i < 256; i++) {
			j = (j + s[i] + T[i]) % 256;
			swap(ref s[i], ref s[j]);
		}
	}

	//针对NCM文件的解密
	//异或关系
	/*
	* s: s盒
	* data: 要加密或者解密的数据
	* len: data的长度
	*/
	void rc4PRGA(byte[] s, ref byte[] data, int len) {
		int i = 0;
		int j = 0;
		int k = 0;
		int idx = 0;
		for (idx = 0; idx < len; idx++) {
			i = (idx + 1) % 256;
			j = (i + s[i]) % 256;
			k= (s[i] + s[j]) % 256;
			data[idx]^=s[k];  //异或
		}
	}
}
