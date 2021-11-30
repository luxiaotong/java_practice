// edit jre\lib\security\java.security
// add security.provider.10=org.bouncycastle.jce.provider.BouncyCastleProvider
// copy bc*.jar to jre\lib\ext

// docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp davidcaste/alpine-java-unlimited-jce:jdk javac Main.java
// docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp davidcaste/alpine-java-unlimited-jce:jdk java Main


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Security;

public class Main {
    public static final String KEY_ALGORITHM = "AES";
	public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
	public static final Integer KEY_LENGTH = 256;
	
    public static void main(String[] args) {
        String auth_token = null;
		try {
			Long t = System.currentTimeMillis();
			auth_token = encrypt("20211117001:31c241309a9231f585bca20c9873b49a:"+t, "31c241309a9231f585bca20c9873b49a");
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
        System.out.println(auth_token);
        // e.printStackTrace();
    }

    public static String encrypt(String info, String secret) throws Exception{
        byte[] data = info.getBytes();

        byte[] key = HexUtil.hexStr2ByteArray(secret);
        Key k = toKey(key);
        
		Security.addProvider(new BouncyCastleProvider());
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
		cipher.init(Cipher.ENCRYPT_MODE, k);
		byte[] encrypt = cipher.doFinal(data);
		return HexUtil.byteArray2HexStr(encrypt);
    }

    public static Key toKey(byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
		return secretKey;
	}
}