package security;

import java.security.MessageDigest;

/**
 * HASH值工具类
 */
public class HashUtils {
	
	public static String  ALGORITHM_MD5= "MD5";
	
	public static String  ALGORITHM_SHA1= "SHA-1";
	
	public static String  ALGORITHM_SHA256= "SHA-256";
	
	
	/**
	 * 将源数据通过hash算法生成散列值
	 * @param source
	 * @return
	 */
	public static String convertStringByAlgorithm(String source, String algorithm)
	{
		try {
			MessageDigest msgDigest = MessageDigest.getInstance(algorithm);
			msgDigest.update(source.getBytes("UTF-8"));
			byte[] bytes = msgDigest.digest();
			return byteToHexString(bytes);
		}  catch(Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 将源数据通过hash算法生成散列值;默认MD5
	 * @param source
	 * @return
	 */
	public static String toStringByMd5(String source)
	{
		return convertStringByAlgorithm(source, HashUtils.ALGORITHM_MD5);
	}
	
	/**
	 * 将源数据通过hash算法生成散列值;默认MD5
	 * 不可以从消息摘要中复原信息；两个不同的消息不会产生同样的消息摘要,(但会有1x10 ^ 48分之一的机率出现相同的消息摘要,一般使用时忽略)。
	 * @param source
	 * @return
	 */
	public static String toStringBySha1(String source)
	{
		return convertStringByAlgorithm(source, HashUtils.ALGORITHM_SHA1);
	}
	
	/**
	 * 将bytes值转成双字节
	 * @param source
	 * @return
	 */
	private static String byteToHexString(byte[] source)
	{
		char hexDigits[] = "0123456789abcdef".toCharArray();
		char str[] = new char[source.length * 2];
		int k = 0;
		for (int i = 0; i < source.length; i++) {
			byte b = source[i];
			// 将没个数(int)b进行双字节加密
			str[k++] = hexDigits[b >> 4 & 0xf];
			str[k++] = hexDigits[b & 0xf];
		}
		return new String(str);
	}
	
}
