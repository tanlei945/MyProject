package org.benben.common.util;


import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.methods.PostMethod;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;

public class WeatherUtil {
	/**
	 * 天气查询
	 * @param dq
	 * @return
	 */
	public static String weather(String dq) {
		String res = null;
        HttpClient httpclient = null;
        PostMethod postMethod = null;
		HashMap<String, Object> req = new HashMap<>();
		//执行查询
		try {
			String url = "http://api.k780.com:88/?app=weather.today&weaid=" + URLEncoder.encode(dq,"UTF-8") + "&%E6%B2%B3%E5%8D%97&&appkey=10003&sign=b59bc3ef6191eb9f747dd4e83c99f2a4&format=json";
		    //创建连接
		    httpclient = new HttpClient();
		    postMethod = new PostMethod(url);
            httpclient.executeMethod(postMethod);
            //返回信息
            res = new String(postMethod.getResponseBody(), "UTF-8");
			res=res.split("weather\":\"")[1].split("\",\"")[0];
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			//关闭连接,释放资源
			postMethod.releaseConnection();
			((SimpleHttpConnectionManager) httpclient.getHttpConnectionManager()).shutdown();
		}
		return res;
	}

    public static String temperature(String cityid) {
        HttpClient httpclient = null;
        PostMethod postMethod = null;
		String res = null;
		HashMap<String, Object> req = new HashMap<>();
        //执行查询
		try {
			String url = "http://api.k780.com:88/?app=weather.today&weaid=" + URLEncoder.encode(cityid,"UTF-8") + "&%E6%B2%B3%E5%8D%97&&appkey=10003&sign=b59bc3ef6191eb9f747dd4e83c99f2a4&format=json";
            httpclient = new HttpClient();
            postMethod = new PostMethod(url);
            httpclient.executeMethod(postMethod);
            //返回信息
            res = new String(postMethod.getResponseBody(), "UTF-8");
			res=res.split("temperature_curr\":\"")[1].split("\",\"")[0];
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			//关闭连接,释放资源
			postMethod.releaseConnection();
			((SimpleHttpConnectionManager) httpclient.getHttpConnectionManager()).shutdown();
		}
		return res;
    }


	public static void main(String[] args) {
		System.err.println(weather("商丘"));
		System.err.println(temperature("商丘"));
	}
}