package org.benben.common.util.wechat;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;

/**
 * @author: WangHao
 * @date: 2019/4/11 09:15
 * @description: 微信网络请求工具类
 */
public class WeChatUtil {

    public static JSONObject doGetJson(String url) {

        HttpClient httpclient = null;
        GetMethod getMethod = null;
        JSONObject jsonObject = null;

        //执行请求
        try {
            //创建连接
            httpclient = new HttpClient();
            getMethod = new GetMethod(url);
            httpclient.executeMethod(getMethod);
            //返回信息
            String result = new String(getMethod.getResponseBody(), "UTF-8");
            System.out.println("返回微信" + result);
            if (StringUtils.isNotBlank(result)) {
                jsonObject = JSONObject.parseObject(result);
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            //关闭连接,释放资源
            getMethod.releaseConnection();
            ((SimpleHttpConnectionManager) httpclient.getHttpConnectionManager()).shutdown();
        }

        return jsonObject;
    }


}
