package org.benben.modules.business.commen.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.benben.modules.business.commen.service.IWbService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class WbServiceImpl implements IWbService {

    @Value("${weibo.appId}")
    private String appKey;
    @Value("${weibo.appSecret}")
    private String appSecret;
    @Value("${weibo.backUrl}")
    private String backUrl;

    /**
     * 微博登录
     * @param response
     */
    @Override
    public void login(String mobile, HttpServletResponse response) {

        String url = "";

        // 第一步：用户同意授权，获取code
        try {
            url = "https://api.weibo.com/oauth2/authorize?client_id="
                    + appKey
                    + "&redirect_uri="
                    + URLEncoder.encode(backUrl, "UTF-8")
                    + "&response_type=code"+ "&state=" + mobile;

            log.debug("forward重定向地址{" + backUrl + "}");
            response.sendRedirect(url);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * 微博回调
     * @param request
     * @return
     */
    @Override
    public String callBack(HttpServletRequest request) {

        HttpClient httpclient = null;
        PostMethod postMethod = null;
        GetMethod getMethod = null;
        String result = "";
        String reply = "";
        Map<String, Object> resp;

        String code = request.getParameter("code");
        String mobile = request.getParameter("state");

        try {
            String url = "https://api.weibo.com/oauth2/access_token";

            //创建连接
            httpclient = new HttpClient();
            postMethod = new PostMethod(url);
            postMethod.addParameter("client_id",appKey);
            postMethod.addParameter("client_secret",appSecret);
            postMethod.addParameter("grant_type","authorization_code");
            postMethod.addParameter("redirect_uri",backUrl);
            postMethod.addParameter("code",code);
            //第二步：通过code换取网页授权access_token
            httpclient.executeMethod(postMethod);

            //返回信息
            result = new String(postMethod.getResponseBody(), "UTF-8");
            resp = JSONObject.parseObject(result, new TypeReference<Map<String, Object>>(){});
            System.out.println("发送post 请求到服务器 获取access_token---------------result:"+result);
            System.out.println("发送post 请求到服务器 获取access_token---------------result:"+resp);
            /*{
                   "access_token": "ACCESS_TOKEN",
                   "expires_in": 1234,
                   "remind_in":"798114",
                   "uid":"12341234"
             }*/
            String accessToken = (String) resp.get("access_token");
            String uid = (String)resp.get("uid");// 这个uid就是微博用户的唯一用户ID，可以通过这个id直接访问到用户微博主页
            // 第三步：拉取用户信息
            httpclient = new HttpClient();
            getMethod = new GetMethod("https://api.weibo.com/2/users/show.json?access_token=" + accessToken + "&uid="+ uid);
            httpclient.executeMethod(getMethod);
            //返回信息
            result = new String(getMethod.getResponseBody(), "UTF-8");
            resp = JSONObject.parseObject(result, new TypeReference<Map<String, Object>>(){});
            reply = uid;
            System.out.println("发送get 请求到服务器 获取用户信息---------------result:"+resp);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            //关闭连接,释放资源
            postMethod.releaseConnection();
            ((SimpleHttpConnectionManager) httpclient.getHttpConnectionManager()).shutdown();
        }

        return reply;
    }

    //    /**
//     * 前端微博回调
//     * @param code
//     * @return
//     */
//    @Override
//    public String callBack(String code) {
//
//        HttpClient httpclient = null;
//        PostMethod postMethod = null;
//        GetMethod getMethod = null;
//        String result = "";
//        String reply = "";
//        Map<String, Object> resp;
//
//        try {
//            String url = "https://api.weibo.com/oauth2/access_token";
//
//            //创建连接
//            httpclient = new HttpClient();
//            postMethod = new PostMethod(url);
//            postMethod.addParameter("client_id",appKey);
//            postMethod.addParameter("client_secret",appSecret);
//            postMethod.addParameter("grant_type","authorization_code");
//            postMethod.addParameter("redirect_uri",backUrl);
//            postMethod.addParameter("code",code);
//            //第二步：通过code换取网页授权access_token
//            httpclient.executeMethod(postMethod);
//
//            //返回信息
//            result = new String(postMethod.getResponseBody(), "UTF-8");
//            resp = JSONObject.parseObject(result, new TypeReference<Map<String, Object>>(){});
//            System.out.println("发送post 请求到服务器 获取access_token---------------result:"+result);
//            System.out.println("发送post 请求到服务器 获取access_token---------------result:"+resp);
//            /*{
//                   "access_token": "ACCESS_TOKEN",
//                   "expires_in": 1234,
//                   "remind_in":"798114",
//                   "uid":"12341234"
//             }*/
//            String accessToken = (String) resp.get("access_token");
//            String uid = (String)resp.get("uid");// 这个uid就是微博用户的唯一用户ID，可以通过这个id直接访问到用户微博主页
//            // 第三步：拉取用户信息
//            httpclient = new HttpClient();
//            getMethod = new GetMethod("https://api.weibo.com/2/users/show.json?access_token=" + accessToken + "&uid="+ uid);
//            httpclient.executeMethod(getMethod);
//            //返回信息
//            result = new String(getMethod.getResponseBody(), "UTF-8");
//            resp = JSONObject.parseObject(result, new TypeReference<Map<String, Object>>(){});
//            reply = uid;
//            System.out.println("发送get 请求到服务器 获取用户信息---------------result:"+resp);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        } finally {
//            //关闭连接,释放资源
//            postMethod.releaseConnection();
//            ((SimpleHttpConnectionManager) httpclient.getHttpConnectionManager()).shutdown();
//        }
//
//        return reply;
//    }
}
