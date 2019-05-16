package org.benben.modules.business.commen.service.impl;

import com.qq.connect.QQConnectException;
import com.qq.connect.api.OpenID;
import com.qq.connect.javabeans.AccessToken;
import com.qq.connect.oauth.Oauth;
import org.benben.modules.business.commen.service.IQqService;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service
public class IQqServiceImpl implements IQqService {

    @Override
    public void login(String mobile, HttpServletResponse response) {

        try {
            //生成授权连接
            response.setContentType("text/html;charset=utf-8");
            response.sendRedirect((new Oauth().getAuthorizeURL(mobile)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public String callBack(HttpServletRequest request) {

        String result = "";

        String mobile = request.getParameter("state");

        try {
            String queryString = ((HttpServletRequest) request).getQueryString();
            System.out.println("queryString"+queryString);
            AccessToken accessTokenObj = (new Oauth()).getAccessTokenByQueryString(queryString,mobile);
            System.out.println("发送post 请求到服务器 获取OpenID---------------result:"+accessTokenObj.toString());
            if (accessTokenObj.getAccessToken().equals("")) {
                System.out.println("没有获取到响应参数");
                return result;
            }
            //得到token
            String accessToken = accessTokenObj.getAccessToken();
//            request.getSession().setAttribute("demo_access_token", accessToken);
            // 利用获取到的accessToken 去获取当前用的openid
            OpenID openIDObj = new OpenID(accessToken);
            System.out.println("发送post 请求到服务器 获取OpenID---------------result:"+openIDObj.toString());
            String openID = openIDObj.getUserOpenID();
            result = openID;

        } catch (QQConnectException e) {
            e.printStackTrace();
            System.out.println("QQ登录失败，原因：" + e.getMessage());
        }

        return result;
    }

    //    @Override
//    public String beforeCallBack(HttpServletRequest request) {
//
//        String result = "";
//
//        String state = request.getParameter("state");
//
//        try {
//            String queryString = ((HttpServletRequest) request).getQueryString();
//            System.out.println("queryString"+queryString);
//            AccessToken accessTokenObj = (new Oauth()).getAccessTokenByQueryString(queryString,state);
//            System.out.println("发送post 请求到服务器 获取OpenID---------------result:"+accessTokenObj.toString());
//            if (accessTokenObj.getAccessToken().equals("")) {
//                System.out.println("没有获取到响应参数");
//                return result;
//            }
//            //得到token
//            String accessToken = accessTokenObj.getAccessToken();
////            request.getSession().setAttribute("demo_access_token", accessToken);
//            // 利用获取到的accessToken 去获取当前用的openid
//            OpenID openIDObj = new OpenID(accessToken);
//            System.out.println("发送post 请求到服务器 获取OpenID---------------result:"+openIDObj.toString());
//            String openID = openIDObj.getUserOpenID();
//            result = openID;
//
//        } catch (QQConnectException e) {
//            e.printStackTrace();
//            System.out.println("QQ登录失败，原因：" + e.getMessage());
//        }
//
//        return result;
//    }

}
