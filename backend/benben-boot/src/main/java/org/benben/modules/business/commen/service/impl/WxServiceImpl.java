package org.benben.modules.business.commen.service.impl;

import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.benben.common.util.wechat.WeChatUtil;
import org.benben.modules.business.commen.service.IWxService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

/**
 * @author: WangHao
 * @date: 2019/4/11 11:30
 * @description: 微信业务层实现
 */
@Slf4j
@Service
public class WxServiceImpl implements IWxService {

    @Value("${wecat.appId}")
    private String appId;
    @Value("${wecat.appSecret}")
    private String appSecret;
    @Value("${wecat.token}")
    private String token;
    @Value("${wecat.backUrl}")
    private String backUrl;

    @Override
    public void wxLogin(String mobile, HttpServletResponse response) {
        String url = "";

        // 第一步：用户同意授权，获取code
        try {
            url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=" + appId
                    + "&redirect_uri=" + URLEncoder.encode(backUrl, "UTF-8")
                    + "&response_type=code"
                    + "&scope=snsapi_userinfo"
                    + "&state=" + mobile + "#wechat_redirect";
            log.debug("forward重定向地址{" + url + "}");
            response.sendRedirect(url);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public String callBack(HttpServletRequest request) {

        String result = "";
             /*
         * start 获取微信用户基本信息
         */
        String code = request.getParameter("code");
        String mobile = request.getParameter("state");
        //第二步：通过code换取网页授权access_token
        String url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" + appId
                + "&secret=" + appSecret
                + "&code=" + code
                + "&grant_type=authorization_code";

        System.out.println("url:" + url);
        JSONObject jsonObject = WeChatUtil.doGetJson(url);
             /*
         { "access_token":"ACCESS_TOKEN",
            "expires_in":7200,
            "refresh_token":"REFRESH_TOKEN",
            "openid":"OPENID",
            "scope":"SCOPE" 
           }
         */
        String openid = jsonObject.getString("openid");
        String access_token = jsonObject.getString("access_token");
        String refresh_token = jsonObject.getString("refresh_token");
        //第五步验证access_token是否失效；展示都不需要
        String chickUrl = "https://api.weixin.qq.com/sns/auth?access_token=" + access_token + "&openid=" + openid;

        JSONObject chickuserInfo = WeChatUtil.doGetJson(chickUrl);
        System.out.println(chickuserInfo.toString());
        if (!"0".equals(chickuserInfo.getString("errcode"))) {
            // 第三步：刷新access_token（如果需要）-----暂时没有使用,参考文档https://mp.weixin.qq.com/wiki，
            String refreshTokenUrl = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=" + openid + "&grant_type=refresh_token&refresh_token=" + refresh_token;

            JSONObject refreshInfo = WeChatUtil.doGetJson(chickUrl);
                   /*
             * { "access_token":"ACCESS_TOKEN",
                "expires_in":7200,
                "refresh_token":"REFRESH_TOKEN",
                "openid":"OPENID",
                "scope":"SCOPE" }
             */
            System.out.println(refreshInfo.toString());
            access_token = refreshInfo.getString("access_token");
        }

        // 第四步：拉取用户信息(需scope为 snsapi_userinfo)
        String infoUrl = "https://api.weixin.qq.com/sns/userinfo?access_token=" + access_token
                + "&openid=" + openid
                + "&lang=zh_CN";
        System.out.println("infoUrl:" + infoUrl);
        JSONObject userInfo = WeChatUtil.doGetJson(infoUrl);
            /*
         {  "openid":" OPENID",
            "nickname": NICKNAME,
            "sex":"1",
            "province":"PROVINCE"
            "city":"CITY",
            "country":"COUNTRY",
            "headimgurl":    "http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/46",
            "privilege":[ "PRIVILEGE1" "PRIVILEGE2"     ],
            "unionid": "o6_bmasdasdsad6_2sgVt7hMZOPfL"
            }
         */
        System.out.println("JSON-----" + userInfo.toString());
        System.out.println("名字-----" + userInfo.getString("nickname"));
        System.out.println("头像-----" + userInfo.getString("headimgurl"));
             /*
         * end 获取微信用户基本信息
         */
        //获取到用户信息后就可以进行重定向，走自己的业务逻辑了。。。。。。
        //接来的逻辑就是你系统逻辑了，请自由发挥
        result = userInfo.getString("openid");

        return result;
    }

    //    @Override
//    public String callBack(String code) {
//
//        String result = "";
//             /*
//         * start 获取微信用户基本信息
//         */
//
//        //第二步：通过code换取网页授权access_token
//        String url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" + appId
//                + "&secret=" + appSecret
//                + "&code=" + code
//                + "&grant_type=authorization_code";
//
//        System.out.println("url:" + url);
//        JSONObject jsonObject = WeChatUtil.doGetJson(url);
//             /*
//         { "access_token":"ACCESS_TOKEN",
//            "expires_in":7200,
//            "refresh_token":"REFRESH_TOKEN",
//            "openid":"OPENID",
//            "scope":"SCOPE" 
//           }
//         */
//        String openid = jsonObject.getString("openid");
//        String access_token = jsonObject.getString("access_token");
//        String refresh_token = jsonObject.getString("refresh_token");
//        //第五步验证access_token是否失效；展示都不需要
//        String chickUrl = "https://api.weixin.qq.com/sns/auth?access_token=" + access_token + "&openid=" + openid;
//
//        JSONObject chickuserInfo = WeChatUtil.doGetJson(chickUrl);
//        System.out.println(chickuserInfo.toString());
//        if (!"0".equals(chickuserInfo.getString("errcode"))) {
//            // 第三步：刷新access_token（如果需要）-----暂时没有使用,参考文档https://mp.weixin.qq.com/wiki，
//            String refreshTokenUrl = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=" + openid + "&grant_type=refresh_token&refresh_token=" + refresh_token;
//
//            JSONObject refreshInfo = WeChatUtil.doGetJson(chickUrl);
//                   /*
//             * { "access_token":"ACCESS_TOKEN",
//                "expires_in":7200,
//                "refresh_token":"REFRESH_TOKEN",
//                "openid":"OPENID",
//                "scope":"SCOPE" }
//             */
//            System.out.println(refreshInfo.toString());
//            access_token = refreshInfo.getString("access_token");
//        }
//
//        // 第四步：拉取用户信息(需scope为 snsapi_userinfo)
//        String infoUrl = "https://api.weixin.qq.com/sns/userinfo?access_token=" + access_token
//                + "&openid=" + openid
//                + "&lang=zh_CN";
//        System.out.println("infoUrl:" + infoUrl);
//        JSONObject userInfo = WeChatUtil.doGetJson(infoUrl);
//            /*
//         {  "openid":" OPENID",
//            "nickname": NICKNAME,
//            "sex":"1",
//            "province":"PROVINCE"
//            "city":"CITY",
//            "country":"COUNTRY",
//            "headimgurl":    "http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/46",
//            "privilege":[ "PRIVILEGE1" "PRIVILEGE2"     ],
//            "unionid": "o6_bmasdasdsad6_2sgVt7hMZOPfL"
//            }
//         */
//        System.out.println("JSON-----" + userInfo.toString());
//        System.out.println("名字-----" + userInfo.getString("nickname"));
//        System.out.println("头像-----" + userInfo.getString("headimgurl"));
//             /*
//         * end 获取微信用户基本信息
//         */
//        //获取到用户信息后就可以进行重定向，走自己的业务逻辑了。。。。。。
//        //接来的逻辑就是你系统逻辑了，请自由发挥
//        result = userInfo.getString("openid");
//
//        return result;
//    }
}
