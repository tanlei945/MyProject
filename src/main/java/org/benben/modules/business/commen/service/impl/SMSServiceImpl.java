package org.benben.modules.business.commen.service.impl;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.lang.StringUtils;
import org.benben.common.menu.SMSEnum;
import org.benben.common.util.RedisUtil;
import org.benben.modules.business.commen.service.ISMSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * @author: WangHao
 * @date: 2019/4/10 10:00
 * @description: 短信业务层
 */
@Service
public class SMSServiceImpl implements ISMSService {

    @Value("${sms-configure.host}")
    private String host;
    @Value("${sms-configure.appcode}")
    private String appcode;

    @Autowired
    private RedisUtil redisUtil;

    /**
     * 短信发送
     *
     * @param mobile 手机号码
     * @param event  事件
     * @return
     */
    @Override
    public String send(String mobile, String event) {

        HttpClient httpclient = null;
        PostMethod postMethod = null;

        String returncode = "";

        Integer code = (int) ((Math.random() * 9 + 1) * 100000);

        try {
            //创建连接
            httpclient = new HttpClient();
            postMethod = new PostMethod(host);
            //设置编码方式
            postMethod.getParams().setParameter(HttpMethodParams.HTTP_CONTENT_CHARSET, "UTF-8");
            postMethod.setRequestHeader("Authorization", "APPCODE " + appcode);
            //添加参数
            postMethod.addParameter("phone", mobile);
            postMethod.addParameter("variable", "num:" + code + ",money:888");
            postMethod.addParameter("templateId", "TP1711063");
            //执行请求
            httpclient.executeMethod(postMethod);
            //返回信息
            String result = new String(postMethod.getResponseBody(), "UTF-8");
            System.out.println("短信返回code" + result);
            if (StringUtils.isNotBlank(result)) {
                JSONObject object = JSONObject.parseObject(result);
                returncode = object.getString("return_code");
            }


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            //关闭连接,释放资源
            postMethod.releaseConnection();
            ((SimpleHttpConnectionManager) httpclient.getHttpConnectionManager()).shutdown();
        }

        if (StringUtils.equals(returncode, SMSEnum.SEND_SUCCESS.getCode())) {
            //存入redis
            redisUtil.set(mobile + "," + event, String.valueOf(code), 300);
        }
        System.out.println("验证码:" + code);

        return returncode;
    }

    /**
     * 短信验证
     *
     * @param mobile  手机号码
     * @param event   事件
     * @param captcha 验证码
     * @return
     */
    @Override
    public int check(String mobile, String event, String captcha) {

        int num = 0;
        //检测redis是否过期
        if (!redisUtil.hasKey(mobile + "," + event)) {
            return num = 1;
        }

        String result = (String) redisUtil.get(mobile + "," + event);
        //取redis中缓存数据
        if (!StringUtils.equals(result, captcha) || result == null) {
            return num = 2;
        }
        //验证成功,删除redis缓存数据
        redisUtil.del(mobile + "," + event);

        return num;
    }
}
