package org.benben.modules.business.commen.service;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * @author: WangHao
 * @date: 2019/4/11 13:55
 * @description: 微信业务层
*/
public interface IWxService {

    public void wxLogin(HttpServletResponse response, HttpServletRequest request);

    public Map callBack(HttpServletRequest request);
}