package org.benben.modules.business.commen.service;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * @author: WangHao
 * @date: 2019/4/23 13:55
 * @description: 微博业务层
*/
public interface IWbService {

    public void login(HttpServletResponse response, HttpServletRequest request);

    public Map callBack(HttpServletRequest request);
}