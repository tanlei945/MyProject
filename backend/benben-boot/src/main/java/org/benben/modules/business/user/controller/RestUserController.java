package org.benben.modules.business.user.controller;

import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.qq.connect.QQConnectException;
import com.qq.connect.api.OpenID;
import com.qq.connect.javabeans.AccessToken;
import com.qq.connect.oauth.Oauth;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.api.vo.Result;
import org.benben.common.constant.CommonConstant;
import org.benben.common.menu.ResultEnum;
import org.benben.common.system.api.ISysBaseAPI;
import org.benben.common.util.PasswordUtil;
import org.benben.common.util.RedisUtil;
import org.benben.common.util.oConvertUtils;
import org.benben.modules.business.commen.dto.SmsDTO;
import org.benben.modules.business.commen.service.ISMSService;
import org.benben.modules.business.commen.service.IWxService;
import org.benben.modules.business.user.entity.User;
import org.benben.modules.business.user.service.IUserService;
import org.benben.modules.shiro.authc.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

/**
 * @Title: Controller
 * @Description: 普通用户
 * @author： jeecg-boot
 * @date： 2019-04-19
 * @version： V1.0
 */
@RestController
@RequestMapping("/api/user")
@Slf4j
@Api(tags = "会员接口")
public class RestUserController {
    @Autowired
    private IUserService userService;

    @Autowired
    private ISysBaseAPI sysBaseAPI;

    @Autowired
    private ISMSService ismsService;

    @Autowired
    private IWxService iWxService;

    @Autowired
    private RedisUtil redisUtil;


    @PostMapping(value = "/login")
    @ApiOperation(value = "会员登录接口", tags = "会员接口", notes = "会员登录接口")
    public RestResponseBean login(@RequestParam("username") String username, @RequestParam("password") String password) {

        JSONObject obj = new JSONObject();
        User user = userService.getByUsername(username);

        if (user == null) {
            sysBaseAPI.addLog("登录失败，用户名:" + username + "不存在！", CommonConstant.LOG_TYPE_1, null);
            return new RestResponseBean(ResultEnum.USER_NOT_EXIST.getValue(), ResultEnum.USER_NOT_EXIST.getDesc(), null);
        } else {
            //密码验证
            String userpassword = PasswordUtil.encrypt(username, password, user.getSalt());
            String syspassword = user.getPassword();
            if (!syspassword.equals(userpassword)) {
                return new RestResponseBean(ResultEnum.USER_PWD_ERROR.getValue(), ResultEnum.USER_PWD_ERROR.getDesc(), null);
            }
            //调用公共方法
            obj = tokenBuild(user);
        }

        return new RestResponseBean(ResultEnum.LOGIN_SUCCESS.getValue(), ResultEnum.LOGIN_SUCCESS.getDesc(), obj);
    }


    /**
     * 分页列表查询
     *
     * @param user
     * @param pageNo
     * @param pageSize
     * @param req
     * @return
     */

    @GetMapping(value = "/list")
    @ApiOperation(value = "会员列表", tags = "会员接口", notes = "会员列表")
    public Result<IPage<User>> queryPageList(User user,
                                             @RequestParam(name = "pageNo", defaultValue = "1") Integer pageNo,
                                             @RequestParam(name = "pageSize", defaultValue = "10") Integer pageSize,
                                             HttpServletRequest req) {
        Result<IPage<User>> result = new Result<IPage<User>>();
        QueryWrapper<User> queryWrapper = new QueryWrapper<User>(user);
        Page<User> page = new Page<User>(pageNo, pageSize);
        //排序逻辑 处理
        String column = req.getParameter("column");
        String order = req.getParameter("order");
        if (oConvertUtils.isNotEmpty(column) && oConvertUtils.isNotEmpty(order)) {
            if ("asc".equals(order)) {
                queryWrapper.orderByAsc(oConvertUtils.camelToUnderline(column));
            } else {
                queryWrapper.orderByDesc(oConvertUtils.camelToUnderline(column));
            }
        }
        IPage<User> pageList = userService.page(page, queryWrapper);
        //log.debug("查询当前页："+pageList.getCurrent());
        //log.debug("查询当前页数量："+pageList.getSize());
        //log.debug("查询结果数量："+pageList.getRecords().size());
        //log.debug("数据总数："+pageList.getTotal());
        result.setSuccess(true);
        result.setResult(pageList);
        return result;
    }

    /**
     * 添加
     *
     * @param user
     * @return
     */
    @PostMapping(value = "/add")
    @ApiOperation(value = "会员添加", tags = "会员接口", notes = "会员添加")
    public Result<User> add(@RequestBody User user) {
        Result<User> result = new Result<User>();

        try {
            user.setCreateTime(new Date());//设置创建时间
            String salt = oConvertUtils.randomGen(8);
            user.setSalt(salt);
            String passwordEncode = PasswordUtil.encrypt(user.getUsername(), user.getPassword(), salt);
            user.setPassword(passwordEncode);
            userService.save(user);
            result.success("添加成功！");
        } catch (Exception e) {
            e.printStackTrace();
            log.info(e.getMessage());
            result.error500("操作失败");
        }

        return result;
    }

    /**
     * 编辑
     *
     * @param user
     * @return
     */
    @PostMapping(value = "/edit")
    @ApiOperation(value = "会员编辑", tags = "会员接口", notes = "会员编辑")
    public Result<User> eidt(@RequestBody User user) {
        Result<User> result = new Result<User>();

        User userEntity = userService.getById(user.getId());
        if (userEntity == null) {
            result.error500("未找到对应实体");
        } else {
            boolean ok = userService.updateById(user);
            //TODO 返回false说明什么？
            if (ok) {
                result.success("修改成功!");
            }
        }

        return result;
    }

    /**
     * 通过id删除
     *
     * @param id
     * @return
     */
    @PostMapping(value = "/delete")
    @ApiOperation(value = "会员删除", tags = "会员接口", notes = "会员删除")
    public Result<User> delete(@RequestParam(name = "id", required = true) String id) {
        Result<User> result = new Result<User>();
        User user = userService.getById(id);

        if (user == null) {
            result.error500("未找到对应实体");
        } else {
            boolean ok = userService.removeById(id);
            if (ok) {
                result.success("删除成功!");
            }
        }

        return result;
    }

    /**
     * 批量删除
     *
     * @param ids
     * @return
     */
    @PostMapping(value = "/deleteBatch")
    @ApiOperation(value = "批量删除", tags = "会员接口", notes = "批量删除")
    public Result<User> deleteBatch(@RequestParam(name = "ids", required = true) String ids) {
        Result<User> result = new Result<User>();

        if (ids == null || "".equals(ids.trim())) {
            result.error500("参数不识别！");
        } else {
            this.userService.removeByIds(Arrays.asList(ids.split(",")));
            result.success("删除成功!");
        }
        return result;
    }

    /**
     * 通过id查询
     *
     * @param id
     * @return
     */
    @GetMapping(value = "/queryById")
    @ApiOperation(value = "通过id查询会员", tags = "会员接口", notes = "通过id查询会员")
    public Result<User> queryById(@RequestParam(name = "id", required = true) String id) {
        Result<User> result = new Result<User>();

        User user = userService.getById(id);
        if (user == null) {
            result.error500("未找到对应实体");
        } else {
            result.setResult(user);
            result.setSuccess(true);
        }
        return result;
    }

    /**
     * 会员注册
     *
     * @param user
     * @return
     */
    @PostMapping(value = "/register")
    @ApiOperation(value = "会员注册", tags = "会员接口", notes = "会员注册")
    public RestResponseBean register(User user) {
        RestResponseBean RestResponseBean = new RestResponseBean();

        try {

            String salt = oConvertUtils.randomGen(8);
            user.setSalt(salt);
            String passwordEncode = PasswordUtil.encrypt(user.getUsername(), user.getPassword(), salt);
            user.setPassword(passwordEncode);
            userService.save(user);
            QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
            userQueryWrapper.eq("username", user.getUsername());
            User one = userService.getOne(userQueryWrapper);
            RestResponseBean.setData(one);


        } catch (Exception e) {
            e.printStackTrace();
            log.info(e.getMessage());
            RestResponseBean.setMsg(ResultEnum.ERROR.getDesc());
        }

        return RestResponseBean;
    }

    /**
     * 会员修改
     *
     * @param user
     * @return
     */
    @PostMapping(value = "/profile")
    @ApiOperation(value = "会员修改", tags = "会员接口", notes = "会员修改")
    public RestResponseBean profile(User user) {
        RestResponseBean RestResponseBean = new RestResponseBean();

        User userEntity = (User) SecurityUtils.getSubject().getPrincipal();
        if (user.getAvatar() != null || user.getAvatar() != "")
            userEntity.setAvatar(user.getAvatar());
        if (user.getUsername() != null || user.getUsername() != "")
            userEntity.setUsername(user.getUsername());
        if (user.getNickname() != null || user.getNickname() != "")
            userEntity.setNickname(user.getNickname());
        if (user.getBio() != null || user.getBio() != "")
            userEntity.setBio(user.getBio());

        boolean b = userService.updateById(userEntity);

        if (b)
            RestResponseBean.setMsg(ResultEnum.OPERATION_SUCCESS.getDesc());
        return RestResponseBean;
    }

    /**
     * 根据姓名查找
     *
     * @param username
     * @return
     */
    @GetMapping(value = "/queryByName")
    @ApiOperation(value = "根据姓名查找", tags = "会员接口", notes = "根据姓名查找")
    public User queryByName(@RequestParam String username) {
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        userQueryWrapper.eq("username", username);
        User user = userService.getOne(userQueryWrapper);
        return user;
    }

    /**
     * 修改邮箱
     *
     * @param email
     * @param captcha
     * @return
     */
    @PostMapping(value = "/changeEmail")
    @ApiOperation(value = "修改邮箱", tags = "会员接口", notes = "修改邮箱")
    public Result<User> changeEmail(@RequestParam String email, @RequestParam String captcha) {
        Result<User> result = new Result<User>();
        RestResponseBean RestResponseBean = new RestResponseBean();

        if (!"yanzheng".equals(captcha)) {
            result.error500("验证码错误");
            return result;
        }
        if (email == null || email == "") {
            result.error500("邮箱不允许为空");
            return result;
        }
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        user.setEmail(email);
        boolean b = userService.updateById(user);
        if (b)
            result.success("修改成功");
        return result;


    }

    /**
     * 修改手机号
     *
     * @param mobile
     * @param captcha
     * @return
     */
    @PostMapping(value = "/changeMobile")
    @ApiOperation(value = "修改手机号", tags = "会员接口", notes = "修改手机号")
    public Result<User> changeMobile(@RequestParam String mobile, @RequestParam String captcha) {
        Result<User> result = new Result<User>();

        if (mobile == null || mobile == "") {
            result.error500("手机号不允许为空");
            return result;
        }
        if (!"yanzheng".equals(captcha)) {
            result.error500("验证码错误");
            return result;
        }
        //得到登录会员
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        user.setMobile(mobile);
        boolean b = userService.updateById(user);
        if (b)
            result.success("修改成功");
        return result;
    }

    /**
     * 修改密码
     *
     * @param mobile
     * @param captcha
     * @param newpassword
     * @return
     */
    @PostMapping(value = "/changeResetpwd")
    @ApiOperation(value = "修改密码", tags = "会员接口", notes = "修改密码")
    public Result<User> changeResetpwd(@RequestParam String mobile, @RequestParam String captcha, @RequestParam String newpassword) {
        Result<User> result = new Result<User>();

        if (mobile == null || mobile == "") {
            result.error500("手机号不允许为空");
            return result;
        }
        if (captcha == null || captcha == "") {
            result.error500("验证码不允许为空");
            return result;
        }
        if (!"yanzheng".equals(captcha)) {
            result.error500("验证码错误");
            return result;
        }

        if (newpassword == null || newpassword == "") {
            result.error500("新密码不允许为空");
            return result;
        }

        User user = (User) SecurityUtils.getSubject().getPrincipal();
        //随机得到盐
        String salt = oConvertUtils.randomGen(8);
        user.setSalt(salt);
        String passwordEncode = PasswordUtil.encrypt(user.getUsername(), newpassword, salt);
        user.setPassword(passwordEncode);
        boolean b = userService.updateById(user);

        if (b)
            result.success("修改成功");

        return result;
    }

    /**
     * 退出
     *
     * @return
     */
    @GetMapping("/logOut")
    @ApiOperation(value = "退出", tags = "会员接口", notes = "退出")
    public Result<User> logOut() {
        Result<User> result = new Result<User>();
        User user = (User) SecurityUtils.getSubject().getPrincipal();
        String token = JwtUtil.sign(CommonConstant.SIGN_MEMBER_USER + user.getUsername(), user.getPassword());
        redisUtil.del(CommonConstant.SIGN_MEMBER_USER + token);
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        result.success("安全登出");
        return result;
    }

    @GetMapping("/logincheck")
    public String loginUrl(HttpServletRequest request) {
        //获取当前sesion
        HttpSession sessoin = request.getSession();
        //随机产生字符串
        String state = RandomStringUtils.random(10);
        sessoin.setAttribute("state", state);
        //重定向
        return "redirect:https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id="
                + 101531196 + "&redirect_uri=" + "http://127.0.0.1:8080/recall" + "&state=" + state;

    }


    /**
     * 短信登录
     *
     * @param smsDTO
     * @param bindingResult
     * @return
     */
    @PostMapping(value = "/mobilelogin")
    @ApiOperation(value = "手机验证码登录", tags = "会员接口", notes = "手机验证码登录")
    public RestResponseBean mobilelogin(@Valid SmsDTO smsDTO, BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            return new RestResponseBean(ResultEnum.PARAMETER_MISSING.getValue(), ResultEnum.PARAMETER_MISSING.getDesc(), null);
        }

        switch (ismsService.check(smsDTO.getMobile(), smsDTO.getEvent(), smsDTO.getCaptcha())) {
            case 1:
                return new RestResponseBean(ResultEnum.SMS_CODE_OVERTIME.getValue(), ResultEnum.SMS_CODE_OVERTIME.getDesc(), null);
            case 2:
                return new RestResponseBean(ResultEnum.SMS_CODE_ERROR.getValue(), ResultEnum.SMS_CODE_ERROR.getDesc(), null);
        }

        User user = userService.queryByMobile(smsDTO.getMobile());

        if (user == null) {
            return new RestResponseBean(ResultEnum.USER_NOT_EXIST.getValue(), ResultEnum.USER_NOT_EXIST.getDesc(), null);
        }

        return new RestResponseBean(ResultEnum.LOGIN_SUCCESS.getValue(), ResultEnum.LOGIN_SUCCESS.getDesc(), tokenBuild(user));
    }

    /**
     * 微信登录
     *
     * @return
     */
    @PostMapping(value = "/wxLogin")
    @ApiOperation(value = "微信登录", tags = "会员接口", notes = "微信登录")
    public void wxLogin(HttpServletResponse response, HttpServletRequest request) {

        iWxService.wxLogin(response, request);

    }

    /**
     * 微信回调
     *
     * @param request
     * @return
     * @throws ServletException
     * @throws IOException
     */
    @GetMapping(value = "/callBack")
    public RestResponseBean callBack(HttpServletRequest request) {
        //获取回调map
        Map<String, String> map = iWxService.callBack(request);
        String openid = map.get("openid");
        String mobile = map.get("mobile");
        //返回空则表明回调异常
        if (StringUtils.isBlank(openid)) {
            return new RestResponseBean(ResultEnum.ERROR.getValue(), ResultEnum.ERROR.getDesc(), null);
        }
        //查询登录状态
        User loginUser = userService.queryByMobile(mobile);
        //查询是否已有账户绑定该WX
        User user = userService.queryByWeChatOpenId(openid);
        //未登录
        if (loginUser == null) {
            //未登录,未绑定
            if (user == null) {
                return new RestResponseBean(ResultEnum.WX_UNBOUND_OPENID.getValue(), ResultEnum.WX_UNBOUND_OPENID.getDesc(), null);
            }
            //未登录,已绑定,返回登录信息token等
            return new RestResponseBean(ResultEnum.LOGIN_SUCCESS.getValue(), ResultEnum.LOGIN_SUCCESS.getDesc(), tokenBuild(user));
        }
        //已登录,未绑定
        if (user == null) {
            //绑定微信
            loginUser.setWxId(openid);
            if (userService.updateById(loginUser)) {
                return new RestResponseBean(ResultEnum.WX_BINDING_SUCCESS.getValue(), ResultEnum.WX_BINDING_SUCCESS.getDesc(), null);
            }
            //绑定失败
            return new RestResponseBean(ResultEnum.WX_BINDING_ERROR.getValue(), ResultEnum.WX_BINDING_ERROR.getDesc(), null);
        }
        //已登录,禁止重复绑定
        return new RestResponseBean(ResultEnum.WX_REPEATED_BINDING.getValue(), ResultEnum.WX_REPEATED_BINDING.getDesc(), null);
    }

    /**
     * qq登录
     *
     * @param request
     * @param response
     * @throws QQConnectException
     */
    @PostMapping("/locaQQLogin")
    @ApiOperation(value = "qq登录", tags = "会员接口", notes = "qq登录")
    public void locaQQLogin(HttpServletRequest request, HttpServletResponse response) throws QQConnectException {
        //生成授权连接
        response.setContentType("text/html;charset=utf-8");

        try {


            response.sendRedirect(userService.getQQURL(request));


        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    /**
     * qq登录回调
     *
     * @param request
     * @param httpSession
     * @param response
     * @return
     * @throws QQConnectException
     */
    @GetMapping("/qqLoginCallback")
    public RestResponseBean qqLoginCallback(HttpServletRequest request, HttpSession httpSession, HttpServletResponse response) throws QQConnectException {

        response.setContentType("text/html;charset=utf-8");
        String state = request.getParameter("state");

        String accessToken = null;
        String openID = null;
        long tokenExpireIn = 0L;


        User user1 = userService.queryByMobile(state);

        String queryString = ((HttpServletRequest) request).getQueryString();
        try {
            AccessToken accessTokenObj = (new Oauth().getAccessTokenByQueryString(queryString, state));
            if (accessTokenObj.getAccessToken().equals("")) {
                System.out.println("没有获取到响应参数");
                return new RestResponseBean(ResultEnum.PARAMETER_MISSING.getValue(), ResultEnum.PARAMETER_MISSING.getDesc(), null);
            } else {
                //得到token
                accessToken = accessTokenObj.getAccessToken();
                tokenExpireIn = accessTokenObj.getExpireIn();
                request.getSession().setAttribute("demo_access_token", accessToken);
                request.getSession().setAttribute("demo_token_expirein", String.valueOf(tokenExpireIn));
                // 利用获取到的accessToken 去获取当前用的openid -------- start
                OpenID openIDObj = new OpenID(accessToken);
                openID = openIDObj.getUserOpenID();

                User user = userService.queryByQQOpenId(openID);

                //判断是否已经登录
                if (user1 != null) {
                    /**
                     * 判断是否已经绑定
                     */
                    if (user != null) {
                        return new RestResponseBean(ResultEnum.QQ_REPEATED_BINDING.getValue(), ResultEnum.QQ_REPEATED_BINDING.getDesc(), null);
                    }
                    RestResponseBean RestResponseBean = userService.qqBinding(openID, user);
                    return RestResponseBean;
                }

                request.getSession().setAttribute("demo_openid", openID);

                if (user == null) {
                    return new RestResponseBean(ResultEnum.QQ_UNBOUND_OPENID.getValue(), ResultEnum.QQ_UNBOUND_OPENID.getDesc(), null);
                }
                this.tokenBuild(user);

            }
        } catch (QQConnectException e) {
            e.printStackTrace();
            System.out.println("QQ登录失败，原因：" + e.getMessage());
            return new RestResponseBean(ResultEnum.QQ_LOGIN_FAIL.getValue(), ResultEnum.QQ_LOGIN_FAIL.getDesc() + "失败原因:" + e.getMessage(), null);

        }
        return new RestResponseBean(ResultEnum.QQ_LOGIN.getValue(), ResultEnum.QQ_LOGIN.getDesc(), null);
    }


    /**
     * 公共方法,作用于:账号密码登录,手机验证码登录,三方登录
     *
     * @param user 根据传参查询到的实体
     * @return
     */
    private JSONObject tokenBuild(User user) {

        JSONObject obj = new JSONObject();
        //生成token
        String token = JwtUtil.sign(CommonConstant.SIGN_MEMBER_USER + user.getUsername(), user.getPassword());
        redisUtil.set(CommonConstant.PREFIX_USER_TOKEN + token, token);
        //设置超时时间
        redisUtil.expire(CommonConstant.PREFIX_USER_TOKEN + token, JwtUtil.EXPIRE_TIME / 1000);

        obj.put("token", token);
        obj.put("user", user);

        sysBaseAPI.addLog("用户名: " + user.getUsername() + ",登录成功！", CommonConstant.LOG_TYPE_1, null);

        return obj;
    }

}
