package org.benben.modules.business.user.controller;

import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.qq.connect.QQConnectException;
import com.qq.connect.oauth.Oauth;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.api.vo.Result;
import org.benben.common.constant.CommonConstant;
import org.benben.common.menu.ResultEnum;
import org.benben.common.system.api.ISysBaseAPI;
import org.benben.common.system.query.QueryGenerator;
import org.benben.common.util.PasswordUtil;
import org.benben.common.util.RedisUtil;
import org.benben.common.util.oConvertUtils;
import org.benben.modules.business.commen.dto.SmsDTO;
import org.benben.modules.business.commen.service.IQqService;
import org.benben.modules.business.commen.service.ISMSService;
import org.benben.modules.business.commen.service.IWbService;
import org.benben.modules.business.commen.service.IWxService;
import org.benben.modules.business.user.entity.User;
import org.benben.modules.business.user.entity.UserThird;
import org.benben.modules.business.user.service.IUserService;
import org.benben.modules.business.user.service.IUserThirdService;
import org.benben.modules.shiro.authc.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

/**
 * @Title: Controller
 * @Description: 用户
 * @author： jeecg-boot
 * @date： 2019-04-19
 * @version： V1.0
 */
@RestController
@RequestMapping("/api/user")
@Api(tags = {"用户接口"})
@Slf4j
public class RestUserController {
    @Autowired
    private IUserService userService;

    @Autowired
    private IUserThirdService userThirdService;

    @Autowired
    private ISysBaseAPI sysBaseAPI;

    @Autowired
    private ISMSService ismsService;

    @Autowired
    private IWxService iWxService;

    @Autowired
    private IWbService iWbService;

    @Autowired
    private IQqService iQqService;

    @Autowired
    private RedisUtil redisUtil;


    /**
     * 分页列表查询
     * @param user
     * @param pageNo
     * @param pageSize
     * @param req
     * @return
     */
    @GetMapping(value = "/list")
    @ApiOperation(value = "用户列表", tags = {"用户接口"}, notes = "用户列表")
    public RestResponseBean queryPageList(User user,
                                          @RequestParam(name="pageNo", defaultValue="1") Integer pageNo,
                                          @RequestParam(name="pageSize", defaultValue="10") Integer pageSize,
                                          HttpServletRequest req) {

        QueryWrapper<User> queryWrapper = QueryGenerator.initQueryWrapper(user, req.getParameterMap());
        Page<User> page = new Page<User>(pageNo, pageSize);
        IPage<User> pageList = userService.page(page, queryWrapper);

        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(),ResultEnum.OPERATION_SUCCESS.getDesc(),pageList);
    }



    /**
     * 通过id查询
     * @param id
     * @return
     */
    @GetMapping(value = "/queryById")
    @ApiOperation(value = "通过id查询用户", tags = {"用户接口"}, notes = "通过id查询用户")
    public RestResponseBean queryById(@RequestParam(name="id",required=true) String id) {

        User user = userService.getById(id);

        if(user==null) {
            return new RestResponseBean(ResultEnum.QUERY_NOT_EXIST.getValue(),ResultEnum.QUERY_NOT_EXIST.getDesc(),null);
        }

        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(),ResultEnum.OPERATION_SUCCESS.getDesc(),user);
    }


    /**
     * 用户注册
     * @param user
     * @return
     */
    @PostMapping(value = "/register")
    @ApiOperation(value = "用户注册", tags = {"用户接口"}, notes = "用户注册")
    public RestResponseBean add(@RequestBody User user) {

        try {

            String salt = oConvertUtils.randomGen(8);
            user.setSalt(salt);
            String passwordEncode = PasswordUtil.encrypt(user.getUsername(), user.getPassword(), salt);
            user.setPassword(passwordEncode);
            userService.save(user);
            return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(),ResultEnum.OPERATION_SUCCESS.getDesc(),user);

        } catch (Exception e) {
            e.printStackTrace();
            log.info(e.getMessage());
        }

        return new RestResponseBean(ResultEnum.OPERATION_FAIL.getValue(),ResultEnum.OPERATION_FAIL.getDesc(),user);

    }


    /**
     * 用户修改
     * @param user
     * @return
     */
    @PostMapping(value = "/edit")
    @ApiOperation(value = "用户修改", tags = {"用户接口"}, notes = "用户修改")
    public RestResponseBean edit(@RequestBody User user) {

        User userEntity = userService.getById(user.getId());

        if(userEntity==null) {
            return new RestResponseBean(ResultEnum.QUERY_NOT_EXIST.getValue(),ResultEnum.QUERY_NOT_EXIST.getDesc(),null);
        }else {
            boolean ok = userService.updateById(user);

            if(!ok) {
                return new RestResponseBean(ResultEnum.OPERATION_FAIL.getValue(),ResultEnum.OPERATION_FAIL.getDesc(),user);
            }
        }

        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(),ResultEnum.OPERATION_SUCCESS.getDesc(),user);
    }

    /**
     *   通过id删除
     * @param id
     * @return
     */
    @PostMapping(value = "/delete")
    @ApiOperation(value = "用户删除", tags = {"用户接口"}, notes = "用户删除")
    public RestResponseBean delete(@RequestParam(name="id",required=true) String id) {

        User user = userService.getById(id);

        if(user==null) {
            return new RestResponseBean(ResultEnum.QUERY_NOT_EXIST.getValue(),ResultEnum.QUERY_NOT_EXIST.getDesc(),null);
        }

        userService.delMain(id);

        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(),ResultEnum.OPERATION_SUCCESS.getDesc(),user);
    }


    /**
     * 根据姓名查找
     *
     * @param username
     * @return
     */
    @GetMapping(value = "/queryByName")
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
    @ApiOperation(value = "修改邮箱", tags = {"用户接口"}, notes = "修改邮箱")
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
    @ApiOperation(value = "修改手机号", tags = {"用户接口"}, notes = "修改手机号")
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
    @ApiOperation(value = "修改密码", tags = {"用户接口"}, notes = "修改密码")
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

    @PostMapping(value = "/login")
    @ApiOperation(value = "用户登录接口", tags = {"用户接口"}, notes = "用户登录接口")
    public RestResponseBean login(@RequestParam("username") String username, @RequestParam("password") String password) {

        JSONObject obj = new JSONObject();
        User user = userService.queryByUsername(username);

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
     * 退出
     *
     * @return
     */
    @GetMapping("/logOut")
    @ApiOperation(value = "退出", tags = {"用户接口"}, notes = "退出")
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

    /**
     * 短信登录
     *
     * @param smsDTO
     * @param bindingResult
     * @return
     */
    @PostMapping(value = "/mobile_login")
    @ApiOperation(value = "手机验证码登录", tags = {"用户接口"}, notes = "手机验证码登录")
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
     * qq登录
     *
     * @param response
     * @throws QQConnectException
     */
    @PostMapping("/qq_login")
    @ApiOperation(value = "qq登录", tags = {"用户接口"}, notes = "qq登录")
    public void qqlogin(HttpServletRequest request,HttpServletResponse response) {

        String mobile = request.getParameter("mobile");

        try {
            //生成授权连接
            response.setContentType("text/html;charset=utf-8");
            response.sendRedirect((new Oauth().getAuthorizeURL(mobile)));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    /**
     * qq登录回调
     * @param request
     * @return
     */
    @GetMapping("/qq_login_callback")
    public RestResponseBean qqLoginCallback(HttpServletRequest request) {

        //获取回调
        String openid = iQqService.callBack(request);
        String mobile = request.getParameter("state");

        return publicCallBack(openid,mobile,"0");
    }

    /**
     * 微信登录
     *
     * @return
     */
    @PostMapping(value = "/wx_login")
    @ApiOperation(value = "微信登录", tags = {"用户接口"}, notes = "微信登录")
    public void wxLogin(HttpServletResponse response, HttpServletRequest request) {

        iWxService.wxLogin(response, request);

    }

    /**
     * 微信回调
     * @param request
     * @return
     */
    @GetMapping(value = "/wx_login_callBack")
    public RestResponseBean callBack(HttpServletRequest request) {

        User userEntity = null;
        //获取回调
        String openid = iWxService.callBack(request);
        String mobile = request.getParameter("state");

        return publicCallBack(openid,mobile,"1");
    }

    /**
     * 微博登录
     *
     * @return
     */
    @PostMapping(value = "/wb_login")
    @ApiOperation(value = "微博登录", tags = {"用户接口"}, notes = "微博登录")
    public void wbLogin(HttpServletResponse response, HttpServletRequest request) {

        iWbService.login(response,request);

    }

    /**
     * 微博回调
     * @param request
     * @return
     */
    @GetMapping(value = "/wb_login_callback")
    public RestResponseBean wbCallBack(HttpServletRequest request) {

        User userEntity = null;
        //获取回调
        String openid = iWbService.callBack(request);
        String mobile = request.getParameter("state");

        return publicCallBack(openid,mobile,"2");
    }

    @PostMapping("/forget_password")
    @ApiOperation(value = "忘记密码", tags = {"用户接口"}, notes = "忘记密码")
    public RestResponseBean forgetPassword(@RequestParam String mobile,@RequestParam String password){

        if(StringUtils.equals(mobile,"")||StringUtils.equals(password,"")){
            return new RestResponseBean(ResultEnum.PARAMETER_MISSING.getValue(), ResultEnum.PARAMETER_MISSING.getDesc(), null);
        }

        if(userService.forgetPassword(mobile,password) == 0){
            return new RestResponseBean(ResultEnum.ERROR.getValue(),ResultEnum.ERROR.getDesc(),null);
        }

        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(),ResultEnum.OPERATION_SUCCESS.getDesc(),null);
    }


    /**
     * 公共方法,三方登录公共回调
     * @param openid
     * @param mobile
     * @param type
     * @return
     */
    private RestResponseBean publicCallBack(String openid,String mobile,String type){

        User userEntity = null;

        //返回空则表明回调异常
        if (StringUtils.isBlank(openid)) {
            return new RestResponseBean(ResultEnum.ERROR.getValue(), ResultEnum.ERROR.getDesc(), null);
        }
        //查询登录状态
        User user = userService.queryByMobile(mobile);
        //查询是否已有账户绑定该微博
        UserThird userThird = userThirdService.queryByOpenid(openid);
        if(userThird != null){
            //查询绑定的用户信息
            userEntity = userService.getById(userThird.getUserId());
        }
        //未登录
        if (user == null) {
            //未登录,未绑定
            if (userEntity == null) {
                return new RestResponseBean(ResultEnum.UNBOUND_OPENID.getValue(), ResultEnum.UNBOUND_OPENID.getDesc(), null);
            }
            //未登录,已绑定,返回登录信息token等
            return new RestResponseBean(ResultEnum.LOGIN_SUCCESS.getValue(), ResultEnum.LOGIN_SUCCESS.getDesc(), tokenBuild(userEntity));
        }
        //已登录,未绑定
        if (userEntity == null) {

            switch (type){
                case "0":
                    //绑定QQ
                    if (userService.bindingThird(openid,user.getId(),"0") == 1) {
                        return new RestResponseBean(ResultEnum.BINDING_SUCCESS.getValue(), ResultEnum.BINDING_SUCCESS.getDesc(), null);
                    }
                    break;
                case "1":
                    //绑定微信
                    if (userService.bindingThird(openid,user.getId(),"1") == 1) {
                        return new RestResponseBean(ResultEnum.BINDING_SUCCESS.getValue(), ResultEnum.BINDING_SUCCESS.getDesc(), null);
                    }
                    break;
                default :
                    //绑定微博
                    if (userService.bindingThird(openid,user.getId(),"2") == 1) {
                        return new RestResponseBean(ResultEnum.BINDING_SUCCESS.getValue(), ResultEnum.BINDING_SUCCESS.getDesc(), null);
                    }
                    break;
            }

            //绑定失败
            return new RestResponseBean(ResultEnum.BINDING_FAIL.getValue(), ResultEnum.BINDING_FAIL.getDesc(), null);
        }
        //已登录,禁止重复绑定
        return new RestResponseBean(ResultEnum.REPEATED_BINDING.getValue(), ResultEnum.REPEATED_BINDING.getDesc(), null);
    }

    /**
     * 公共方法,三方登录返回信息token
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
