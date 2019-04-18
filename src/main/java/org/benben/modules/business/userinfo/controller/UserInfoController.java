package org.benben.modules.business.userinfo.controller;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.benben.common.api.vo.Result;
import org.benben.common.system.query.QueryGenerator;
import org.benben.common.util.oConvertUtils;
import org.benben.modules.business.userinfo.entity.UserInfo;
import org.benben.modules.business.userinfo.service.IUserInfoService;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import lombok.extern.slf4j.Slf4j;

import org.jeecgframework.poi.excel.ExcelImportUtil;
import org.jeecgframework.poi.excel.def.NormalExcelConstants;
import org.jeecgframework.poi.excel.entity.ExportParams;
import org.jeecgframework.poi.excel.entity.ImportParams;
import org.jeecgframework.poi.excel.view.JeecgEntityExcelView;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.ModelAndView;
import com.alibaba.fastjson.JSON;

/**
 * @Title: Controller
 * @Description: 会员表
 * @author： jeecg-boot
 * @date： 2019-04-18
 * @version： V1.0
 */
@RestController
@RequestMapping("/user/userInfo")
@Slf4j
public class UserInfoController {
    @Autowired
    private IUserInfoService userInfoService;

    /**
     * 分页列表查询
     *
     * @param userInfo
     * @param pageNo
     * @param pageSize
     * @param req
     * @return
     */
    @GetMapping(value = "/list")
    public Result<IPage<UserInfo>> queryPageList(UserInfo userInfo,
                                                 @RequestParam(name = "pageNo", defaultValue = "1") Integer pageNo,
                                                 @RequestParam(name = "pageSize", defaultValue = "10") Integer pageSize,
                                                 HttpServletRequest req) {
        Result<IPage<UserInfo>> result = new Result<IPage<UserInfo>>();
        QueryWrapper<UserInfo> queryWrapper = QueryGenerator.initQueryWrapper(userInfo, req.getParameterMap());
        Page<UserInfo> page = new Page<UserInfo>(pageNo, pageSize);
        IPage<UserInfo> pageList = userInfoService.page(page, queryWrapper);
        result.setSuccess(true);
        result.setResult(pageList);
        return result;
    }

    /**
     * 添加
     *
     * @param userInfo
     * @return
     */
    @PostMapping(value = "/add")
    public Result<UserInfo> add(@RequestBody UserInfo userInfo) {
        Result<UserInfo> result = new Result<UserInfo>();
        try {
            userInfoService.save(userInfo);
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
     * @param userInfo
     * @return
     */
    @PutMapping(value = "/edit")
    public Result<UserInfo> edit(@RequestBody UserInfo userInfo) {
        Result<UserInfo> result = new Result<UserInfo>();
        UserInfo userInfoEntity = userInfoService.getById(userInfo.getId());
        if (userInfoEntity == null) {
            result.error500("未找到对应实体");
        } else {
            boolean ok = userInfoService.updateById(userInfo);
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
    @DeleteMapping(value = "/delete")
    public Result<UserInfo> delete(@RequestParam(name = "id", required = true) String id) {
        Result<UserInfo> result = new Result<UserInfo>();
        UserInfo userInfo = userInfoService.getById(id);
        if (userInfo == null) {
            result.error500("未找到对应实体");
        } else {
            boolean ok = userInfoService.removeById(id);
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
    @DeleteMapping(value = "/deleteBatch")
    public Result<UserInfo> deleteBatch(@RequestParam(name = "ids", required = true) String ids) {
        Result<UserInfo> result = new Result<UserInfo>();
        if (ids == null || "".equals(ids.trim())) {
            result.error500("参数不识别！");
        } else {
            this.userInfoService.removeByIds(Arrays.asList(ids.split(",")));
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
    public Result<UserInfo> queryById(@RequestParam(name = "id", required = true) String id) {
        Result<UserInfo> result = new Result<UserInfo>();
        UserInfo userInfo = userInfoService.getById(id);
        if (userInfo == null) {
            result.error500("未找到对应实体");
        } else {
            result.setResult(userInfo);
            result.setSuccess(true);
        }
        return result;
    }

    /**
     * 导出excel
     *
     * @param request
     * @param response
     */
    @RequestMapping(value = "/exportXls")
    public ModelAndView exportXls(HttpServletRequest request, HttpServletResponse response) {
        // Step.1 组装查询条件
        QueryWrapper<UserInfo> queryWrapper = null;
        try {
            String paramsStr = request.getParameter("paramsStr");
            if (oConvertUtils.isNotEmpty(paramsStr)) {
                String deString = URLDecoder.decode(paramsStr, "UTF-8");
                UserInfo userInfo = JSON.parseObject(deString, UserInfo.class);
                queryWrapper = QueryGenerator.initQueryWrapper(userInfo, request.getParameterMap());
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        //Step.2 AutoPoi 导出Excel
        ModelAndView mv = new ModelAndView(new JeecgEntityExcelView());
        List<UserInfo> pageList = userInfoService.list(queryWrapper);
        //导出文件名称
        mv.addObject(NormalExcelConstants.FILE_NAME, "会员表列表");
        mv.addObject(NormalExcelConstants.CLASS, UserInfo.class);
        mv.addObject(NormalExcelConstants.PARAMS, new ExportParams("会员表列表数据", "导出人:Jeecg", "导出信息"));
        mv.addObject(NormalExcelConstants.DATA_LIST, pageList);
        return mv;
    }

    /**
     * 通过excel导入数据
     *
     * @param request
     * @param response
     * @return
     */
    @RequestMapping(value = "/importExcel", method = RequestMethod.POST)
    public Result<?> importExcel(HttpServletRequest request, HttpServletResponse response) {
        MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest) request;
        Map<String, MultipartFile> fileMap = multipartRequest.getFileMap();
        for (Map.Entry<String, MultipartFile> entity : fileMap.entrySet()) {
            MultipartFile file = entity.getValue();// 获取上传文件对象
            ImportParams params = new ImportParams();
            params.setTitleRows(2);
            params.setHeadRows(1);
            params.setNeedSave(true);
            try {
                List<UserInfo> listUserInfos = ExcelImportUtil.importExcel(file.getInputStream(), UserInfo.class, params);
                for (UserInfo userInfoExcel : listUserInfos) {
                    userInfoService.save(userInfoExcel);
                }
                return Result.ok("文件导入成功！数据行数：" + listUserInfos.size());
            } catch (Exception e) {
                log.error(e.getMessage());
                return Result.error("文件导入失败！");
            } finally {
                try {
                    file.getInputStream().close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return Result.ok("文件导入失败！");
    }

}
