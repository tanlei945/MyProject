package org.benben.modules.business.commen.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.StringUtils;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.api.vo.Result;
import org.benben.common.menu.ResultEnum;
import org.benben.common.util.aliyun.OSSClientUtils;
import org.benben.modules.business.commen.service.ICommonService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author: WangHao
 * @date: 2019/4/12 14:00
 * @description:
 */
@RestController
@RequestMapping("/api/v1/common/")
@Api(tags = {"通用接口"})
public class RestCommonController {

    @Value(value = "${benben.path.upload}")
    private String uploadpath;
    @Autowired
    private ICommonService commonService;

    @PostMapping(value = "/upload_image_local")
    @ApiOperation(value = "上传图片到本地",tags = {"通用接口"}, notes = "上传图片到本地")
    public RestResponseBean uploadImage(@RequestParam(value = "file") MultipartFile file) {

        String dbpath =commonService.localUploadImage(file);

        if(StringUtils.isBlank(dbpath)){
            return new RestResponseBean(ResultEnum.OPERATION_FAIL.getValue(),ResultEnum.OPERATION_FAIL.getDesc(),dbpath);
        }

        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(),ResultEnum.OPERATION_SUCCESS.getDesc(),null);

    }


    @PostMapping(value = "/upload_image_ali")
    @ApiOperation(value = "上传图片到阿里云OSS",tags = {"通用接口"}, notes = "上传图片到阿里云OSS")
    public RestResponseBean upload(@RequestParam(value = "file") MultipartFile[] files) {

        String result = "";

        try {
            result = OSSClientUtils.fileUpload(files);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(), ResultEnum.OPERATION_SUCCESS.getDesc(), result);
    }


    @PostMapping(value = "/file_upload")
    @ApiOperation(value = "上传视频",tags = {"通用接口"}, notes = "上传视频")
    public Result<Object> fileUpload(@RequestParam(value = "file") MultipartFile file) throws IOException {
        Result<Object> result = new Result<Object>();

        if (StringUtils.isEmpty(file.getOriginalFilename())) {
            result.error500("上传失败!");
        }

        InputStream fileContent = file.getInputStream();
        String fileName = file.getOriginalFilename();
        String url = OSSClientUtils.uploadFile(fileContent, fileName);
        String[] strarray = {fileName, url};

        return result.ok(strarray);
    }
}
