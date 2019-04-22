package org.benben.modules.business.commen.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.StringUtils;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.api.vo.Result;
import org.benben.common.menu.ResultEnum;
import org.benben.common.util.aliyun.OSSClientUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author: WangHao
 * @date: 2019/4/12 14:00
 * @description:
 */
@RestController
@RequestMapping("/api/common/")
@Api(tags = {"通用接口"})
public class RestCommonController {


    @PostMapping("/upload")
    @ApiOperation(value = "上传文件",tags = {"通用接口"}, notes = "上传文件")
    public RestResponseBean upload(@RequestParam(value = "file") MultipartFile[] files) {

        String result = "";

        try {
            result = OSSClientUtils.fileUpload(files);
        } catch (Exception e) {
            e.printStackTrace();
        }


        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(), ResultEnum.OPERATION_SUCCESS.getDesc(), result);
    }

    /**
     * 上传图片
     *
     * @param files
     * @return
     * @throws Exception
     */
    @PostMapping(value = "/imageUpload")
    @ApiOperation(value = "上传图片",tags = {"通用接口"}, notes = "上传图片")
    public Result<Object> imageUpload(@RequestParam(value = "file") MultipartFile[] files) throws Exception{
        Result<Object> result = new Result<Object>();

        if (files.length < 1) {
            return Result.error(401,"上传失败");
        }

        return result.ok(OSSClientUtils.fileUpload(files));
    }

    /**
     * 上传视频
     *
     * @param file
     * @return
     */
    @PostMapping(value = "/fileUpload")
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
