package org.benben.modules.business.commen.service;


import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;


public interface ICommonService {

    public String localUploadImage(HttpServletRequest request);

    public String localUploadImage(MultipartFile multipartFile);
}
