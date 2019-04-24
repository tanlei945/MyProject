package org.benben.common.util.aliyun;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.aliyun.oss.ClientException;
import com.aliyun.oss.OSSClient;
import com.aliyun.oss.OSSException;
import com.aliyun.oss.model.GetObjectRequest;
import com.aliyun.oss.model.OSSObject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.web.multipart.MultipartFile;
import sun.misc.BASE64Decoder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;

/**
 * @author: WangHao
 * @date: 2019/3/29 10:51
 * @description: OSS文件系统实现
 */
@Slf4j
public class OSSClientUtils {


    public static final String ACCESS_KEY_ID = "LTAIIOthct0QzTY8";
    public static final String ACCESS_KEY_SECRET = "klMxEot3jfKYbNZDlB0BuhmF2FrkTj";
    public static final String BUCKET_NAME = "jeecg-boot";
    public static final String URL = "http://oss-cn-beijing.aliyuncs.com";
    public static final String RESULT_URL = "http://jeecg-boot.oss-cn-beijing.aliyuncs.com/";


    /**
     * file对象多图片上传
     *
     * @param files
     * @return
     * @throws Exception
     */
    public static String fileUpload(MultipartFile[] files) throws Exception {

        String urlList = "";
        int sum = 1;
        if (files != null && files.length > 0) {
            for (MultipartFile picFile : files) {
                String filename = picFile.getOriginalFilename();
                if (sum != files.length) {
                    String uploadFile = uploadFile(picFile.getBytes(), System.currentTimeMillis() + filename.substring(filename.lastIndexOf(".")));
                    urlList += uploadFile + ",";
                } else {
                    String uploadFile = uploadFile(picFile.getBytes(), System.currentTimeMillis() + filename.substring(filename.lastIndexOf(".")));
                    urlList += uploadFile;
                }
                sum++;
            }
        }

        return urlList;
    }

    /**
     * base64str多图片上传
     *
     * @param image
     * @return
     * @throws Exception
     */
    public static String morePicturesUpdate(String image) throws Exception {
        //转换jsonarray
        JSONArray array = JSONArray.parseArray(image);
        String[] uril = new String[array.size()];
        //遍历list
        for (int i = 0; i < array.size(); i++) {
            JSONObject jsonObject = array.getJSONObject(i);
            String imgBase64 = jsonObject.getString("src");

            if (imgBase64.indexOf("http") != -1) {
                uril[i] = imgBase64;
            } else {
                imgBase64 = imgBase64.substring(imgBase64.indexOf(",") + 1, imgBase64.length());
                String url = base64uploadFile(imgBase64, System.currentTimeMillis() + ".jpg");
                uril[i] = url;
            }
        }
        return JSONObject.toJSONString(uril);
    }

    /**
     * base64str单图片上传
     *
     * @param base64str
     * @return
     * @throws Exception
     */
    public static String picturesUpload(String base64str) throws Exception {

        String url = "";

        if (base64str.indexOf("http") != -1) {
            return base64str;
        }

        base64str = base64str.substring(base64str.indexOf(",") + 1, base64str.length());
        url = base64uploadFile(base64str, System.currentTimeMillis() + ".jpg");

        return url;
    }

    /**
     * base64图片上传
     *
     * @param base64str
     * @param fileName
     * @throws Exception
     */
    public static String base64uploadFile(String base64str, String fileName) throws Exception {

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] imageByte = decoder.decodeBuffer(base64str);
        String url = uploadFile(imageByte, fileName);

        return url;
    }

    /**
     * 上传文件
     *
     * @param file
     * @param fileName
     * @return
     */
    public static String uploadFile(byte[] file, String fileName) {

        InputStream is = null;
        String resultUrl = "";
        try {
            is = new ByteArrayInputStream(file);
            resultUrl = uploadFile(is, fileName);

        } catch (Exception e) {
            log.error("OSS文件上传出错！", e);
            throw new RuntimeException(e);
        } finally {
            try {
                is.close();
            } catch (Exception e2) {
                log.error("流关闭异常！", e2);
            }
        }
        return resultUrl;
    }


    /**
     * 上传流文件
     *
     * @param in
     * @param fileName
     */
    public static String uploadFile(InputStream in, String fileName) {
        OSSClient ossClient = new OSSClient(URL, ACCESS_KEY_ID,
                ACCESS_KEY_SECRET);
        ossClient.putObject(BUCKET_NAME, fileName, in);
        ossClient.shutdown();

        StringBuffer sb = new StringBuffer();
        sb.append(RESULT_URL).append(fileName);
        return sb.toString();
    }


    /**
     * 下载文件
     *
     * @param fileKey
     * @param file
     */
    public static void downloadFile(String fileKey, String file) {
        OSSClient ossClient = new OSSClient(URL, ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        ossClient.getObject(new GetObjectRequest(BUCKET_NAME, fileKey), new File(file));
        ossClient.shutdown();
    }


    public static byte[] downloadFile(String fileId) {
        byte[] bytes = null;
        OSSClient ossClient = new OSSClient(URL, ACCESS_KEY_ID,
                ACCESS_KEY_SECRET);
        try {
            OSSObject ossObject = ossClient.getObject(BUCKET_NAME, fileId);
            bytes = IOUtils.toByteArray(ossObject.getObjectContent());

        } catch (Exception e) {
            log.error("OSS文件下载出错！", e);
            throw new RuntimeException(e);
        } finally {
            try {
                ossClient.shutdown();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return bytes;
    }


    /**
     * 文件删除
     *
     * @param filePath
     */
    public static void deleteFile(String filePath) {

        OSSClient ossClient = new OSSClient(URL, ACCESS_KEY_ID,
                ACCESS_KEY_SECRET);
        filePath = filePath.substring(46);

        try {
            ossClient.deleteObject(BUCKET_NAME, filePath);
        } catch (OSSException oe) {
            oe.printStackTrace();
        } catch (ClientException ce) {
            ce.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            ossClient.shutdown();
        }

    }


}
