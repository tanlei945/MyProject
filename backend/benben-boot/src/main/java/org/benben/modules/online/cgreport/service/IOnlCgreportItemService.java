package org.benben.modules.online.cgreport.service;

import java.util.List;
import java.util.Map;

import org.benben.modules.online.cgreport.entity.OnlCgreportItem;

import com.baomidou.mybatisplus.extension.service.IService;

/**
 * @Description: 在线报表配置
 * @author: benben-boot
 * @date: 2019-03-08
 * @version: V1.0
 */
public interface IOnlCgreportItemService extends IService<OnlCgreportItem> {

	List<Map<String, String>> getAutoListQueryInfo(String cgrheadId);

}
