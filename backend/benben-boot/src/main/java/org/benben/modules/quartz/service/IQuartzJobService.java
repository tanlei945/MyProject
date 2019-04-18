package org.benben.modules.quartz.service;

import java.util.List;

import org.benben.modules.quartz.entity.QuartzJob;

import com.baomidou.mybatisplus.extension.service.IService;

/**
 * @Description: 定时任务在线管理
 * @author： benben-boot
 * @date：   2019-01-02
 * @version： V1.0
 */
public interface IQuartzJobService extends IService<QuartzJob> {

	List<QuartzJob> findByJobClassName(String jobClassName);

}
