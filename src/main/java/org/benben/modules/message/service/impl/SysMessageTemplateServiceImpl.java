package org.benben.modules.message.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.benben.modules.message.entity.SysMessageTemplate;
import org.benben.modules.message.mapper.SysMessageTemplateMapper;
import org.benben.modules.message.service.ISysMessageTemplateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @Description: 消息模板
 * @author： benben-boot
 * @date：   2019-04-09
 * @version： V1.0
 */
@Service
public class SysMessageTemplateServiceImpl extends ServiceImpl<SysMessageTemplateMapper, SysMessageTemplate> implements ISysMessageTemplateService {

    @Autowired
    private SysMessageTemplateMapper sysMessageTemplateMapper;


    @Override
    public List<SysMessageTemplate> selectByCode(String code) {
        return sysMessageTemplateMapper.selectByCode(code);
    }
}
