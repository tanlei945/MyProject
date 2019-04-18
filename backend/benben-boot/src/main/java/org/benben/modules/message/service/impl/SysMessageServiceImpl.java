package org.benben.modules.message.service.impl;

import org.benben.modules.message.entity.SysMessage;
import org.benben.modules.message.mapper.SysMessageMapper;
import org.benben.modules.message.service.ISysMessageService;
import org.springframework.stereotype.Service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;

/**
 * @Description: 消息
 * @author： benben-boot
 * @date：   2019-04-09
 * @version： V1.0
 */
@Service
public class SysMessageServiceImpl extends ServiceImpl<SysMessageMapper, SysMessage> implements ISysMessageService {

}
