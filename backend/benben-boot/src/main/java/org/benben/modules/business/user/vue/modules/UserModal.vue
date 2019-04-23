<template>
  <a-modal
          :title="title"
          :width="800"
          :visible="visible"
          :confirmLoading="confirmLoading"
          @ok="handleOk"
          @cancel="handleCancel"
          cancelText="关闭">

    <a-spin :spinning="confirmLoading">
      <a-form :form="form">

        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="组别ID">
          <a-input placeholder="请输入组别ID" v-decorator="['groupId', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="用户名">
          <a-input placeholder="请输入用户名" v-decorator="['username', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="真实姓名">
          <a-input placeholder="请输入真实姓名" v-decorator="['realname', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="昵称">
          <a-input placeholder="请输入昵称" v-decorator="['nickname', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="密码">
          <a-input placeholder="请输入密码" v-decorator="['password', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="密码盐">
          <a-input placeholder="请输入密码盐" v-decorator="['salt', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="用户类型  0/普通用户,1/骑手">
          <a-input placeholder="请输入用户类型  0/普通用户,1/骑手" v-decorator="['userType', validatorRules.userType ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="电子邮箱">
          <a-input placeholder="请输入电子邮箱" v-decorator="['email', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="手机号">
          <a-input placeholder="请输入手机号" v-decorator="['mobile', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="头像">
          <a-input placeholder="请输入头像" v-decorator="['avatar', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="等级">
          <a-input placeholder="请输入等级" v-decorator="['userLevel', validatorRules.userLevel ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="性别  0/男,1/女">
          <a-input placeholder="请输入性别  0/男,1/女" v-decorator="['sex', validatorRules.sex ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="生日">
          <a-date-picker showTime format='YYYY-MM-DD HH:mm:ss' v-decorator="[ 'birthday', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="格言">
          <a-input placeholder="请输入格言" v-decorator="['bio', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="余额">
          <a-input-number v-decorator="[ 'userMoney', validatorRules.userMoney ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="积分">
          <a-input-number v-decorator="[ 'score', validatorRules.score ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="连续登录天数">
          <a-input-number v-decorator="[ 'successIons', validatorRules.successIons ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="最大连续登录天数">
          <a-input-number v-decorator="[ 'maxsuccessIons', validatorRules.maxsuccessIons ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="上次登录时间">
          <a-input-number v-decorator="[ 'prevTime', validatorRules.prevTime ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="登录时间">
          <a-date-picker showTime format='YYYY-MM-DD HH:mm:ss' v-decorator="[ 'loginTime', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="登录IP">
          <a-input placeholder="请输入登录IP" v-decorator="['loginip', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="失败次数">
          <a-input placeholder="请输入失败次数" v-decorator="['loginfailure', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="加入IP">
          <a-input placeholder="请输入加入IP" v-decorator="['joinip', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="加入时间">
          <a-date-picker showTime format='YYYY-MM-DD HH:mm:ss' v-decorator="[ 'joinTime', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="状态(1：正常  2：冻结 ）">
          <a-input placeholder="请输入状态(1：正常  2：冻结 ）" v-decorator="['status', validatorRules.status ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="删除状态  0/正常,1/已删除">
          <a-input placeholder="请输入删除状态  0/正常,1/已删除" v-decorator="['delFlag', validatorRules.delFlag ]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="邀请人">
          <a-input placeholder="请输入邀请人" v-decorator="['inviterId', {}]" />
        </a-form-item>

      </a-form>
    </a-spin>
  </a-modal>
</template>

<script>
  import { httpAction } from '@/api/manage'
  import pick from 'lodash.pick'
  import moment from "moment"

  export default {
    name: "UserModal",
    data () {
      return {
        title:"操作",
        visible: false,
        model: {},
        labelCol: {
          xs: { span: 24 },
          sm: { span: 5 },
        },
        wrapperCol: {
          xs: { span: 24 },
          sm: { span: 16 },
        },

        confirmLoading: false,
        form: this.$form.createForm(this),
        validatorRules:{
          userType:{rules: [{ required: true, message: '请输入用户类型  0/普通用户,1/骑手!' }]},
          userLevel:{rules: [{ required: true, message: '请输入等级!' }]},
          sex:{rules: [{ required: true, message: '请输入性别  0/男,1/女!' }]},
          userMoney:{rules: [{ required: true, message: '请输入余额!' }]},
          score:{rules: [{ required: true, message: '请输入积分!' }]},
          successIons:{rules: [{ required: true, message: '请输入连续登录天数!' }]},
          maxsuccessIons:{rules: [{ required: true, message: '请输入最大连续登录天数!' }]},
          prevTime:{rules: [{ required: true, message: '请输入上次登录时间!' }]},
          status:{rules: [{ required: true, message: '请输入状态(1：正常  2：冻结 ）!' }]},
          delFlag:{rules: [{ required: true, message: '请输入删除状态  0/正常,1/已删除!' }]},
        },
        url: {
          add: "/user/add",
          edit: "/user/edit",
        },
      }
    },
    created () {
    },
    methods: {
      add () {
        this.edit({});
      },
      edit (record) {
        this.form.resetFields();
        this.model = Object.assign({}, record);
        this.visible = true;
        this.$nextTick(() => {
          this.form.setFieldsValue(pick(this.model,'groupId','username','realname','nickname','password','salt','userType','email','mobile','avatar','userLevel','sex','bio','userMoney','score','successIons','maxsuccessIons','prevTime','loginip','loginfailure','joinip','status','delFlag','inviterId'))
          //时间格式化
          this.form.setFieldsValue({birthday:this.model.birthday?moment(this.model.birthday):null})
          this.form.setFieldsValue({loginTime:this.model.loginTime?moment(this.model.loginTime):null})
          this.form.setFieldsValue({joinTime:this.model.joinTime?moment(this.model.joinTime):null})
        });

      },
      close () {
        this.$emit('close');
        this.visible = false;
      },
      handleOk () {
        const that = this;
        // 触发表单验证
        this.form.validateFields((err, values) => {
          if (!err) {
            that.confirmLoading = true;
            let httpurl = '';
            let method = '';
            if(!this.model.id){
              httpurl+=this.url.add;
              method = 'post';
            }else{
              httpurl+=this.url.edit;
              method = 'put';
            }
            let formData = Object.assign(this.model, values);
            //时间格式化
            formData.birthday = formData.birthday?formData.birthday.format('YYYY-MM-DD HH:mm:ss'):null;
            formData.loginTime = formData.loginTime?formData.loginTime.format('YYYY-MM-DD HH:mm:ss'):null;
            formData.joinTime = formData.joinTime?formData.joinTime.format('YYYY-MM-DD HH:mm:ss'):null;

            console.log(formData)
            httpAction(httpurl,formData,method).then((res)=>{
              if(res.success){
                that.$message.success(res.message);
                that.$emit('ok');
              }else{
                that.$message.warning(res.message);
              }
            }).finally(() => {
              that.confirmLoading = false;
              that.close();
            })



          }
        })
      },
      handleCancel () {
        this.close()
      },


    }
  }
</script>

<style scoped>

</style>