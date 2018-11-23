package com.rinbo.springsecurity.ssoserver.service;


import com.rinbo.springsecurity.ssoserver.domain.SysUser;

public interface UserService {

    /**
     * 根据用户名获取系统用户
     */
    SysUser getUserByName(String username);

}
