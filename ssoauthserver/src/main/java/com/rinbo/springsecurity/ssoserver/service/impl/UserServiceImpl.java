package com.rinbo.springsecurity.ssoserver.service.impl;


import com.rinbo.springsecurity.ssoserver.dao.UserDao;
import com.rinbo.springsecurity.ssoserver.domain.SysUser;
import com.rinbo.springsecurity.ssoserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDao userDao;

    @Override
    public SysUser getUserByName(String username) {
        return userDao.selectByName(username);
    }
}
