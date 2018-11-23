/**
 *
 */
package com.rinbo.springsecurity.core.authentication.mobile;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * 短信登录验证信息封装类
 */
public class DXAuthenticationToken extends AbstractAuthenticationToken {

    //认证信息，认证前手机号码，认证后用户信息
    private final Object principal;

    public DXAuthenticationToken(String mobile) {
        super(null);
        //保存手机号码
        this.principal = mobile;
        setAuthenticated(false);
    }

    public DXAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true);
    }

    //返回密码，用于用户名密码token
    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
