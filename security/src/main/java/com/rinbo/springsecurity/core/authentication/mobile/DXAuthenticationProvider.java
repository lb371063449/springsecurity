package com.rinbo.springsecurity.core.authentication.mobile;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 短信登录验证逻辑
 */
public class DXAuthenticationProvider implements AuthenticationProvider {

	private UserDetailsService userDetailsService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		DXAuthenticationToken authenticationToken = (DXAuthenticationToken) authentication;
		//根据手机号码拿到用户信息
		UserDetails user = userDetailsService.loadUserByUsername((String) authenticationToken.getPrincipal());

		if (user == null) {
			throw new InternalAuthenticationServiceException("无法获取用户信息");
		}
		//传入用户信息、用户权限
		DXAuthenticationToken authenticationResult = new DXAuthenticationToken(user, user.getAuthorities());
		//将未认证之前的请求信息设置已认证的token中
		authenticationResult.setDetails(authenticationToken.getDetails());
		return authenticationResult;
	}

	//支持的token
	@Override
	public boolean supports(Class<?> authentication) {
		return DXAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

}
