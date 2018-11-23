package com.rinbo.springsecurity.core.config;

import com.rinbo.springsecurity.core.authentication.mobile.DXAuthenticationFilter;
import com.rinbo.springsecurity.core.authentication.mobile.DXAuthenticationProvider;
import com.rinbo.springsecurity.core.handler.WebAuthenctiationFailureHandler;
import com.rinbo.springsecurity.core.handler.WebAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@Component
public class DXSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Autowired
    private WebAuthenctiationFailureHandler failureHandler;

    @Autowired
    private WebAuthenticationSuccessHandler successHandler;

    @Qualifier("myUserDetailsService")
    @Autowired()
    private UserDetailsService userDetailsService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        DXAuthenticationFilter dxAuthenticationFilter = new DXAuthenticationFilter();
        dxAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        dxAuthenticationFilter.setAuthenticationSuccessHandler(successHandler);
        dxAuthenticationFilter.setAuthenticationFailureHandler(failureHandler);
        DXAuthenticationProvider dxAuthenticationProvider = new DXAuthenticationProvider();
        dxAuthenticationProvider.setUserDetailsService(userDetailsService);

        //添加到spring安全框架中的authenticationProvider
        http.authenticationProvider(dxAuthenticationProvider)
                //将短信认证filter添加到UsernamePasswordAuthenticationFilter之后
                .addFilterAfter(dxAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
