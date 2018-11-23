package com.rinbo.springsecurity.core.config;

import com.rinbo.springsecurity.core.filter.ValidateDXFilter;
import com.rinbo.springsecurity.core.filter.ValidateImageFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private ValidateImageFilter validateImageFilter;

    @Autowired
    private ValidateDXFilter validateDXFilter;

    @Autowired
    private DXSecurityConfig dxAuthenticationSecurityConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //添加到spring安全框架中的authenticationProvider集合中
        http
                .apply(dxAuthenticationSecurityConfig)
                .and()
                //将短信认证filter添加到UsernamePasswordAuthenticationFilter之后
                .addFilterBefore(validateImageFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(validateDXFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .authorizeRequests()
                .antMatchers("/", "/home", "/web-signIn.html", "/authentication/require", "/code/*")
                .permitAll()
//                .antMatchers("/getname").access("hasRole('ADMIN') and hasIpAddress('192.168.102.32')")
                .and()
                .formLogin()
                .loginPage("/authentication/require")
                .loginProcessingUrl("/authentication/form")
                .permitAll()
                .and()
                .logout()
                .permitAll().and().csrf().disable()
                .authorizeRequests().anyRequest().access("@rbacService.hasPermission(request,authentication)");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}