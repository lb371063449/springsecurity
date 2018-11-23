package com.rinbo.springsecurity.core.filter;

import com.rinbo.springsecurity.core.exception.ValidateCodeException;
import com.rinbo.springsecurity.core.handler.WebAuthenctiationFailureHandler;
import com.rinbo.springsecurity.core.valid.ImageCode;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//短信内容验证filter
@Component
public class ValidateDXFilter extends OncePerRequestFilter implements InitializingBean {

    @Autowired
    private WebAuthenctiationFailureHandler failAuthenticationHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (StringUtils.endsWithIgnoreCase("/authentication/mobile", request.getRequestURI())) {
            try {
                validate(new ServletWebRequest(request));
            } catch (ValidateCodeException e) {
                failAuthenticationHandler.onAuthenticationFailure(request, response, e);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    public void validate(ServletWebRequest request) {
        String processorType = "";
        ImageCode codeInSession = (ImageCode) request.getRequest().getSession().getAttribute("SESSION_KEY_DX");
        String codeInRequest;
        try {
            codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(),
                    "dxCode");
        } catch (ServletRequestBindingException e) {
            throw new ValidateCodeException("获取验证码的值失败");
        }

        if (StringUtils.isEmpty(codeInRequest)) {
            throw new ValidateCodeException(processorType + "验证码的值不能为空");
        }
        if (codeInSession == null) {
            throw new ValidateCodeException(processorType + "验证码不存在");
        }
        if (!codeInSession.getCode().equals(codeInRequest)) {
            throw new ValidateCodeException(processorType + "验证码不匹配");
        }
        request.getRequest().getSession().removeAttribute("SESSION_KEY_IMAGE");
    }
}