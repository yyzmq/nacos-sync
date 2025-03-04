package com.alibaba.nacossync.filters;

import cn.hutool.http.HttpUtil;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * @Description
 * @Author penghui
 * @Date 2025/3/4 13:31
 */
@Component
@WebFilter(urlPatterns = "/*")
public class AuthenticationFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Value("${authentication.login.isEnable:false}")
    private Boolean isEnable;

    @Value("${authentication.login.url:}")
    private String loginUrl;

    @Value("${authentication.login.tokenCheckUrl:}")
    private String tokenCheckUrl;

    private static final String SSO_TOKEN_ID = "ssoTokenId";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
        log.info("AuthenticationFilter已开启......");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (isEnable){
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            boolean isSaveToken = true;
            //优先从参数中获取SSOTokenId
            String ssoTokenId = httpRequest.getParameter(SSO_TOKEN_ID);;

            //若参数中不存在，则再从Cookie中获取TokenId
            if (StringUtils.isBlank(ssoTokenId)){
                isSaveToken = false;
                Cookie[] cookies = httpRequest.getCookies();
                for (Cookie cookie : cookies) {
                    String name = cookie.getName();
                    if (SSO_TOKEN_ID.equalsIgnoreCase(name)){
                        ssoTokenId = cookie.getValue();
                    }
                }
            }
            log.info("获取到TokenId为：{}", ssoTokenId);

            if (!checkToken(ssoTokenId)){
                // 用户未登录，重定向到登录页面
                httpResponse.sendRedirect(loginUrl);
                chain.doFilter(request, response);
                return;
            }
            //若是tokenId不是从cookie中来的，则需要保存到cookie中
            if (isSaveToken){
                Cookie cookie = new Cookie(SSO_TOKEN_ID, ssoTokenId);
                cookie.setPath("/");
                cookie.setSecure(false);
                httpResponse.addCookie(cookie);
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

    private boolean checkToken(String token){
        if (StringUtils.isNotBlank(tokenCheckUrl)){
            Map<String, Object> param = Maps.newHashMap();
            param.put("token", token);
//            String reponse = HttpUtil.get(tokenCheckUrl, param);
            return true;
        }
        return false;
    }

}
