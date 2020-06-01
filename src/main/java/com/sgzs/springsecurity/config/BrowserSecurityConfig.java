package com.sgzs.springsecurity.config;

import cn.hutool.http.HttpStatus;
import cn.hutool.json.JSONUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

/**
 * @author: jianyufeng
 * @description:
 * @date: 2020/5/31 22:12
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private DataSource datesource;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() //表单方式
                    .loginPage("/login.html") // 登录跳转 URL
                    .loginProcessingUrl("/login") // 处理表单登录 URL
                    .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        response.getWriter().write(JSONUtil.toJsonStr(authentication));
                    }
                })
                    .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        response.setStatus(HttpStatus.HTTP_INTERNAL_ERROR);
                        response.setContentType("application/json;charset=utf-8");
                        response.getWriter().write(exception.getMessage());
                    }
                })
                .and()
                    .exceptionHandling()
                    //没有权限的异常
                    .accessDeniedHandler(new AccessDeniedHandler() {
                        @Override
                        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                            response.setStatus(HttpStatus.HTTP_INTERNAL_ERROR);
                            response.setContentType("application/json;charset=utf-8");
                            response.getWriter().write("很抱歉，您没有该访问权限");
                        }
                    })
                .and()
                    //登出
                    .logout()
                    .logoutUrl("/signout")
//                    .logoutSuccessUrl("/signout/success")
                    .logoutSuccessHandler(new LogoutSuccessHandler() {
                        @Override
                        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            response.setStatus(HttpStatus.HTTP_UNAUTHORIZED);
                            response.setContentType("application/json;charset=utf-8");
                            response.getWriter().write("退出成功，请重新登录");
                        }
                    })
                    .deleteCookies("JSESSIONID")
                .and()
                    //记住我
                    .rememberMe()
                    .tokenRepository(persistentTokenRepository())// 配置 token 持久化仓库
                    .tokenValiditySeconds(3600)// remember 过期时间，单为秒
                    .userDetailsService(userDetailsService)// 处理自动登录逻辑
                .and()
                    //授权配置
                    .authorizeRequests()
                    .antMatchers("/login.html").permitAll()// 无需认证的请求路径
                    .anyRequest()//所有请求
                    .authenticated()//都需要认证
                .and()
                    //添加 Session管理器
                    .sessionManagement()
                    .invalidSessionUrl("/session/invalid")// Session失效后跳转到这个链接
                    .maximumSessions(1)
                    .maxSessionsPreventsLogin(true)
                    .expiredSessionStrategy(new SessionInformationExpiredStrategy() {
                        @Override
                        public void onExpiredSessionDetected(SessionInformationExpiredEvent eventØ) throws IOException {
                            HttpServletResponse response = eventØ.getResponse();
                            response.setStatus(HttpStatus.HTTP_NOT_AUTHORITATIVE);
                            response.setContentType("application/json;charset=utf-8");
                            response.getWriter().write("您的账号已经在别的地方登录，当前登录已失效。如果密码遭到泄露，请立即修改密码！");
                        }
                    })
                .and()
                .and()
                    //关闭防csrf攻击
                    .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(datesource);
        jdbcTokenRepository.setCreateTableOnStartup(false);
        return jdbcTokenRepository;
    }
}
