package com.sgzs.springsecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author: jianyufeng
 * @description:
 * @date: 2020/5/31 22:07
 */
@RestController
public class TestController {
    @GetMapping("hello")
    public String hello() {
        return "hello spring security";
    }

    @GetMapping("index")
    public Object index(Authentication authentication) {
        return authentication;
    }

    @GetMapping("session/invalid")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public String sessionInvalid(){
        return "session已失效，请重新认证";
    }

    @GetMapping("/signout/success")
    public String signout() {
        return "退出成功，请重新登录";
    }

    @GetMapping("auth/admins")
    @PreAuthorize("hasAnyAuthority('admin')")
    public String authenticationTest1(){
        return  "您拥有admin的权限，可以查看";
    }

    @GetMapping("auth/test")
    @PreAuthorize("hasAnyAuthority('test')")
    public String authenticationTest2(){
        return  "您拥有test的权限，可以查看";
    }


}
