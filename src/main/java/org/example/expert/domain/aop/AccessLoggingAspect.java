package org.example.expert.domain.aop;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.example.expert.config.JwtUtil;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AccessLoggingAspect {

    private final JwtUtil jwtUtil;

    private final HttpServletRequest httpServletRequest;

    @Pointcut("execution(* org.example.expert.domain.comment.controller.CommentAdminController.deleteComment(..))")
    private void commentController(){}

    @Pointcut("execution(* org.example.expert.domain.user.controller.UserAdminController.changeUserRole(..))")
    private void userController(){}

    @Around("commentController() || userController()")
    public Object logAdminAccess(ProceedingJoinPoint joinPoint) throws Throwable{
        //요청 URL
        String requestUrl = httpServletRequest.getRequestURI();

        // 사용자 Id
        String bearerToken = httpServletRequest.getHeader("Authorization");
        String token = jwtUtil.substringToken(bearerToken);

        Claims claims = jwtUtil.extractClaims(token);
        String userId = claims.getSubject();

        // 요청 시각
        LocalDateTime Time = LocalDateTime.now();

        try {
            Object result = joinPoint.proceed();
            return result;
        }finally {
            log.info("User Id : {}, API URL {} : , Request Time : {}", userId, requestUrl, Time);
        }

    }

}
