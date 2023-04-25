package com.ensueno.order.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

@Slf4j
@Aspect
public class AspectV1 {

    @Around("execution(* com.ensueno.order..*(..))") // pointcut
    public Object doLog(ProceedingJoinPoint joinPoint) throws Throwable { // Advice
        log.info("[log] {}", joinPoint.getSignature());
        return joinPoint.proceed();
    }
}
