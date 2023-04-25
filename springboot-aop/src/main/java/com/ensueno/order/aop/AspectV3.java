package com.ensueno.order.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;

@Slf4j
@Aspect
public class AspectV3 {

    @Pointcut("execution(* com.ensueno.order..*(..))") // pointcut
    private void allOrder(){} // pointcut signature

    @Pointcut("execution(* *..*Service.*(..))")
    private void allService(){}

    @Around("allOrder()") // pointcut
    public Object doLog(ProceedingJoinPoint joinPoint) throws Throwable { // Advice
        log.info("[log] {}", joinPoint.getSignature());
        return joinPoint.proceed();
    }

    @Around("allOrder() && allService()") // pointcut
    public Object doTransaction(ProceedingJoinPoint joinPoint) throws Throwable { // Advice
        try {
            log.info("[트랜잭션 시작] {}", joinPoint.getSignature());
            Object result = joinPoint.proceed();
            log.info("result {}", result);
            log.info("[트랜잭션 커밋] {}", joinPoint.getSignature());
            return result;
        } catch (Exception e) {
            log.error("[트랜잭션 롤백] {}", joinPoint.getSignature());
            throw e;
        } finally {
            log.info("[리소스 릴리즈] {}", joinPoint.getSignature());
        }
    }
}
