package com.blueskykong.demo.filter;

import com.blueskykong.demo.annotation.PreAuth;
import com.blueskykong.demo.security.CustomerSecurityExpressionRoot;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Created by keets on 2017/12/7.
 */
@Component
@Aspect
public class AuthAspect {


    @Pointcut("@annotation(com.blueskykong.demo.annotation.PreAuth)")
    private void cut() {
    }

    /**
     * 定制一个环绕通知
     * 当想获得注解里面的属性，可以直接注入改注解
     *
     * @param joinPoint
     * @param preAuth
     */
    @Around("cut()&&@annotation(preAuth)")
    public Object record(ProceedingJoinPoint joinPoint, PreAuth preAuth) throws Throwable {

        //取出注解中的表达式
        String value = preAuth.value();

        SecurityContextHolder.getContext();
        //Spring EL 对value进行解析
        SecurityExpressionOperations operations = new CustomerSecurityExpressionRoot(SecurityContextHolder.getContext().getAuthentication());
        StandardEvaluationContext operationContext = new StandardEvaluationContext(operations);
        ExpressionParser parser = new SpelExpressionParser();
        Expression expression = parser.parseExpression(value);

        //获取表达式判断的结果
        boolean result = expression.getValue(operationContext, boolean.class);
        if (result) {
            //继续执行接口内的方法
            return joinPoint.proceed();
        }

        return "Forbidden";
    }


}

