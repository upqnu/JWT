package com.codestates.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class FirstFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        System.out.println("FirstFilter");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        res.setCharacterEncoding("UTF-8"); // value로 입력될 값이 한글일 경우를 대비.

        // 포스트맨에서 POST를 통해 key : Authorization, value : codestates 일 경우 -> Controller를 통해 <h1>token</h1> 출력. 아니라면 "인증 실패" 출력.
        if(req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");

            if(headerAuth.equals("codestates")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter writer = res.getWriter();
                writer.println("인증 실패");
            }
        }

    }
}

/*
<HttpServletRequest>
ServletRequest를 상속한다. Http 프로토콜의 request 정보를 서블릿에 전달하기 위한 목적으로 사용.
Header 정보, Parameter, cookie, URI, URL 등의 정보를 읽어들이는 메서드를 가진 클래스. Body의 Stream을 읽어들이는 메서드를 가지고 있다.

<HttpServletResponse>
ServletResponse를 상속한다. Servlet이 HttpServletResponse 객체에 Content Type, 응답코드, 응답 메세지 등을 담아서 전송한다.

HttpServlerRequest, HttpServletResponse는 http 요청을 할 때 요청 정보가 해당 객체에 있기 때문에 사용한다.
 */