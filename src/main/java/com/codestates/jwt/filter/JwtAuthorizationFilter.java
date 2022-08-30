package com.codestates.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.codestates.jwt.model.Member;
import com.codestates.jwt.oauth.PrincipalDetails;
import com.codestates.jwt.repository.MemberRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter { // 인가 처리. - user의 인가를 확인. BasicAuthenticationFilter : 인증 확인 필요할 때 무조건 동작된다.

    private MemberRepository memberRepository;

//    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
//        super(authenticationManager);
//    }


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청 됨.");

        String jwtHeader = request.getHeader("Authorization"); // request header에서 authorization값을 가져와서

        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) { // null이거나 Bearer타입이 아니라면 잘못된 것이니
            chain.doFilter(request, response);
            return; // 그냥 넘기고 다음 필터 실행하라.
        }

        String jwtToken = jwtHeader.replace("Bearer ", ""); // (Bearer타입이라면) 토큰을 체크하여 Bearer문자열을 없앤다. 그러면 토큰값만 jwtToken에 저장됨.

        // HMAC512알고리즘으로 비밀키를 가지고 토큰을 해독한 뒤,jwtToken이 정상적인지 증명한 후에 그 안에 username이 있는지 가져와라.
        String username = JWT.require(Algorithm.HMAC512("cos_jwt_token")).build().verify(jwtToken).getClaim("username").asString();

        if (username != null) { // 위에서 정상적으로 들어온 username이라면 if 안을 실행하라.
            Member memberEntity = memberRepository.findByUsername(username); // username을 가지고

            PrincipalDetails principalDetails = new PrincipalDetails(memberEntity); // 인증처리를 한다
            // UsernamePasswordAuthenticationToken을 통해 어떤 권한이 있는지 체크하여 인증 처리.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContextHolder에 인증된 정보(authentication)을 넘긴다.

            chain.doFilter(request, response);
        }
        super.doFilterInternal(request, response, chain);
    }
}