package com.codestates.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.codestates.jwt.model.Member;
import com.codestates.jwt.oauth.PrincipalDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

//        System.out.println("login 시도");

        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while((input = br.readLine()) != null) {
//                System.out.println(input);
            ObjectMapper om = new ObjectMapper(); // ObjectMapper는 JSON데이터를 parsing.
            Member member = om.readValue(request.getInputStream(), Member.class); // 요청이 있는 정보를 가져와서 Member.class와 비교.

            // 그렇게 들어온 정보의 username, password를 통해 토큰을 만든다.
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member.getUsername(), member.getPassword());

            // 만들어진 토큰을 가지고 authenticationManager의 authenticate 실행 - 즉, 인증 절차를 밟는 것.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

//            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            return authentication; // 토큰을 가진 사람이 정상적으로 인증되었는지를 반환. 성공적으로 인증되었을 경우, 아래 successfulAuthentication 메서드가 실행됨.
        } catch (IOException e) {
            e.printStackTrace();;
        }
//        return super.attemptAuthentication(request, response);
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal(); // 인증 결과 속 (인증에 성공한) 인증 정보를 객체에 저장.

        String jwtToken = JWT.create() // JWT를 만드는 라이브러리를 통해
                .withSubject("cos jwt token") // 토큰의 이름 설정
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 1000 * 10))) // 토큰의 유효기간(10분)
                .withClaim("id", principalDetails.getMember().getId()) // withClaim : payload에 담겨야 할 정보를 설정
                .withClaim("username", principalDetails.getMember().getUsername())
                .sign(Algorithm.HMAC512("cos_jwt_token")); // 서명 - HMAC512 알고리즘을 통해서 암호화하며, 암호화의 비밀키 값 설정.
        response.addHeader("Authorization", "Bearer " + jwtToken); // 인증이 되면 응답을 보내줌. Header의 이름(Authorization) + Bearer방식("Bearer " - 끝에 스페이스 1칸 반드시 삽입) + Bearer에 jwt방식 토큰을 보내준다.
    }

}

// JWT헤더에 공개키만 노출 (서버만 비밀키를 가지고 있다)