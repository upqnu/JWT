package com.codestates.jwt.config;

import com.codestates.jwt.filter.FirstFilter;
import com.codestates.jwt.filter.JwtAuthenticationFilter;
import com.codestates.jwt.filter.JwtAuthorizationFilter;
import com.codestates.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final MemberRepository memberRepository;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new FirstFilter(), BasicAuthenticationFilter.class); // (5) BasicAuthenticationFilter 사용 전에 FirstFilter가 먼저 사용되도록
        http.csrf().disable(); // (1)
        http.headers().frameOptions().disable(); // (2)
        // (3)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
//                .addFilter(corsFilter) // CORS필터 추가
                .formLogin().disable() // form Login을 사용하지 않는다.
                .httpBasic().disable() // (4) http 로그인 방식을 사용하지 않는다.
                // HttpSecurity에 CustomDsl 필터를 적용시키라는 뜻.
                .apply(new CustomDsl())
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
        return http.build();
    }

    public class CustomDsl extends AbstractHttpConfigurer<CustomDsl, HttpSecurity> {

        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder
                    .addFilter(corsFilter)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, memberRepository));
        }
    }
}

/*
(1) CSRF protection은 CSRF protection은 spring security에서 default로 설정된다. 즉, protection을 통해 GET요청을 제외한 상태를 변화시킬 수 있는 POST, PUT, DELETE 요청으로부터 보호한다.
보안 수준을 향상시키는 CSRF를 왜 disable 하였을까? spring security documentation에 non-browser clients 만을 위한 서비스라면 csrf를 disable 하여도 좋다고 한다.
rest api를 이용한 서버라면, session 기반 인증과는 다르게 stateless하기 때문에 서버에 인증정보를 보관하지 않는다.
rest api에서 client는 권한이 필요한 요청을 하기 위해 요청에 필요한 인증 정보를(OAuth2, jwt토큰 등) 포함시켜야 한다.
따라서 서버에 인증정보를 저장하지 않기 때문에 굳이 불필요한 csrf 코드들을 작성할 필요가 없다.
(https://velog.io/@woohobi/Spring-security-csrf%EB%9E%80 참고)

(2) 스프링 시큐리티가 X-Frame-Options header를 답변에 포함하지 않게 함. 실습 중 사용하게 될 H2 console UI가 <frame> element를 이용하기 때문에
이런 설정을 하지 않는다면 H2에서의 실행결과가 렌더링 되지 않고 에러 메시지를 보게 될 것.

X-Frame-Options response header는 clickjacking 공격을 피하기 위해서 사용 (콘텐츠가 다른 사이트에 임베드 되지 않음을 확신하는 방식으로 사용됨)
(https://stackoverflow.com/questions/65894268/how-does-headers-frameoptions-disable-work 의 첫번째 답변 참조)

(3) Web은 기본적으로 stateless인데 seesion이나 cookie를 사용할 수 있다. session / cookie를 만들지 않고 STATELESS로 진행하겠다는 의미이다.
자세한 것은 소스 정보를 참조할 것

(4) http 통신을 할 때 headers에 Authorization 값을 ID, Password를 입력하는 방식이다. https를 사용하면 ID와 Password가 암호화되어 전달된다.
disable은 http 로그인 방식을 사용하지 않는다.

(5) addFilterBefore() 또는 addFilterAfter()를 사용해서 특정 필터 전/후로 적용될 수 있게 한다.

 */