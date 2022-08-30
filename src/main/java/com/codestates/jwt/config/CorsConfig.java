package com.codestates.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 서버가 응답할 때 json을 자바스크립트에서 처리할 수 있게 설정
        config.addAllowedOrigin("*"); // 모든 ip에 응답 허용
        config.addAllowedHeader("*"); // 모든 header에 응답 허용
        config.addAllowedMethod("*"); // 모든 post, get, patch, delete 요청 허용
        source.registerCorsConfiguration("/api/**", config);

        return new CorsFilter(source);
    }
}

/*
CORS 에러를 Spring boot에서 해결하기 위한 3가지 방법 중 CorsFilter 생성을 사용.
(나머지 2가지는 @CrossOrigin 사용, WebMvcController에서 설정)
 */